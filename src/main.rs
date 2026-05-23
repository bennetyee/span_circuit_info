use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

// Import operations and structures from library
use span_circuit_info::{fetch_circuits, load_auth_config};

#[derive(Parser, Debug)]
#[command(
    name = "span_circuit_info",
    author,
    version,
    about = "Query and inspect SPAN panel circuits locally"
)]
struct Args {
    /// IP address or hostname of the SPAN panel (overrides auth file configuration)
    #[arg(long)]
    ip: Option<String>,

    /// Optional bearer authentication token (overrides auth file configuration, long-only to avoid -t conflict)
    #[arg(long)]
    token: Option<String>,

    /// Path to the SPAN authentication JSON file
    #[arg(long, value_name = "FILE")]
    auth_file: Option<PathBuf>,

    /// Name of the panel to query, overriding default_panel from config
    #[arg(short, long, value_name = "PANEL")]
    panel: Option<String>,

    /// Port to use for the HTTP or HTTPS connection (overrides auth file configuration)
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// Select circuit(s) by ID (can be specified multiple times)
    #[arg(short, long, value_name = "ID")]
    id: Vec<String>,

    /// Select circuit(s) by Name (can be specified multiple times)
    #[arg(short, long, value_name = "NAME")]
    name: Vec<String>,

    /// Select all circuits (overrides --id and --name options)
    #[arg(short, long)]
    all: bool,

    /// Print only the value of this specific key (e.g., "instantPowerW", "relayState")
    #[arg(short, long, value_name = "KEY")]
    key: Option<String>,

    /// Separator string when printing attributes (long-only, defaults to a single space)
    #[arg(long, default_value = " ")]
    separator: String,

    /// Shell-quote values for safe usage in a shell eval
    #[arg(short, long)]
    quote: bool,

    /// Replace numerical values with their absolute value (corrects backwards-installed current transformers)
    #[arg(long)]
    abs: bool,

    /// Continuous polling mode. Interval to wait (in seconds) between data samplings
    #[arg(long, value_name = "SECONDS")]
    live: Option<u64>,

    /// Maximum number of retries if the API request fails
    #[arg(long, value_name = "INT", default_value_t = 10)]
    max_retries: u32,

    /// Initial backoff time (in seconds, can be fractional) before the first retry
    #[arg(long, value_name = "SECONDS", default_value_t = 0.1)]
    initial_retry_backoff: f64,

    /// Multiplier applied to the backoff interval on each consecutive retry failure
    #[arg(long, value_name = "MULTIPLIER", default_value_t = 2.0)]
    retry_backoff_multiplier: f64,

    /// Disable TLS and connect using standard unencrypted HTTP
    #[arg(long)]
    no_tls: bool,

    /// Suppress retry warnings and fatal connection messages on API failure
    #[arg(long)]
    quiet: bool,

    /// Add a Unix epoch timestamp in floating-point seconds (only applicable when used with --key)
    #[arg(short = 't', long = "timestamp")]
    timestamp: bool,
}

fn get_string_field(obj: &serde_json::Value, field: &str) -> Option<String> {
    obj.get(field)
        .and_then(|v| v.as_str().map(|s| s.to_string()))
}

/// Normalizes casing and separators (case-insensitive, strips '-' and '_')
/// to resolve casing mismatches between CLI inputs and SPAN API keys.
fn get_attribute_resilient<'a>(
    obj: &'a serde_json::Value,
    attr: &str,
) -> Option<&'a serde_json::Value> {
    let map = obj.as_object()?;

    // 1. Exact match fallback
    if let Some(val) = map.get(attr) {
        return Some(val);
    }

    // 2. Normalized search
    let normalize = |s: &str| -> String { s.to_lowercase().replace('_', "").replace('-', "") };

    let target = normalize(attr);
    for (k, v) in map {
        if normalize(k) == target {
            return Some(v);
        }
    }

    None
}

/// Prepares and shell-quotes a string value. If `should_quote` is true,
/// single quotes are escaped for POSIX shells and a space is prepended if the value begins with '-'.
fn prepare_and_quote(mut val_str: String, should_quote: bool) -> String {
    if should_quote {
        if val_str.starts_with('-') {
            val_str = format!(" {}", val_str);
        }
        // In POSIX single-quoted strings, single quotes are escaped by closing
        // the quote context, writing an escaped quote, and reopening.
        let escaped = val_str.replace('\'', r#"'\''"#);
        format!("'{}'", escaped)
    } else {
        val_str
    }
}

/// Recursively traverses a JSON value and replaces all negative numerical values
/// with their absolute equivalents.
fn apply_abs(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    *val = serde_json::Value::Number(i.abs().into());
                }
            } else if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    if let Some(abs_f) = serde_json::Number::from_f64(f.abs()) {
                        *val = serde_json::Value::Number(abs_f);
                    }
                }
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                apply_abs(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                apply_abs(v);
            }
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate the backoff multiplier value
    if args.retry_backoff_multiplier < 1.0 {
        eprintln!("Error: --retry-backoff-multiplier must be 1.0 or greater.");
        std::process::exit(1);
    }

    let mut hostname_from_file: Option<String> = None;
    let mut token_from_file: Option<String> = None;
    let mut port_from_file: Option<u16> = None;
    let mut resolved_panel_name: Option<String> = None;

    // 1. Resolve auth file path (CLI -> SPAN_AUTH_FILE env -> default ~/.span-auth.json)
    let mut auth_file_explicit = false;
    let auth_path = if let Some(path) = &args.auth_file {
        auth_file_explicit = true;
        path.clone()
    } else if let Ok(env_path) = std::env::var("SPAN_AUTH_FILE") {
        auth_file_explicit = true;
        PathBuf::from(env_path)
    } else {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine the user's home directory.",
            )
        })?;
        home_dir.join(".span-auth.json")
    };

    // 2. Load the configuration defaults if the file exists
    if auth_path.exists() {
        let auth_config = match load_auth_config(&auth_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "Error: Authentication file at {:?} is malformed: {}",
                    auth_path, e
                );
                std::process::exit(1);
            }
        };

        let target_panel = if let Some(p) = &args.panel {
            p.clone()
        } else {
            auth_config.default_panel.clone()
        };

        if let Some(panel_credentials) = auth_config.panels.get(&target_panel) {
            hostname_from_file = Some(panel_credentials.hostname.clone());
            token_from_file = panel_credentials.access_token.clone();
            port_from_file = panel_credentials.port;
            resolved_panel_name = Some(target_panel);
        } else {
            eprintln!(
                "Error: Panel '{}' not found in authentication configuration file.",
                target_panel
            );
            std::process::exit(1);
        }
    } else if auth_file_explicit {
        // If they explicitly requested a configuration file and it doesn't exist, exit.
        eprintln!(
            "Error: Specified authentication file not found at {:?}",
            auth_path
        );
        std::process::exit(1);
    }

    // 3. Resolve connection parameters. CLI overrides have precedence over file parameters.
    let panel_ip = args.ip.clone()
        .or(hostname_from_file)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not resolve the SPAN panel IP or hostname. Please provide --ip or set up ~/.span-auth.json.",
            )
        })?;

    let auth_token = args.token.clone().or(token_from_file);
    let active_port = args.port.or(port_from_file);

    // Try resolving the panel name to locate CA cert if it was not resolved from file
    let panel_name = resolved_panel_name.or_else(|| {
        if panel_ip.starts_with("span-") && panel_ip.ends_with(".local") {
            Some(panel_ip[5..panel_ip.len() - 6].to_string())
        } else {
            None
        }
    });

    // 4. Resolve CA directory (SPAN_CA_CERT_DIR env -> default ~/.span-ca-certs)
    let ca_cert_dir = if let Ok(env_dir) = std::env::var("SPAN_CA_CERT_DIR") {
        PathBuf::from(env_dir)
    } else {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine the user's home directory to locate SPAN CA certs.",
            )
        })?;
        home_dir.join(".span-ca-certs")
    };

    // 5. Build HTTP Client and configure TLS Certificates
    let use_tls = !args.no_tls;
    let mut client_builder = reqwest::Client::builder().timeout(Duration::from_secs(5));

    if use_tls {
        if let Some(p_name) = &panel_name {
            let cert_path = ca_cert_dir.join(format!("{}.crt", p_name));
            if cert_path.exists() {
                match std::fs::read(&cert_path) {
                    Ok(cert_bytes) => match reqwest::Certificate::from_pem(&cert_bytes) {
                        Ok(cert) => {
                            client_builder = client_builder.add_root_certificate(cert);
                        }
                        Err(e) => {
                            eprintln!(
                                "Warning: Failed to parse CA cert from {:?}: {}",
                                cert_path, e
                            );
                        }
                    },
                    Err(e) => {
                        eprintln!("Warning: Failed to read CA cert at {:?}: {}", cert_path, e);
                    }
                }
            } else {
                eprintln!(
                    "Warning: TLS enabled, but custom CA certificate not found at {:?}. Using default trust store.",
                    cert_path
                );
            }
        }
    }

    let client = client_builder.build()?;

    // 6. Main execution / Polling loop
    loop {
        let mut attempt = 0;
        let mut current_backoff = args.initial_retry_backoff;

        let spaces = loop {
            match fetch_circuits(
                &client,
                &panel_ip,
                active_port,
                use_tls,
                auth_token.as_deref(),
            )
            .await
            {
                Ok(s) => break s,
                Err(e) => {
                    if attempt < args.max_retries {
                        attempt += 1;
                        if !args.quiet {
                            eprintln!(
                                "Warning: API request failed ({}). Retrying in {:.3}s (attempt {}/{})...",
                                e, current_backoff, attempt, args.max_retries
                            );
                        }
                        tokio::time::sleep(Duration::from_secs_f64(current_backoff)).await;
                        current_backoff *= args.retry_backoff_multiplier;
                    } else {
                        if !args.quiet {
                            eprintln!(
                                "Error fetching circuit data from SPAN panel ({}): {}",
                                panel_ip, e
                            );
                        }
                        std::process::exit(1);
                    }
                }
            }
        };

        // Stores (ID, Circuit JSON Object) to preserve key associations and ordering
        let mut selected_circuits: Vec<(String, serde_json::Value)> = Vec::new();

        // 7. Selection and sorting logic
        if args.all {
            let mut all_ids: Vec<&String> = spaces.keys().collect();
            all_ids.sort();
            for id in all_ids {
                if let Some(val) = spaces.get(id) {
                    selected_circuits.push((id.clone(), val.clone()));
                }
            }
        } else {
            let mut id_selected_ids = Vec::new();
            let mut name_selected_pairs = Vec::new();
            let mut processed_ids = HashSet::new();

            // Process IDs in the exact order specified by the user in the command line
            for requested_id in &args.id {
                if spaces.contains_key(requested_id) {
                    if processed_ids.insert(requested_id.clone()) {
                        id_selected_ids.push(requested_id.clone());
                    }
                } else {
                    eprintln!("Warning: Circuit ID '{}' not found", requested_id);
                }
            }

            let mut name_to_best_id: HashMap<String, String> = HashMap::new();
            for (id, val) in &spaces {
                if let Some(name) = get_string_field(val, "name") {
                    name_to_best_id
                        .entry(name)
                        .and_modify(|existing_id| {
                            if id < existing_id {
                                *existing_id = id.clone();
                            }
                        })
                        .or_insert_with(|| id.clone());
                }
            }

            // Process Names in the exact order specified by the user in the command line
            for requested_name in &args.name {
                if let Some(matched_id) = name_to_best_id.get(requested_name) {
                    if processed_ids.insert(matched_id.clone()) {
                        name_selected_pairs.push((requested_name.clone(), matched_id.clone()));
                    }
                } else {
                    eprintln!("Warning: Circuit Name '{}' not found", requested_name);
                }
            }

            // Assemble matching circuits: IDs in user command-line order first, then Names in user command-line order
            for id in id_selected_ids {
                if let Some(val) = spaces.get(&id) {
                    selected_circuits.push((id.clone(), val.clone()));
                }
            }
            for (_name, id) in name_selected_pairs {
                if let Some(val) = spaces.get(&id) {
                    selected_circuits.push((id.clone(), val.clone()));
                }
            }
        }

        if selected_circuits.is_empty() {
            eprintln!("No circuits matched your selection criteria. Use --id, --name, or --all.");
            std::process::exit(1);
        }

        // 8. Apply absolute value transformation if requested
        if args.abs {
            for (_id, circuit) in &mut selected_circuits {
                apply_abs(circuit);
            }
        }

        // 9. Output results
        if let Some(ref key_name) = args.key {
            // Pre-allocate the vector with exact capacity to minimize allocations [4.1]
            let capacity = selected_circuits.len() + if args.timestamp { 1 } else { 0 };
            let mut output_parts = Vec::with_capacity(capacity);

            // Push timestamp first if requested, guaranteeing O(1) appends
            if args.timestamp {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();

                let ts_str = prepare_and_quote(format!("{}", now), args.quote);
                output_parts.push(ts_str);
            }

            for (_id, circuit) in &selected_circuits {
                let val_str = if let Some(val) = get_attribute_resilient(circuit, key_name) {
                    match val {
                        serde_json::Value::Null => "null".to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        other => other.to_string(),
                    }
                } else {
                    "null".to_string()
                };

                let formatted = prepare_and_quote(val_str, args.quote);
                output_parts.push(formatted);
            }

            let joined = output_parts.join(&args.separator);
            println!("{}", joined);
        } else {
            // Build the JSON Map. Insertion order is preserved because of "preserve_order" in Cargo.toml.
            let mut output_map = serde_json::Map::new();
            for (id, circuit) in selected_circuits {
                output_map.insert(id, circuit);
            }

            let output_json = serde_json::to_string_pretty(&serde_json::Value::Object(output_map))?;
            println!("{}", output_json);
        }

        // 10. Polling control
        if let Some(secs) = args.live {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        } else {
            break;
        }
    }

    Ok(())
}
