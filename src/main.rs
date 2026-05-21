use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

// Import operations and structures from library
use span_cli::{fetch_circuits, load_auth_config};

#[derive(Parser, Debug)]
#[command(
    name = "span-cli",
    author,
    version,
    about = "Query and inspect SPAN panel circuits locally"
)]
struct Args {
    /// IP address or hostname of the SPAN panel (long-only, requires --token)
    #[arg(long, requires = "token", conflicts_with_all = ["auth_file", "panel"])]
    ip: Option<String>,

    /// Optional bearer authentication token (requires --ip)
    #[arg(short, long, requires = "ip", conflicts_with_all = ["auth_file", "panel"])]
    token: Option<String>,

    /// Path to the SPAN authentication JSON file (conflicts with --ip and --token)
    #[arg(long, value_name = "FILE", conflicts_with_all = ["ip", "token"])]
    auth_file: Option<PathBuf>,

    /// Name of the panel to query, overriding default_panel from config (conflicts with --ip and --token)
    #[arg(short, long, value_name = "PANEL", conflicts_with_all = ["ip", "token"])]
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

    /// Select all circuits (overrides --id and --name options, long-only)
    #[arg(long)]
    all: bool,

    /// Print only the value of this specific attribute (e.g., "instantPowerW", "relayState")
    #[arg(short, long)]
    attribute: Option<String>,

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
    #[arg(long, value_name = "INT", default_value_t = 0)]
    max_retries: u32,

    /// Time (in seconds, can be fractional) to pause before retrying a failed API request
    #[arg(long, value_name = "SECONDS", default_value_t = 0.5)]
    retry_sleep: f64,

    /// Disable TLS and connect using standard unencrypted HTTP
    #[arg(long)]
    no_tls: bool,
}

fn get_string_field(obj: &serde_json::Value, field: &str) -> Option<String> {
    obj.get(field).and_then(|v| v.as_str().map(|s| s.to_string()))
}

/// Normalizes casing and separators (case-insensitive, strips '-' and '_') 
/// to resolve casing mismatches between CLI inputs and SPAN API keys.
fn get_attribute_resilient<'a>(obj: &'a serde_json::Value, attr: &str) -> Option<&'a serde_json::Value> {
    let map = obj.as_object()?;
    
    // 1. Exact match fallback
    if let Some(val) = map.get(attr) {
        return Some(val);
    }
    
    // 2. Normalized search
    let normalize = |s: &str| -> String {
        s.to_lowercase()
            .replace('_', "")
            .replace('-', "")
    };
    
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

    // 1. Resolve auth file path (CLI -> SPAN_AUTH_FILE env -> default ~/.span-auth.json)
    let auth_path = if let Some(path) = &args.auth_file {
        path.clone()
    } else if let Ok(env_path) = std::env::var("SPAN_AUTH_FILE") {
        PathBuf::from(env_path)
    } else {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine the user's home directory. Provide --ip/--token, --auth-file, or set SPAN_AUTH_FILE.",
            )
        })?;
        home_dir.join(".span-auth.json")
    };

    // 2. Resolve credentials & target panel config
    let (panel_ip, auth_token, panel_name, file_port) = if let (Some(ip), Some(token)) = (&args.ip, &args.token) {
        // Fallback guess of panel name if hostname looks like standard "span-panelname.local"
        let extracted_panel = if ip.starts_with("span-") && ip.ends_with(".local") {
            Some(ip[5..ip.len() - 6].to_string())
        } else {
            None
        };
        (ip.clone(), Some(token.clone()), extracted_panel, None)
    } else {
        if !auth_path.exists() {
            eprintln!(
                "Error: Authentication file not found at {:?}. Run SPAN-auth setup, or provide --ip and --token.",
                auth_path
            );
            std::process::exit(1);
        }

        let auth_config = match load_auth_config(&auth_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error: Authentication file at {:?} is malformed: {}", auth_path, e);
                std::process::exit(1);
            }
        };

        let target_panel = if let Some(p) = &args.panel {
            p.clone()
        } else {
            auth_config.default_panel.clone()
        };

        let panel_credentials = auth_config.panels.get(&target_panel).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Panel '{}' not found in authentication configuration file.", target_panel),
            )
        })?;

        (
            panel_credentials.hostname.clone(),
            panel_credentials.access_token.clone(),
            Some(target_panel),
            panel_credentials.port,
        )
    };

    // CLI --port overrides file-defined port if both are present
    let active_port = args.port.or(file_port);

    // 3. Resolve CA directory (SPAN_CA_CERT_DIR env -> default ~/.span-ca-certs)
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

    // 4. Build HTTP Client and configure TLS Certificates
    let use_tls = !args.no_tls;
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5));

    if use_tls {
        if let Some(p_name) = &panel_name {
            let cert_path = ca_cert_dir.join(format!("{}.crt", p_name));
            if cert_path.exists() {
                match std::fs::read(&cert_path) {
                    Ok(cert_bytes) => {
                        match reqwest::Certificate::from_pem(&cert_bytes) {
                            Ok(cert) => {
                                client_builder = client_builder.add_root_certificate(cert);
                            }
                            Err(e) => {
                                eprintln!("Warning: Failed to parse CA cert from {:?}: {}", cert_path, e);
                            }
                        }
                    }
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
    let retry_sleep_duration = Duration::from_secs_f64(args.retry_sleep);

    // 5. Main execution / Polling loop
    loop {
        let mut attempt = 0;
        let spaces = loop {
            match fetch_circuits(&client, &panel_ip, active_port, use_tls, auth_token.as_deref()).await {
                Ok(s) => break s,
                Err(e) => {
                    if attempt < args.max_retries {
                        attempt += 1;
                        eprintln!(
                            "Warning: API request failed ({}). Retrying in {}s (attempt {}/{})...",
                            e, args.retry_sleep, attempt, args.max_retries
                        );
                        tokio::time::sleep(retry_sleep_duration).await;
                    } else {
                        eprintln!("Error fetching circuit data from SPAN panel ({}): {}", panel_ip, e);
                        std::process::exit(1);
                    }
                }
            }
        };

        // Stores (ID, Circuit JSON Object) to preserve key associations and ordering
        let mut selected_circuits: Vec<(String, serde_json::Value)> = Vec::new();

        // 6. Selection and sorting logic
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

        // 7. Apply absolute value transformation if requested
        if args.abs {
            for (_id, circuit) in &mut selected_circuits {
                apply_abs(circuit);
            }
        }

        // 8. Output results
        if let Some(ref attr) = args.attribute {
            let mut output_parts = Vec::new();
            
            for (_id, circuit) in &selected_circuits {
                let val_str = if let Some(val) = get_attribute_resilient(circuit, attr) {
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

        // 9. Polling control
        if let Some(secs) = args.live {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        } else {
            break;
        }
    }

    Ok(())
}