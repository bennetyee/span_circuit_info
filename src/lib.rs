use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Holds all credentials and metadata related to a specific SPAN panel configuration
#[derive(Deserialize, Debug, Clone)]
pub struct PanelConfig {
    pub hostname: String,
    pub port: Option<u16>,
    pub hop_passphrase: Option<String>,
    pub ebus_broker_password: Option<String>,
    pub access_token: Option<String>,
    pub access_token_issued_at: Option<u64>,
}

/// Root structure of the .span-auth.json configuration file
#[derive(Deserialize, Debug, Clone)]
pub struct AuthConfig {
    pub version: u32,
    pub default_panel: String,
    pub panels: HashMap<String, PanelConfig>,
}

/// Reads and parses the SPAN authentication JSON file
pub fn load_auth_config<P: AsRef<Path>>(path: P) -> Result<AuthConfig, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(path)?;
    let auth_config: AuthConfig = serde_json::from_str(&file_content)?;
    Ok(auth_config)
}

/// Asynchronously queries the local SPAN REST API for circuit data using a preconfigured client and port
pub async fn fetch_circuits(
    client: &reqwest::Client,
    panel_ip: &str,
    port: Option<u16>,
    use_tls: bool,
    auth_token: Option<&str>,
) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
    let scheme = if use_tls { "https" } else { "http" };

    let url = match port {
        Some(p) => format!("{}://{}:{}/api/v1/circuits", scheme, panel_ip, p),
        None => format!("{}://{}/api/v1/circuits", scheme, panel_ip),
    };

    let mut request = client.get(&url);

    if let Some(token) = auth_token {
        let auth_val = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?;
        request = request.header(reqwest::header::AUTHORIZATION, auth_val);
    }

    let response = request.send().await?;
    let root: serde_json::Value = response.error_for_status()?.json().await?;

    // Dynamically resolve whether circuits are nested under "circuits", "spaces", or flat at the root
    let parsed_map = if let Some(circuits_val) = root.get("circuits").and_then(|v| v.as_object()) {
        circuits_val.clone()
    } else if let Some(spaces_val) = root.get("spaces").and_then(|v| v.as_object()) {
        spaces_val.clone()
    } else if let Some(root_obj) = root.as_object() {
        root_obj.clone()
    } else {
        return Err("Unexpected JSON structure: expected a JSON object from the SPAN API".into());
    };

    let map: HashMap<String, serde_json::Value> = parsed_map.into_iter().collect();
    Ok(map)
}
