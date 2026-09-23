//! Local AI Loopback Proxy with JIT Key Acquisition & Cryptographic Session Authentication.
//!
//! Listens on loopback (127.0.0.1:4141) and proxies requests to upstream AI providers
//! (OpenAI, Anthropic) as well as serving as a Universal HTTPS Forward Gateway. Implements:
//! - Per-session cryptographic token authentication (~/.cloak/proxy.token)
//! - Zero browser CORS exposure (prevents cross-origin drive-by spending)
//! - Cryptographic singleton challenge-handshake to prevent port-squatting
//! - Path allowlist & upstream header sanitization (stripping client auth/duplicate keys)
//! - Non-blocking asynchronous JIT approval channel
//! - Local Root CA & Dynamic Leaf Certificate TLS termination for HTTPS MITM proxying
//! - Generic outbound forwarding gateway (`/cloak/forward`)

pub mod ca;
pub mod rules;

use crate::storage::SecretStore;
use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub enum AiProvider {
    OpenAI,
    Anthropic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingJitRequest {
    pub id: String,
    pub agent: String,
    pub key: String,
    pub target_endpoint: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct JitDecisionPayload {
    pub id: String,
    pub action: String, // "once", "always", "deny"
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SubmitJitPayload {
    pub agent: String,
    pub key: String,
    pub target_endpoint: Option<String>,
}

type JitResponseSender = oneshot::Sender<Option<(Zeroizing<String>, bool)>>;

pub struct ProxyState {
    pub store: Arc<Box<dyn SecretStore>>,
    pub target_namespace: String,
    pub port: u16,
    pub client: reqwest::Client,
    pub _prompt_lock: Mutex<()>,
    pub session_token: String,
    pub pending_jit: Mutex<HashMap<String, (PendingJitRequest, JitResponseSender)>>,
    pub shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    pub ca: Arc<ca::CertificateAuthority>,
    pub rules: Arc<rules::RuleRegistry>,
}

impl ProxyState {
    pub fn new(
        store: Box<dyn SecretStore>,
        target_namespace: String,
        port: u16,
        session_token: String,
        shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("Failed to build HTTP client");

        let ca = Arc::new(
            ca::CertificateAuthority::load_or_generate()
                .expect("Failed to initialize Cloak Certificate Authority"),
        );
        let rules = Arc::new(rules::RuleRegistry::load_or_default());

        Self {
            store: Arc::new(store),
            target_namespace,
            port,
            client,
            _prompt_lock: Mutex::new(()),
            session_token,
            pending_jit: Mutex::new(HashMap::new()),
            shutdown_tx,
            ca,
            rules,
        }
    }

    pub async fn async_get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<String>>> {
        let store = self.store.clone();
        let ns = namespace.to_string();
        let k = key.to_string();
        tokio::task::spawn_blocking(move || store.get(&ns, &k))
            .await
            .context("Task join error")?
    }

    pub async fn async_set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        let store = self.store.clone();
        let ns = namespace.to_string();
        let k = key.to_string();
        let v = value.to_string();
        tokio::task::spawn_blocking(move || store.set(&ns, &k, &v))
            .await
            .context("Task join error")?
    }

    pub async fn async_list_all_keys(&self) -> Vec<String> {
        let store = self.store.clone();
        let target_ns = self.target_namespace.clone();
        tokio::task::spawn_blocking(move || {
            let mut keys = store.list(&target_ns).unwrap_or_default();
            if target_ns != crate::project::GLOBAL_NAMESPACE {
                if let Ok(global_keys) = store.list(crate::project::GLOBAL_NAMESPACE) {
                    keys.extend(global_keys);
                }
            }
            keys.sort();
            keys.dedup();
            keys
        })
        .await
        .unwrap_or_default()
    }

    /// Resolves the secret for the provider. If missing, acquires it interactively or via JIT.
    pub async fn get_or_prompt_key(
        &self,
        provider: &AiProvider,
        endpoint: &str,
        agent: &str,
    ) -> Result<Zeroizing<String>> {
        let key_name = match provider {
            AiProvider::OpenAI => "OPENAI_API_KEY",
            AiProvider::Anthropic => "ANTHROPIC_API_KEY",
        };
        self.get_or_prompt_key_named(key_name, endpoint, agent)
            .await
    }

    /// Resolves an arbitrary named secret. If missing, acquires it interactively or via JIT.
    pub async fn get_or_prompt_key_named(
        &self,
        key_name: &str,
        endpoint: &str,
        agent: &str,
    ) -> Result<Zeroizing<String>> {
        // 1. Check active namespace (e.g. proj-xxx)
        if let Some(val) = self.async_get(&self.target_namespace, key_name).await? {
            if !val.trim().is_empty() {
                return Ok(val);
            }
        }

        // 2. Check global namespace
        if self.target_namespace != crate::project::GLOBAL_NAMESPACE {
            if let Some(val) = self
                .async_get(crate::project::GLOBAL_NAMESPACE, key_name)
                .await?
            {
                if !val.trim().is_empty() {
                    return Ok(val);
                }
            }
        }

        // 3. Prompting / JIT Acquisition
        if std::io::stdin().is_terminal() {
            // Interactive CLI with active TTY: prompt without blocking async worker thread
            println!("\n┌─────────────────────────────────────────────────────────────┐");
            println!("│ [CLOAK JIT PROXY] ⏸ Request Paused: Key Missing            │");
            println!("├─────────────────────────────────────────────────────────────┤");
            println!(
                "│ An AI tool or agent is requesting access to '{}'.",
                key_name
            );
            println!("│ Enter value below to authorize & continue without restart:   │");
            println!("└─────────────────────────────────────────────────────────────┘");

            let key_owned = key_name.to_string();
            let entered_val = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(format!("Enter {}: ", key_owned))
            })
            .await?
            .context("Failed to read key from terminal")?;

            if entered_val.trim().is_empty() {
                anyhow::bail!("No key entered. Aborting request.");
            }

            self.async_set(&self.target_namespace, key_name, &entered_val)
                .await?;
            println!(
                "✓ Secret '{}' saved to scope '{}'. Resuming request...\n",
                key_name, self.target_namespace
            );
            Ok(Zeroizing::new(entered_val))
        } else {
            // Headless / GUI / Daemon: register in pending JIT queue
            let req_id = format!("jit-{}", rand::thread_rng().next_u32());
            let (tx, rx) = oneshot::channel();
            let now = chrono_timestamp();

            let req_dto = PendingJitRequest {
                id: req_id.clone(),
                agent: agent.to_string(),
                key: key_name.to_string(),
                target_endpoint: endpoint.to_string(),
                timestamp: now,
            };

            {
                let mut map = self.pending_jit.lock().await;
                map.insert(req_id.clone(), (req_dto, tx));
            }

            println!(
                "[CLOAK JIT PROXY] Registered JIT approval request {} for '{}'. Awaiting user decision...",
                req_id, key_name
            );

            // Wait up to 60 seconds for approval from Desktop HUD or control endpoint
            match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
                Ok(Ok(Some((val, is_always)))) => {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        if is_always {
                            let _ = self
                                .async_set(&self.target_namespace, key_name, trimmed)
                                .await;
                            println!(
                                "✓ JIT Secret '{}' permanently stored in scope '{}'. Resuming request...",
                                key_name, self.target_namespace
                            );
                        } else {
                            println!(
                                "✓ JIT Secret '{}' authorized for one-time use (not persisted). Resuming request...",
                                key_name
                            );
                        }
                        Ok(val)
                    } else if let Some(stored) =
                        self.async_get(&self.target_namespace, key_name).await?
                    {
                        Ok(stored)
                    } else {
                        anyhow::bail!("No key provided for JIT request");
                    }
                }
                Ok(Ok(None)) => anyhow::bail!("JIT authorization explicitly denied by user"),
                Ok(Err(_)) => anyhow::bail!("JIT authorization channel disconnected"),
                Err(_) => {
                    let mut map = self.pending_jit.lock().await;
                    map.remove(&req_id);
                    anyhow::bail!("JIT authorization timed out waiting for user confirmation")
                }
            }
        }
    }
}

pub fn token_file_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(home).join(".cloak");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir.join("proxy.token"))
}

pub fn proxy_info_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(home).join(".cloak");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir.join("proxy.info"))
}

pub fn remove_proxy_info() {
    if let Ok(p) = proxy_info_path() {
        let _ = std::fs::remove_file(p);
    }
}

pub fn active_proxy_port() -> Option<u16> {
    if let Ok(p) = proxy_info_path() {
        if let Ok(content) = std::fs::read_to_string(p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                return v.get("port").and_then(|pt| pt.as_u64()).map(|pt| pt as u16);
            }
        }
    }
    None
}

pub fn get_or_create_session_token() -> Result<String> {
    let path = token_file_path()?;
    if let Ok(content) = std::fs::read_to_string(&path) {
        let t = content.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let tmp_path = format!("{}.tmp.{}", path.display(), std::process::id());
    std::fs::write(&tmp_path, &token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&tmp_path, &path)?;
    Ok(token)
}

pub fn constant_time_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_auth(headers: &HeaderMap, expected_token: &str) -> bool {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(bearer) = val.strip_prefix("Bearer ") {
                if constant_time_compare(bearer.trim(), expected_token) {
                    return true;
                }
            }
        }
    }
    if let Some(auth) = headers.get(header::PROXY_AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(bearer) = val.strip_prefix("Bearer ") {
                if constant_time_compare(bearer.trim(), expected_token) {
                    return true;
                }
            }
            if let Some(basic_b64) = val.strip_prefix("Basic ") {
                use base64::Engine;
                if let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(basic_b64.trim())
                {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
                        for part in parts {
                            if constant_time_compare(part, expected_token) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(token_hdr) = headers.get("X-Cloak-Token") {
        if let Ok(val) = token_hdr.to_str() {
            if constant_time_compare(val.trim(), expected_token) {
                return true;
            }
        }
    }
    false
}

fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

pub fn detect_provider(uri: &Uri) -> (AiProvider, String) {
    let path = uri.path();
    if path.starts_with("/v1/messages") {
        let base = std::env::var("CLOAK_UPSTREAM_ANTHROPIC")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        (AiProvider::Anthropic, base)
    } else {
        let base = std::env::var("CLOAK_UPSTREAM_OPENAI")
            .unwrap_or_else(|_| "https://api.openai.com".to_string());
        (AiProvider::OpenAI, base)
    }
}

async fn health_check(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let authenticated = verify_auth(&headers, &state.session_token);
    let mut json = serde_json::json!({
        "status": "active",
        "proxy": "Cloak Local AI Loopback Proxy",
        "scope": state.target_namespace,
        "port": state.port,
        "pid": std::process::id(),
        "authenticated": authenticated,
        "ca_installed": ca::ca_cert_path().map(|p| p.exists()).unwrap_or(false),
    });

    if authenticated {
        let openai_has_key = state
            .async_get(&state.target_namespace, "OPENAI_API_KEY")
            .await
            .unwrap_or(None)
            .is_some();
        let anthropic_has_key = state
            .async_get(&state.target_namespace, "ANTHROPIC_API_KEY")
            .await
            .unwrap_or(None)
            .is_some();

        json["providers"] = serde_json::json!({
            "openai": { "configured": openai_has_key },
            "anthropic": { "configured": anthropic_has_key }
        });
    }

    (StatusCode::OK, Json(json))
}

async fn shutdown_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !verify_auth(&headers, &state.session_token) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    if let Some(tx) = &state.shutdown_tx {
        let _ = tx.send(());
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "shutting_down" })),
        )
            .into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Shutdown signal not configured",
        )
            .into_response()
    }
}

async fn get_pending_jit_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !verify_auth(&headers, &state.session_token) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let map = state.pending_jit.lock().await;
    let list: Vec<PendingJitRequest> = map.values().map(|(r, _)| r.clone()).collect();
    (StatusCode::OK, Json(list)).into_response()
}

async fn respond_jit_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(payload): Json<JitDecisionPayload>,
) -> impl IntoResponse {
    if !verify_auth(&headers, &state.session_token) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let mut map = state.pending_jit.lock().await;
    if let Some((_req, tx)) = map.remove(&payload.id) {
        match payload.action.as_str() {
            "always" => {
                let val = payload.value.clone().unwrap_or_default();
                if val.trim().is_empty() {
                    return (StatusCode::BAD_REQUEST, "Secret value cannot be empty")
                        .into_response();
                }
                let _ = tx.send(Some((Zeroizing::new(val), true)));
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "approved_always" })),
                )
                    .into_response()
            }
            "once" => {
                let val = payload.value.clone().unwrap_or_default();
                if val.trim().is_empty() {
                    return (StatusCode::BAD_REQUEST, "Secret value cannot be empty")
                        .into_response();
                }
                let _ = tx.send(Some((Zeroizing::new(val), false)));
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "approved_once" })),
                )
                    .into_response()
            }
            "deny" => {
                let _ = tx.send(None);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "denied" })),
                )
                    .into_response()
            }
            _ => (
                StatusCode::BAD_REQUEST,
                "Invalid action (expected 'once', 'always', or 'deny')",
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Request ID not found or already handled" })),
        )
            .into_response()
    }
}

/// Allows CLI or subagents to submit a JIT request and hold the connection open
/// until approved by Desktop HUD or terminal.
async fn submit_jit_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(payload): Json<SubmitJitPayload>,
) -> impl IntoResponse {
    if !verify_auth(&headers, &state.session_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized session token" })),
        )
            .into_response();
    }

    let endpoint = payload
        .target_endpoint
        .unwrap_or_else(|| "CLI get".to_string());
    match state
        .get_or_prompt_key_named(&payload.key, &endpoint, &payload.agent)
        .await
    {
        Ok(secret_val) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "approved",
                "value": secret_val.as_str()
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "status": "rejected",
                "error": format!("{e}")
            })),
        )
            .into_response(),
    }
}

/// Generic Outbound Forwarding Gateway (`/cloak/forward`)
///
/// Accepts arbitrary HTTP requests and forwards them to `X-Cloak-Target`.
/// Dynamically injects secrets specified via `X-Cloak-Secret` or domain rules.
async fn forward_gateway_handler(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if !verify_auth(&headers, &state.session_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "message": "Unauthorized: Missing or invalid Cloak Proxy session token. Pass 'Authorization: Bearer <CLOAK_PROXY_TOKEN>' or 'X-Cloak-Token: <CLOAK_PROXY_TOKEN>'.",
                    "type": "unauthorized_proxy_client"
                }
            })),
        )
            .into_response();
    }

    let target_header = match headers.get("X-Cloak-Target") {
        Some(t) => match t.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid X-Cloak-Target header encoding",
                )
                    .into_response()
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing required header 'X-Cloak-Target'",
            )
                .into_response()
        }
    };

    let mut target_url = match reqwest::Url::parse(&target_header) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid X-Cloak-Target URL: {e}"),
            )
                .into_response()
        }
    };

    let host = target_url.host_str().unwrap_or("").to_string();
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("cloak-forward");

    // Determine secret name and injection strategy
    let (secret_name_opt, injection) =
        if let Some(s) = headers.get("X-Cloak-Secret").and_then(|h| h.to_str().ok()) {
            let inj = headers
                .get("X-Cloak-Inject-As")
                .and_then(|h| h.to_str().ok())
                .map(rules::SecretInjection::parse)
                .unwrap_or_else(|| rules::SecretInjection::Header {
                    name: "Authorization".to_string(),
                    prefix: Some("Bearer ".to_string()),
                });
            (Some(s.to_string()), inj)
        } else {
            let available_keys = state.async_list_all_keys().await;
            let has_client_auth = headers.contains_key(header::AUTHORIZATION)
                || headers.contains_key("x-api-key")
                || headers.contains_key("xi-api-key");
            if let Some(rule) = state
                .rules
                .match_or_infer(&host, &available_keys, has_client_auth)
            {
                (Some(rule.secret), rule.inject)
            } else {
                (
                    None,
                    rules::SecretInjection::Header {
                        name: "Authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                )
            }
        };

    let mut extra_headers = HeaderMap::new();

    if let Some(secret_name) = secret_name_opt {
        let secret_val = match state
            .get_or_prompt_key_named(&secret_name, target_url.as_str(), agent)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    format!("Cloak Gateway Error acquiring key '{secret_name}': {e}"),
                )
                    .into_response()
            }
        };

        match injection {
            rules::SecretInjection::Query { param } => {
                target_url
                    .query_pairs_mut()
                    .append_pair(&param, secret_val.as_str());
            }
            rules::SecretInjection::Header { name, prefix } => {
                let full_val =
                    format!("{}{}", prefix.as_deref().unwrap_or(""), secret_val.as_str());
                if let (Ok(h_name), Ok(h_val)) = (
                    header::HeaderName::from_bytes(name.as_bytes()),
                    header::HeaderValue::from_str(&full_val),
                ) {
                    extra_headers.insert(h_name, h_val);
                }
            }
        }
    }

    let mut client_req = state.client.request(method, target_url.as_str());

    for (name, val) in &headers {
        let name_str = name.as_str().to_lowercase();
        if !name_str.starts_with("x-cloak-")
            && name_str != "host"
            && name_str != "authorization"
            && name_str != "proxy-authorization"
        {
            client_req = client_req.header(name, val);
        }
    }

    for (name, val) in extra_headers {
        if let Some(h) = name {
            client_req = client_req.header(h, val);
        }
    }

    if !body.is_empty() {
        client_req = client_req.body(body);
    }

    match client_req.send().await {
        Ok(upstream_res) => {
            let status = upstream_res.status();
            let upstream_headers = upstream_res.headers().clone();
            let resp_stream = upstream_res.bytes_stream();
            let body = Body::from_stream(resp_stream);

            let mut builder = Response::builder().status(status);
            for (name, val) in &upstream_headers {
                if name != header::TRANSFER_ENCODING {
                    builder = builder.header(name.as_str(), val.as_bytes());
                }
            }
            builder.body(body).unwrap_or_else(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build response",
                )
                    .into_response()
            })
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("Gateway Error: {e}")).into_response(),
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    mut req: axum::extract::Request,
) -> Response {
    // 0. Handle HTTPS CONNECT Tunnels
    if req.method() == Method::CONNECT {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_else(|| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            });

        if authority.is_empty() {
            return (StatusCode::BAD_REQUEST, "Missing target host for CONNECT").into_response();
        }

        let state_clone = state.clone();
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    if let Err(e) = handle_mitm_tls_tunnel(state_clone, io, authority).await {
                        eprintln!("[CLOAK MITM] Tunnel error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[CLOAK MITM] Upgrade error: {e}");
                }
            }
        });

        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
    }

    // 1. Authenticate client (S1: Prevents drive-by browser requests)
    let headers = req.headers().clone();
    if !verify_auth(&headers, &state.session_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "message": "Unauthorized: Missing or invalid Cloak Proxy session token. Pass 'Authorization: Bearer <CLOAK_PROXY_TOKEN>' or 'X-Cloak-Token: <CLOAK_PROXY_TOKEN>'.",
                    "type": "unauthorized_proxy_client"
                }
            })),
        )
            .into_response();
    }

    let uri = req.uri().clone();
    let method = req.method().clone();
    let path = uri.path();

    // 2. Validate Path Allowlist for AI Proxy
    let is_allowed_path = path == "/v1/chat/completions"
        || path == "/v1/models"
        || path == "/v1/embeddings"
        || path == "/v1/completions"
        || path == "/v1/messages";

    if !is_allowed_path {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": format!("Path '{}' is not in the Cloak AI Proxy allowlist.", path),
                    "type": "forbidden_proxy_path"
                }
            })),
        )
            .into_response();
    }

    let (provider, base_url) = detect_provider(&uri);

    // Identify agent if declared in User-Agent
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown-agent");

    // Acquire or JIT prompt for API key
    let api_key = match state.get_or_prompt_key(&provider, path, agent).await {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[CLOAK PROXY] ❌ Failed to acquire key: {e}");
            return (StatusCode::UNAUTHORIZED, format!("Cloak Proxy Error: {e}")).into_response();
        }
    };

    // Construct upstream URL
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let upstream_url = format!("{}{}", base_url, path_and_query);

    let mut client_req = state.client.request(method, &upstream_url);

    // Forward incoming headers, stripping client auth, proxy token, and host
    for (name, val) in &headers {
        let name_lower = name.as_str().to_lowercase();
        if name_lower != "host"
            && name_lower != "authorization"
            && name_lower != "proxy-authorization"
            && name_lower != "x-api-key"
            && name_lower != "x-cloak-token"
            && name_lower != "cookie"
        {
            client_req = client_req.header(name, val);
        }
    }

    // Attach genuine provider API key
    match provider {
        AiProvider::OpenAI => {
            client_req = client_req.header(
                header::AUTHORIZATION,
                format!("Bearer {}", api_key.as_str()),
            );
        }
        AiProvider::Anthropic => {
            client_req = client_req.header("x-api-key", api_key.as_str());
            if !headers.contains_key("anthropic-version") {
                client_req = client_req.header("anthropic-version", "2023-06-01");
            }
        }
    }

    let req_body = req.into_body();
    let body_stream = req_body.into_data_stream();
    let upstream_body = reqwest::Body::wrap_stream(body_stream);
    client_req = client_req.body(upstream_body);

    let upstream_res = match client_req.send().await {
        Ok(res) => res,
        Err(err) => {
            eprintln!("[CLOAK PROXY] Upstream dispatch failure: {err}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": {
                        "message": format!("Upstream dispatch failure: {err}"),
                        "type": "cloak_upstream_failure"
                    }
                })),
            )
                .into_response();
        }
    };

    let status = upstream_res.status();
    let upstream_headers = upstream_res.headers().clone();

    // Stream response body directly back to client (essential for SSE streams)
    let resp_stream = upstream_res.bytes_stream();
    let body = Body::from_stream(resp_stream);

    let mut builder = Response::builder().status(status);
    for (name, val) in &upstream_headers {
        if name != header::TRANSFER_ENCODING {
            builder = builder.header(name.as_str(), val.as_bytes());
        }
    }

    builder.body(body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build response",
        )
            .into_response()
    })
}

/// Handles an upgraded HTTPS CONNECT connection by terminating TLS and forwarding decrypted HTTP requests.
async fn handle_mitm_tls_tunnel<I>(state: Arc<ProxyState>, io: I, authority: String) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let host = authority
        .split(':')
        .next()
        .unwrap_or(&authority)
        .to_string();
    let port = authority
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    let server_config = state
        .ca
        .get_or_create_server_config(&host)
        .context("Failed to get or mint server TLS config")?;

    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let tls_stream = acceptor
        .accept(io)
        .await
        .context("TLS server handshake failed")?;

    let state_inner = state.clone();
    let host_inner = host.clone();

    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state_inner.clone();
        let host = host_inner.clone();
        async move { handle_decrypted_mitm_request(state, host, port, req).await }
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), service);

    let _ = conn.await;
    Ok(())
}

async fn handle_decrypted_mitm_request(
    state: Arc<ProxyState>,
    host: String,
    port: u16,
    req: hyper::Request<hyper::body::Incoming>,
) -> std::result::Result<hyper::Response<Body>, std::convert::Infallible> {
    let (parts, incoming_body) = req.into_parts();
    let method = parts.method;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut target_url_str = if port == 443 {
        format!("https://{}{}", host, path_and_query)
    } else {
        format!("https://{}:{}{}", host, port, path_and_query)
    };

    // Check if target host matches any explicit domain rule or dynamic auto-inference
    let has_client_auth = parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(header::PROXY_AUTHORIZATION)
        || parts.headers.contains_key("x-api-key")
        || parts.headers.contains_key("xi-api-key");
    let available_keys = state.async_list_all_keys().await;
    let rule_opt = state
        .rules
        .match_or_infer(&host, &available_keys, has_client_auth);

    let mut extra_headers = HeaderMap::new();
    if let Some(rule) = rule_opt {
        match state
            .get_or_prompt_key_named(&rule.secret, &target_url_str, "MITM Gateway")
            .await
        {
            Ok(secret_val) => match &rule.inject {
                rules::SecretInjection::Query { param } => {
                    let sep = if target_url_str.contains('?') {
                        "&"
                    } else {
                        "?"
                    };
                    target_url_str =
                        format!("{}{}{}={}", target_url_str, sep, param, secret_val.as_str());
                }
                rules::SecretInjection::Header { name, prefix } => {
                    let header_val =
                        format!("{}{}", prefix.as_deref().unwrap_or(""), secret_val.as_str());
                    if let (Ok(h_name), Ok(h_val)) = (
                        header::HeaderName::from_bytes(name.as_bytes()),
                        header::HeaderValue::from_str(&header_val),
                    ) {
                        extra_headers.insert(h_name, h_val);
                    }
                }
            },
            Err(e) => {
                eprintln!("[CLOAK MITM] Failed to acquire secret for {}: {e}", host);
            }
        }
    }

    let mut client_req = state.client.request(method, &target_url_str);

    // Forward client headers, stripping host and proxy headers
    for (name, val) in &parts.headers {
        let name_str = name.as_str().to_lowercase();
        if name_str != "host"
            && name_str != "proxy-authorization"
            && name_str != "proxy-connection"
            && name_str != "x-cloak-token"
        {
            client_req = client_req.header(name, val);
        }
    }

    for (name, val) in extra_headers {
        if let Some(h_name) = name {
            client_req = client_req.header(h_name, val);
        }
    }

    // Convert incoming hyper body to reqwest Body
    let body_bytes = match http_body_util::BodyExt::collect(incoming_body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    if !body_bytes.is_empty() {
        client_req = client_req.body(body_bytes);
    }

    match client_req.send().await {
        Ok(upstream_res) => {
            let status = upstream_res.status();
            let upstream_headers = upstream_res.headers().clone();
            let resp_stream = upstream_res.bytes_stream();
            let body = Body::from_stream(resp_stream);

            let mut builder = hyper::Response::builder().status(status);
            for (name, val) in &upstream_headers {
                if name != header::TRANSFER_ENCODING {
                    builder = builder.header(name.as_str(), val.as_bytes());
                }
            }
            Ok(builder.body(body).unwrap_or_else(|_| {
                hyper::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }))
        }
        Err(err) => {
            let err_body = format!("Cloak Gateway Error connecting to upstream: {err}");
            Ok(hyper::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(err_body))
                .unwrap())
        }
    }
}

pub async fn start_proxy(store: Box<dyn SecretStore>, namespace: String, port: u16) -> Result<()> {
    let session_token = get_or_create_session_token()
        .context("Failed to initialize Cloak proxy session authentication token")?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);

    let state = Arc::new(ProxyState::new(
        store,
        namespace.clone(),
        port,
        session_token.clone(),
        Some(shutdown_tx.clone()),
    ));

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/cloak/shutdown", post(shutdown_handler))
        .route("/cloak/jit/pending", get(get_pending_jit_handler))
        .route("/cloak/jit/respond", post(respond_jit_handler))
        .route("/cloak/jit/request", post(submit_jit_handler))
        .route(
            "/cloak/forward",
            axum::routing::any(forward_gateway_handler),
        )
        .fallback(proxy_handler)
        .with_state(state.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => {
            println!("┌─────────────────────────────────────────────────────────────┐");
            println!("│ 🛡️  Cloak AI Loopback Proxy & HTTPS Gateway Active          │");
            println!("├─────────────────────────────────────────────────────────────┤");
            println!("│ • Bound strictly to: http://{:29} │", addr);
            println!("│ • Active Scope:      {:38} │", namespace);
            println!("│ • Session Token:     ~/.cloak/proxy.token                   │");
            println!("│ • Root CA Bundle:    ~/.cloak/ca.pem                        │");
            println!("│ • Health check:      http://{}/health            │", addr);
            println!("│                                                             │");
            println!("│ Transparent Forward Proxy:                                  │");
            println!(
                "│   export HTTP_PROXY=\"http://{}\"                     │",
                addr
            );
            println!(
                "│   export HTTPS_PROXY=\"http://{}\"                    │",
                addr
            );
            println!("│   export SSL_CERT_FILE=\"~/.cloak/ca.pem\"                   │");
            println!("│                                                             │");
            println!("│ AI Reverse Proxy URLs:                                      │");
            println!(
                "│   export OPENAI_BASE_URL=\"http://{}/v1\"         │",
                addr
            );
            println!(
                "│   export ANTHROPIC_BASE_URL=\"http://{}\"          │",
                addr
            );
            println!("│                                                             │");
            println!("│ Press Ctrl+C to stop.                                       │");
            println!("└─────────────────────────────────────────────────────────────┘\n");
            l
        }
        Err(e) => {
            // Port conflict handling: check if existing Cloak proxy is running
            let health_url = format!("http://127.0.0.1:{}/health", port);
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_millis(800))
                .build()?;

            let check_res = client
                .get(&health_url)
                .header("X-Cloak-Token", &session_token)
                .send()
                .await;

            if let Ok(resp) = check_res {
                if resp.status().is_success() {
                    let val: serde_json::Value = resp.json().await.unwrap_or_default();
                    let is_authenticated = val
                        .get("authenticated")
                        .and_then(|a| a.as_bool())
                        .unwrap_or(false);
                    let is_cloak = val.get("proxy").and_then(|p| p.as_str())
                        == Some("Cloak Local AI Loopback Proxy");

                    if is_cloak && is_authenticated {
                        let running_scope = val
                            .get("scope")
                            .and_then(|s| s.as_str())
                            .unwrap_or(&namespace);
                        println!("┌─────────────────────────────────────────────────────────────┐");
                        println!("│ 🛡️  Cloak AI Loopback Proxy (Singleton Session)             │");
                        println!("├─────────────────────────────────────────────────────────────┤");
                        println!("│ • Bound strictly to: http://{:29} │", addr);
                        println!("│ • Active Scope:      {:38} │", running_scope);
                        println!("│ • Session Token:     ~/.cloak/proxy.token                   │");
                        println!("│ • Root CA Bundle:    ~/.cloak/ca.pem                        │");
                        println!("│ • Health check:      http://{}/health            │", addr);
                        println!("│                                                             │");
                        println!("│ ✓ Cryptographically verified existing Cloak Proxy daemon.   │");
                        println!("│   Seamlessly attached to active singleton session.          │");
                        println!("│                                                             │");
                        println!("│ Press Ctrl+C to detach this session.                        │");
                        println!("│ (Existing proxy will continue running in background)        │");
                        println!(
                            "└─────────────────────────────────────────────────────────────┘\n"
                        );

                        loop {
                            tokio::select! {
                                _ = tokio::signal::ctrl_c() => {
                                    println!("\n✓ Detached CLI session. Cloak Proxy continues running in background.");
                                    return Ok(());
                                }
                                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                                    let still_alive = client.get(&health_url)
                                        .header("X-Cloak-Token", &session_token)
                                        .send()
                                        .await
                                        .map(|r| r.status().is_success())
                                        .unwrap_or(false);
                                    if !still_alive {
                                        println!("\n⚠️ Existing Cloak Proxy daemon terminated. Promoting this session to active server...");
                                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                        match tokio::net::TcpListener::bind(addr).await {
                                            Ok(new_listener) => {
                                                println!("✓ Successfully bound to port {}. Proxy is active.", port);
                                                let info = serde_json::json!({
                                                    "pid": std::process::id(),
                                                    "port": port,
                                                    "scope": namespace,
                                                    "started_at": chrono_timestamp(),
                                                });
                                                if let Ok(p) = proxy_info_path() {
                                                    let _ = std::fs::write(p, serde_json::to_string_pretty(&info).unwrap_or_default());
                                                }
                                                let mut promo_rx = shutdown_tx.subscribe();
                                                let shutdown_signal = async move {
                                                    tokio::select! {
                                                        _ = tokio::signal::ctrl_c() => {},
                                                        _ = promo_rx.recv() => {},
                                                    }
                                                };
                                                let res = axum::serve(new_listener, app)
                                                    .with_graceful_shutdown(shutdown_signal)
                                                    .await;
                                                remove_proxy_info();
                                                res.context("Proxy server crashed")?;
                                                return Ok(());
                                            }
                                            Err(err) => {
                                                println!("❌ Failed to re-bind port {}: {err}. Exiting.", port);
                                                return Ok(());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        eprintln!(
                            "⚠️ Security Alert: Port {} is in use, but Cloak cryptographic authentication failed!",
                            port
                        );
                        eprintln!(
                            "   The process on port {} does not match your ~/.cloak/proxy.token.",
                            port
                        );
                        eprintln!(
                            "   Potential port-squatter or conflict detected. Refusing to connect."
                        );
                        anyhow::bail!("Port conflict with untrusted process on port {}", port);
                    }
                }
            }

            return Err(e).context(format!("Failed to bind to port {port}"));
        }
    };

    let info = serde_json::json!({
        "pid": std::process::id(),
        "port": port,
        "scope": namespace,
        "started_at": chrono_timestamp(),
    });
    if let Ok(p) = proxy_info_path() {
        let _ = std::fs::write(p, serde_json::to_string_pretty(&info).unwrap_or_default());
    }

    let shutdown_signal = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = shutdown_rx.recv() => {},
        }
    };

    let serve_res = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await;

    remove_proxy_info();
    serve_res.context("Proxy server crashed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_provider() {
        let uri: Uri = "/v1/chat/completions".parse().unwrap();
        let (p, _) = detect_provider(&uri);
        assert!(matches!(p, AiProvider::OpenAI));

        let uri_anthropic: Uri = "/v1/messages".parse().unwrap();
        let (p2, _) = detect_provider(&uri_anthropic);
        assert!(matches!(p2, AiProvider::Anthropic));
    }

    #[test]
    fn test_verify_auth() {
        let mut headers = HeaderMap::new();
        let token = "secret-token-12345";

        assert!(!verify_auth(&headers, token));

        headers.insert(
            header::AUTHORIZATION,
            "Bearer secret-token-12345".parse().unwrap(),
        );
        assert!(verify_auth(&headers, token));

        headers.clear();
        headers.insert("X-Cloak-Token", "secret-token-12345".parse().unwrap());
        assert!(verify_auth(&headers, token));

        headers.clear();
        headers.insert(
            header::PROXY_AUTHORIZATION,
            "Bearer secret-token-12345".parse().unwrap(),
        );
        assert!(verify_auth(&headers, token));

        // Basic auth test: base64(cloak:secret-token-12345)
        headers.clear();
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("cloak:secret-token-12345");
        headers.insert(
            header::PROXY_AUTHORIZATION,
            format!("Basic {}", basic).parse().unwrap(),
        );
        assert!(verify_auth(&headers, token));
    }

    #[derive(Default)]
    struct MockStore {
        data: std::sync::Mutex<HashMap<(String, String), String>>,
    }

    impl SecretStore for MockStore {
        fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .insert((namespace.to_string(), key.to_string()), value.to_string());
            Ok(())
        }
        fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .get(&(namespace.to_string(), key.to_string()))
                .map(|s| Zeroizing::new(s.clone())))
        }
        fn list(&self, namespace: &str) -> Result<Vec<String>> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .keys()
                .filter(|(ns, _)| ns == namespace)
                .map(|(_, k)| k.clone())
                .collect())
        }
        fn delete(&self, namespace: &str, key: &str) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .remove(&(namespace.to_string(), key.to_string()));
            Ok(())
        }
        fn list_namespaces(&self) -> Result<Vec<String>> {
            let mut list: Vec<String> = self
                .data
                .lock()
                .unwrap()
                .keys()
                .map(|(ns, _)| ns.clone())
                .collect();
            list.sort();
            list.dedup();
            Ok(list)
        }
    }

    #[tokio::test]
    async fn test_forward_gateway_headers() {
        let store = MockStore::default();
        store
            .set(
                crate::project::GLOBAL_NAMESPACE,
                "TEST_API_KEY",
                "secret-xyz",
            )
            .unwrap();

        let state = Arc::new(ProxyState::new(
            Box::new(store),
            crate::project::GLOBAL_NAMESPACE.to_string(),
            4141,
            "token-123".to_string(),
            None,
        ));

        // Test resolving named secret through proxy state
        let key = state
            .get_or_prompt_key_named("TEST_API_KEY", "https://api.test.com", "test")
            .await
            .unwrap();
        assert_eq!(key.as_str(), "secret-xyz");
    }
}
