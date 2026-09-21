//! Local AI Loopback Proxy with Just-In-Time (JIT) Key Acquisition.
//!
//! Listens on loopback (127.0.0.1:4141) and proxies requests to upstream AI providers
//! (OpenAI, Anthropic). If a key is missing midway, the proxy holds the TCP socket open,
//! prompts the user, securely stores the key in Cloak, and resumes the request.

use crate::storage::SecretStore;
use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::TryStreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Debug)]
pub enum AiProvider {
    OpenAI,
    Anthropic,
}

pub struct ProxyState {
    pub store: Arc<Box<dyn SecretStore>>,
    pub target_namespace: String,
    pub client: reqwest::Client,
    pub prompt_lock: Mutex<()>,
}

impl ProxyState {
    pub fn new(store: Box<dyn SecretStore>, target_namespace: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            store: Arc::new(store),
            target_namespace,
            client,
            prompt_lock: Mutex::new(()),
        }
    }

    /// Resolves the secret for the provider. If missing, acquires it interactively.
    pub async fn get_or_prompt_key(&self, provider: &AiProvider) -> Result<String> {
        let key_name = match provider {
            AiProvider::OpenAI => "OPENAI_API_KEY",
            AiProvider::Anthropic => "ANTHROPIC_API_KEY",
        };

        // 1. Check if key is already stored
        if let Some(val) = self.store.get(&self.target_namespace, key_name)? {
            if !val.trim().is_empty() {
                return Ok(val);
            }
        }
        // Fallback to global if namespace is project
        if self.target_namespace != "global" {
            if let Some(val) = self.store.get("global", key_name)? {
                if !val.trim().is_empty() {
                    return Ok(val);
                }
            }
        }

        // 2. Missing key: acquire lock so multiple concurrent requests don't prompt in parallel
        let _guard = self.prompt_lock.lock().await;

        // Re-check after acquiring lock
        if let Some(val) = self.store.get(&self.target_namespace, key_name)? {
            if !val.trim().is_empty() {
                return Ok(val);
            }
        }

        println!("\n┌─────────────────────────────────────────────────────────────┐");
        println!("│ [CLOAK JIT PROXY] ⏸ Request Paused: Key Missing            │");
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│ An AI tool or agent is requesting access to '{}'.", key_name);
        println!("│ Enter value below to authorize & continue without restart:   │");
        println!("└─────────────────────────────────────────────────────────────┘");

        let entered_val = rpassword::prompt_password(format!("Enter {}: ", key_name))
            .context("Failed to read key from terminal")?;

        if entered_val.trim().is_empty() {
            anyhow::bail!("No key entered. Aborting request.");
        }

        // Save to Cloak
        self.store.set(&self.target_namespace, key_name, &entered_val)?;
        println!("✓ Secret '{}' saved to scope '{}'. Resuming request...\n", key_name, self.target_namespace);

        Ok(entered_val)
    }
}

pub fn detect_provider(uri: &Uri) -> (AiProvider, String) {
    let path = uri.path();
    if path.starts_with("/v1/messages") {
        (AiProvider::Anthropic, "https://api.anthropic.com".to_string())
    } else {
        (AiProvider::OpenAI, "https://api.openai.com".to_string())
    }
}

async fn health_check(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let openai_has_key = state.store.get(&state.target_namespace, "OPENAI_API_KEY")
        .unwrap_or(None)
        .is_some();
    let anthropic_has_key = state.store.get(&state.target_namespace, "ANTHROPIC_API_KEY")
        .unwrap_or(None)
        .is_some();

    let json = serde_json::json!({
        "status": "active",
        "proxy": "Cloak Local AI Loopback Proxy",
        "scope": state.target_namespace,
        "providers": {
            "openai": { "configured": openai_has_key },
            "anthropic": { "configured": anthropic_has_key }
        }
    });

    (StatusCode::OK, axum::Json(json))
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (provider, base_url) = detect_provider(&uri);

    // Acquire or JIT prompt for API key
    let api_key = match state.get_or_prompt_key(&provider).await {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[CLOAK PROXY] ❌ Failed to acquire key: {e}");
            return (
                StatusCode::UNAUTHORIZED,
                format!("Cloak Proxy Error: {e}"),
            )
                .into_response();
        }
    };

    // Construct upstream URL
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let upstream_url = format!("{}{}", base_url, path_and_query);

    let mut req = state.client.request(method, &upstream_url);

    // Forward incoming headers, excluding host
    for (name, val) in &headers {
        if name != header::HOST && name != header::AUTHORIZATION {
            req = req.header(name.as_str(), val.as_bytes());
        }
    }

    // Inject upstream provider credentials
    match provider {
        AiProvider::OpenAI => {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }
        AiProvider::Anthropic => {
            req = req
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01");
        }
    }

    // Stream request body
    let body_stream = body.into_data_stream().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    req = req.body(reqwest::Body::wrap_stream(body_stream));

    // Send request to upstream provider
    let upstream_res = match req.send().await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[CLOAK PROXY] Upstream network error: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                format!("Cloak Upstream Network Error: {e}"),
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
        // Forward headers like content-type, content-encoding, cache-control
        if name != header::TRANSFER_ENCODING {
            builder = builder.header(name.as_str(), val.as_bytes());
        }
    }

    builder.body(body).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
    })
}

pub async fn start_proxy(
    store: Box<dyn SecretStore>,
    namespace: String,
    port: u16,
) -> Result<()> {
    let state = Arc::new(ProxyState::new(store, namespace.clone()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .fallback(proxy_handler)
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 🛡️  Cloak AI Loopback Proxy Active                           │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ • Bound strictly to: http://{}                   │", addr);
    println!("│ • Active Scope:      {:38} │", namespace);
    println!("│ • Health check:      http://{}/health            │", addr);
    println!("│                                                             │");
    println!("│ Point your AI tools / agents to this proxy:                 │");
    println!("│   export OPENAI_BASE_URL=\"http://{}/v1\"         │", addr);
    println!("│   export ANTHROPIC_BASE_URL=\"http://{}\"          │", addr);
    println!("│                                                             │");
    println!("│ Press Ctrl+C to stop.                                       │");
    println!("└─────────────────────────────────────────────────────────────┘\n");

    let listener = tokio::net::TcpListener::bind(addr).await
        .with_context(|| format!("Failed to bind proxy listener to {}", addr))?;

    axum::serve(listener, app)
        .await
        .context("Proxy server crashed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_provider() {
        let uri_openai_models: Uri = "/v1/models".parse().unwrap();
        let (p1, base1) = detect_provider(&uri_openai_models);
        assert!(matches!(p1, AiProvider::OpenAI));
        assert_eq!(base1, "https://api.openai.com");

        let uri_openai_chat: Uri = "/v1/chat/completions".parse().unwrap();
        let (p2, _) = detect_provider(&uri_openai_chat);
        assert!(matches!(p2, AiProvider::OpenAI));

        let uri_anthropic: Uri = "/v1/messages".parse().unwrap();
        let (p3, base3) = detect_provider(&uri_anthropic);
        assert!(matches!(p3, AiProvider::Anthropic));
        assert_eq!(base3, "https://api.anthropic.com");
    }
}

