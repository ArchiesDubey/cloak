//! Child process execution and in-memory environment variable injection.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::{Command, Stdio};

/// Executes a target command with secrets injected into the child process environment.
///
/// Security characteristics:
/// 1. Secrets are passed directly to the child process's environment block in memory.
/// 2. Secrets are NEVER passed as command-line arguments (preventing visibility in `ps aux`, `pgrep`, `/proc`).
/// 3. Parent shell environment remains unmodified.
/// 4. Sensitive passphrases (CLOAK_MASTER_KEY) are explicitly stripped from child environment (S8).
/// 5. Automatically injects CLOAK_PROXY_TOKEN if active proxy session token exists.
pub fn run_with_secrets(
    secrets: &HashMap<String, zeroize::Zeroizing<String>>,
    cmd_name: &str,
    cmd_args: &[String],
    inject_proxy_token: bool,
    proxy_mode: bool,
    proxy_port: u16,
) -> Result<i32> {
    let mut cmd = Command::new(cmd_name);
    cmd.args(cmd_args);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Strip master passphrase from child environment (S8 fix)
    cmd.env_remove("CLOAK_MASTER_KEY");

    // Inject active proxy token and AI routing URLs if proxy mode is enabled
    if proxy_mode || inject_proxy_token {
        if let Ok(token) = crate::proxy::get_or_create_session_token() {
            cmd.env("CLOAK_PROXY_TOKEN", &token);
            if proxy_mode {
                cmd.env(
                    "OPENAI_BASE_URL",
                    format!("http://127.0.0.1:{}/v1", proxy_port),
                );
                cmd.env("OPENAI_API_KEY", &token);
                cmd.env(
                    "ANTHROPIC_BASE_URL",
                    format!("http://127.0.0.1:{}", proxy_port),
                );
                cmd.env("ANTHROPIC_API_KEY", &token);

                // Universal HTTPS & HTTP Proxy variables
                let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
                cmd.env("HTTP_PROXY", &proxy_url);
                cmd.env("HTTPS_PROXY", &proxy_url);
                cmd.env("ALL_PROXY", &proxy_url);
                cmd.env("http_proxy", &proxy_url);
                cmd.env("https_proxy", &proxy_url);
                cmd.env("all_proxy", &proxy_url);
                cmd.env("NO_PROXY", "localhost,127.0.0.1");
                cmd.env("no_proxy", "localhost,127.0.0.1");

                // Inject local CA bundle paths so curl, Python, Node, Git trust Cloak CA
                if let Ok(ca_path) = crate::proxy::ca::ca_cert_path() {
                    let ca_path_str = ca_path.to_string_lossy().to_string();
                    cmd.env("SSL_CERT_FILE", &ca_path_str);
                    cmd.env("REQUESTS_CA_BUNDLE", &ca_path_str);
                    cmd.env("CURL_CA_BUNDLE", &ca_path_str);
                    cmd.env("NODE_EXTRA_CA_CERTS", &ca_path_str);
                }
            }
        }
    } else {
        // Strip inherited proxy token and proxy env vars to ensure zero leakage
        cmd.env_remove("CLOAK_PROXY_TOKEN");
        cmd.env_remove("OPENAI_BASE_URL");
        cmd.env_remove("ANTHROPIC_BASE_URL");
        cmd.env_remove("HTTP_PROXY");
        cmd.env_remove("HTTPS_PROXY");
        cmd.env_remove("ALL_PROXY");
        cmd.env_remove("http_proxy");
        cmd.env_remove("https_proxy");
        cmd.env_remove("all_proxy");
        cmd.env_remove("SSL_CERT_FILE");
        cmd.env_remove("REQUESTS_CA_BUNDLE");
        cmd.env_remove("CURL_CA_BUNDLE");
        cmd.env_remove("NODE_EXTRA_CA_CERTS");
    }

    // Inject secrets into the child process's environment.
    // In proxy mode, AI provider keys (OPENAI_API_KEY, ANTHROPIC_API_KEY) are shielded
    // from child process memory because the proxy handles them internally!
    for (k, v) in secrets {
        if proxy_mode && (k == "OPENAI_API_KEY" || k == "ANTHROPIC_API_KEY") {
            continue;
        }
        cmd.env(k, v.as_str());
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn child process: {}", cmd_name))?;

    let status = child
        .wait()
        .with_context(|| format!("Error while waiting for child process: {}", cmd_name))?;

    let exit_code = status
        .code()
        .unwrap_or(if status.success() { 0 } else { 1 });
    Ok(exit_code)
}
