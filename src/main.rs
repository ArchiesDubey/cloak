//! Cloak: Local-First Cross-Platform Secrets Manager & AI Proxy

mod crypto;
mod project;
mod proxy;
mod runner;
mod security;
mod storage;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use project::GLOBAL_NAMESPACE;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use storage::file_store::FileStore;
use storage::keyring_store::KeyringStore;
use storage::SecretStore;

use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "cloak")]
#[command(
    about = "Local-first cross-platform secrets manager & child process injector",
    long_about = None
)]
#[command(version)]
struct Cli {
    /// Force operation on global scope (available across all projects/directories)
    #[arg(short, long, global = true)]
    global: bool,

    /// Explicitly target a specific project scope by name
    #[arg(short, long, global = true)]
    project: Option<String>,

    /// Storage backend to use
    #[arg(long, global = true, value_enum, default_value_t = StoreBackend::Keyring)]
    store: StoreBackend,

    /// Custom file path for encrypted file vault (only used when --store=file)
    #[arg(long, global = true)]
    vault_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum StoreBackend {
    /// OS-native secure credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service)
    Keyring,
    /// Encrypted standalone file (Argon2id + XChaCha20-Poly1305)
    File,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    /// Standard .env format (KEY=VALUE)
    Dotenv,
    /// Shell export format (export KEY="VALUE")
    Bash,
    /// JSON format ({"KEY": "VALUE"})
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the current directory as a Cloak project
    Init {
        /// Custom project name (defaults to current folder name)
        name: Option<String>,
    },
    /// Store or update a secret
    Set {
        /// Secret key name (e.g., OPENAI_API_KEY)
        key: String,
        /// Secret value. If omitted, prompts securely without echoing to terminal.
        value: Option<String>,
        /// Protect secret with Touch ID / Secure Enclave hardware access control (macOS)
        #[arg(long = "touch-id", aliases = ["secure-enclave"])]
        touch_id: bool,
    },
    /// Retrieve a secret value
    Get {
        /// Secret key name
        key: String,
        /// Reveal the full secret value (otherwise partially masked to prevent screen leaks)
        #[arg(long)]
        reveal: bool,
        /// Do not prompt interactively or trigger JIT if secret is missing (fails with code 1)
        #[arg(long = "no-prompt", aliases = ["strict"])]
        no_prompt: bool,
    },
    /// List secret keys (values are never shown)
    List {
        /// List all projects and global secrets machine-wide
        #[arg(long)]
        all: bool,
    },
    /// Delete a secret
    Delete {
        /// Secret key name to delete
        key: String,
    },
    /// Execute a command with secrets injected into the child process environment
    Run {
        /// Specific keys to inject (comma-separated or repeated). Defaults to all keys in scope.
        #[arg(long, value_delimiter = ',')]
        keys: Option<Vec<String>>,

        /// Route AI agent requests through Cloak's local proxy (auto-starts proxy & injects OPENAI/ANTHROPIC routing)
        #[arg(long = "proxy", aliases = ["ai-proxy"])]
        proxy: bool,

        /// Custom port for the local AI proxy (defaults to 4141)
        #[arg(long = "proxy-port", default_value_t = 4141)]
        proxy_port: u16,

        /// Inject CLOAK_PROXY_TOKEN into the child process environment (opt-in)
        #[arg(long = "proxy-token")]
        proxy_token: bool,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Export secrets for the current scope
    Export {
        /// Export format
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Start or stop the Local AI Loopback Proxy with JIT secret acquisition
    Proxy {
        /// Port to listen on (binds strictly to 127.0.0.1)
        #[arg(long, default_value_t = 4141)]
        port: u16,

        /// Stop any active Cloak proxy daemon
        #[arg(long)]
        stop: bool,

        /// Output shell export commands for current environment (eval $(cloak proxy --env))
        #[arg(long)]
        env: bool,
    },
    /// Manage the local Cloak Certificate Authority (CA) for HTTPS interception
    Ca {
        #[command(subcommand)]
        command: CaCommands,
    },
    /// Launch the Cloak Desktop GUI (Hybrid HUD)
    Gui,
    /// Setup and register Cloak across all local LLM coding agents (Claude, Cursor, Agy, Windsurf, Copilot, Codex)
    Setup,
}

#[derive(Subcommand)]
enum CaCommands {
    /// Install the Cloak Root CA into the user/system trust store
    Install,
    /// Print the path to the Cloak Root CA certificate (~/.cloak/ca.pem)
    Path,
}

fn get_store(backend: StoreBackend, custom_vault: Option<PathBuf>) -> Result<Box<dyn SecretStore>> {
    match backend {
        StoreBackend::Keyring => {
            let store = KeyringStore::new().context(
                "Failed to initialize OS Keyring backend. Consider using --store file on headless systems.",
            )?;
            Ok(Box::new(store))
        }
        StoreBackend::File => {
            let vault_path = custom_vault.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home)
                    .join(".config")
                    .join("cloak")
                    .join("vault.enc")
            });

            // Read and immediately remove master key from environment to prevent child process leakage (S8 fix)
            let passphrase = if let Ok(pass) = std::env::var("CLOAK_MASTER_KEY") {
                std::env::remove_var("CLOAK_MASTER_KEY");
                pass
            } else {
                rpassword::prompt_password("Enter Master Vault Passphrase: ")
                    .context("Failed to read master passphrase")?
            };

            let store = FileStore::new(vault_path, passphrase.as_bytes())
                .context("Failed to initialize encrypted file vault")?;
            Ok(Box::new(store))
        }
    }
}

fn mask_secret(value: &str) -> String {
    let count = value.chars().count();
    if count <= 8 {
        "********".to_string()
    } else {
        let prefix: String = value.chars().take(4).collect();
        let suffix: String = value.chars().skip(count.saturating_sub(4)).collect();
        format!("{}••••••••{}", prefix, suffix)
    }
}

enum TargetScope {
    Global,
    Project(String),
}

fn resolve_target_scope(global: bool, explicit_project: Option<&str>) -> TargetScope {
    if global {
        return TargetScope::Global;
    }
    if let Some(p) = explicit_project {
        return TargetScope::Project(p.to_string());
    }
    if let Some(detected) = project::detect_project() {
        return TargetScope::Project(detected.name);
    }
    TargetScope::Global
}

fn scope_to_namespace(scope: &TargetScope) -> String {
    match scope {
        TargetScope::Global => GLOBAL_NAMESPACE.to_string(),
        TargetScope::Project(name) => format!("proj-{}", name),
    }
}

async fn ensure_proxy_running(port: u16) -> Result<String> {
    let token = proxy::get_or_create_session_token()?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(600))
        .build()
        .unwrap_or_default();
    let health_url = format!("http://127.0.0.1:{}/health", port);

    let is_alive = match client
        .get(&health_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
    {
        Ok(res) => res.status().is_success(),
        Err(_) => false,
    };

    if !is_alive {
        eprintln!(
            "🚀 Auto-starting Cloak AI Loopback Proxy on http://127.0.0.1:{}...",
            port
        );
        let current_exe =
            std::env::current_exe().context("Failed to get current executable path")?;
        let _ = std::process::Command::new(current_exe)
            .args(["proxy", "--port", &port.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("Failed to spawn background Cloak proxy")?;

        let mut started = false;
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if let Ok(res) = client
                .get(&health_url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
            {
                if res.status().is_success() {
                    started = true;
                    break;
                }
            }
        }
        if !started {
            bail!(
                "Cloak proxy failed to start within timeout on port {}",
                port
            );
        }
        eprintln!(
            "✓ Cloak AI Proxy active. Auto-routing OpenAI & Anthropic requests through proxy.\n"
        );
    }

    Ok(token)
}

#[tokio::main]
async fn main() -> Result<std::process::ExitCode> {
    // Apply process-level hardening (anti-core dump, disable ptrace where applicable)
    security::harden_process();

    let cli = Cli::parse();

    // Handle 'init' before loading stores if applicable
    if let Commands::Init { name } = &cli.command {
        let proj = project::init_project(name.clone())?;
        println!(
            "✓ Initialized Cloak project '{}' in {:?}",
            proj.name, proj.root
        );
        println!(
            "  Secrets saved in this directory will be scoped to '{}' by default.",
            proj.name
        );
        return Ok(std::process::ExitCode::SUCCESS);
    }

    let store = get_store(cli.store, cli.vault_path)?;
    let target_scope = resolve_target_scope(cli.global, cli.project.as_deref());

    match cli.command {
        Commands::Init { .. } => unreachable!(),

        Commands::Set {
            key,
            value,
            touch_id,
        } => {
            let val = match value {
                Some(v) => v,
                None => rpassword::prompt_password(format!("Enter value for '{}': ", key))
                    .context("Failed to read masked secret value")?,
            };

            let ns = scope_to_namespace(&target_scope);
            store.set_secure(&ns, &key, &val, touch_id)?;

            let security_note = if touch_id {
                " [Touch ID / Secure Enclave hardware access control enabled]"
            } else {
                ""
            };
            match target_scope {
                TargetScope::Global => {
                    println!(
                        "✓ Secret '{}' saved to Global scope (available machine-wide){}",
                        key, security_note
                    );
                }
                TargetScope::Project(ref name) => {
                    println!(
                        "✓ Secret '{}' saved to project '{}'{}",
                        key, name, security_note
                    );
                }
            }
        }

        Commands::Get {
            key,
            reveal,
            no_prompt,
        } => {
            let found_val = match target_scope {
                TargetScope::Global => store.get(GLOBAL_NAMESPACE, &key)?,
                TargetScope::Project(ref name) => {
                    let ns = format!("proj-{}", name);
                    if let Some(val) = store.get(&ns, &key)? {
                        Some(val)
                    } else {
                        store.get(GLOBAL_NAMESPACE, &key)?
                    }
                }
            };

            if let Some(val) = found_val {
                let scope_label = match target_scope {
                    TargetScope::Global => "Global",
                    TargetScope::Project(ref name) => name.as_str(),
                };
                print_val(&val, reveal, scope_label);
            } else {
                return handle_missing_get(store.as_ref(), &target_scope, &key, reveal, no_prompt)
                    .await;
            }
        }

        Commands::List { all } => {
            if all {
                let namespaces = store.list_namespaces()?;
                println!("All Known Scopes:");
                for ns in namespaces {
                    let keys = store.list(&ns)?;
                    let label = if ns == GLOBAL_NAMESPACE {
                        "🌐 Global".to_string()
                    } else if let Some(p) = ns.strip_prefix("proj-") {
                        format!("📁 Project: {}", p)
                    } else {
                        format!("Namespace: {}", ns)
                    };
                    println!("\n  {}", label);
                    if keys.is_empty() {
                        println!("    (no secrets)");
                    } else {
                        for k in keys {
                            let tier = if store.is_hardware_protected(&ns, &k) {
                                " [Touch ID Enclave]"
                            } else {
                                ""
                            };
                            println!("    • {}{}", k, tier);
                        }
                    }
                }
            } else {
                match target_scope {
                    TargetScope::Global => {
                        let keys = store.list(GLOBAL_NAMESPACE)?;
                        println!("🌐 Global Secrets (available everywhere):");
                        if keys.is_empty() {
                            println!("  (no global secrets found)");
                        } else {
                            for k in keys {
                                let tier = if store.is_hardware_protected(GLOBAL_NAMESPACE, &k) {
                                    " [Touch ID Enclave]"
                                } else {
                                    ""
                                };
                                println!("  • {}{}", k, tier);
                            }
                        }
                    }
                    TargetScope::Project(ref name) => {
                        let ns = format!("proj-{}", name);
                        let project_keys = store.list(&ns)?;
                        let global_keys = store.list(GLOBAL_NAMESPACE)?;

                        println!("📁 Project '{}' Secrets:", name);
                        if project_keys.is_empty() {
                            println!("  (no project-specific secrets)");
                        } else {
                            for k in project_keys {
                                let tier = if store.is_hardware_protected(&ns, &k) {
                                    " [Touch ID Enclave]"
                                } else {
                                    ""
                                };
                                println!("  • {}{}", k, tier);
                            }
                        }

                        println!("\n🌐 Inherited Global Secrets:");
                        if global_keys.is_empty() {
                            println!("  (none)");
                        } else {
                            for k in global_keys {
                                let tier = if store.is_hardware_protected(GLOBAL_NAMESPACE, &k) {
                                    " [Touch ID Enclave]"
                                } else {
                                    ""
                                };
                                println!("  • {}{}", k, tier);
                            }
                        }
                    }
                }
            }
        }

        Commands::Delete { key } => {
            let ns = scope_to_namespace(&target_scope);
            store.delete(&ns, &key)?;
            match target_scope {
                TargetScope::Global => {
                    println!("✓ Secret '{}' deleted from Global scope", key);
                }
                TargetScope::Project(ref name) => {
                    println!("✓ Secret '{}' deleted from project '{}'", key, name);
                }
            }
        }

        Commands::Run {
            keys,
            proxy,
            proxy_port,
            proxy_token,
            command,
        } => {
            if command.is_empty() {
                bail!("No command specified to run.");
            }

            if proxy {
                ensure_proxy_running(proxy_port).await?;
            }

            let secrets: HashMap<String, Zeroizing<String>> = match (&target_scope, &keys) {
                (TargetScope::Global, Some(allowed)) => {
                    let mut map = HashMap::new();
                    for k in allowed {
                        if let Some(v) = store.get(GLOBAL_NAMESPACE, k)? {
                            map.insert(k.clone(), v);
                        }
                    }
                    map
                }
                (TargetScope::Project(ref name), Some(allowed)) => {
                    let ns = format!("proj-{}", name);
                    let mut map = HashMap::new();
                    for k in allowed {
                        // Project scope overrides global scope
                        if let Some(v) = store.get(&ns, k)? {
                            map.insert(k.clone(), v);
                        } else if let Some(v) = store.get(GLOBAL_NAMESPACE, k)? {
                            map.insert(k.clone(), v);
                        }
                    }
                    map
                }
                (TargetScope::Global, None) => store.get_all(GLOBAL_NAMESPACE)?,
                (TargetScope::Project(ref name), None) => {
                    let ns = format!("proj-{}", name);
                    store.get_merged(GLOBAL_NAMESPACE, Some(&ns))?
                }
            };

            let (cmd_name, cmd_args) = command.split_first().unwrap();
            let exit_code = runner::run_with_secrets(
                &secrets,
                cmd_name,
                cmd_args,
                proxy_token,
                proxy,
                proxy_port,
            )?;
            // Return ExitCode from main so local Zeroize Drop destructors execute (S6 fix)
            return Ok(std::process::ExitCode::from(exit_code as u8));
        }

        Commands::Export { format } => {
            let secrets: HashMap<String, Zeroizing<String>> = match target_scope {
                TargetScope::Global => store.get_all(GLOBAL_NAMESPACE)?,
                TargetScope::Project(ref name) => {
                    let ns = format!("proj-{}", name);
                    store.get_merged(GLOBAL_NAMESPACE, Some(&ns))?
                }
            };

            match format {
                ExportFormat::Dotenv => {
                    for (k, v) in secrets {
                        println!("{}={}", k, v.as_str());
                    }
                }
                ExportFormat::Bash => {
                    for (k, v) in secrets {
                        println!("export {}=\"{}\"", k, v.as_str().replace('"', "\\\""));
                    }
                }
                ExportFormat::Json => {
                    let json = serde_json::to_string_pretty(&secrets)?;
                    println!("{}", json);
                }
            }
        }

        Commands::Proxy { port, stop, env } => {
            if env {
                let token = proxy::get_or_create_session_token()?;
                println!("export OPENAI_BASE_URL=\"http://127.0.0.1:{}/v1\"", port);
                println!("export OPENAI_API_KEY=\"{}\"", token);
                println!("export ANTHROPIC_BASE_URL=\"http://127.0.0.1:{}\"", port);
                println!("export ANTHROPIC_API_KEY=\"{}\"", token);
                println!("export CLOAK_PROXY_TOKEN=\"{}\"", token);
                return Ok(std::process::ExitCode::SUCCESS);
            }

            if stop {
                let token = proxy::get_or_create_session_token().unwrap_or_default();
                let port_to_stop = if let Ok(info_path) = proxy::proxy_info_path() {
                    if let Ok(content) = std::fs::read_to_string(&info_path) {
                        serde_json::from_str::<serde_json::Value>(&content)
                            .ok()
                            .and_then(|v| v.get("port").and_then(|p| p.as_u64()))
                            .unwrap_or(port as u64) as u16
                    } else {
                        port
                    }
                } else {
                    port
                };

                let shutdown_url = format!("http://127.0.0.1:{}/cloak/shutdown", port_to_stop);
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(std::time::Duration::from_millis(1500))
                    .build()
                    .unwrap_or_default();

                match client
                    .post(&shutdown_url)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
                {
                    Ok(res) if res.status().is_success() => {
                        println!(
                            "✓ Successfully stopped Cloak Proxy daemon on port {}.",
                            port_to_stop
                        );
                    }
                    _ => {
                        println!(
                            "⚠️ No active Cloak Proxy daemon responded on port {}.",
                            port_to_stop
                        );
                    }
                }
                proxy::remove_proxy_info();
                return Ok(std::process::ExitCode::SUCCESS);
            }

            let ns = scope_to_namespace(&target_scope);
            proxy::start_proxy(store, ns, port).await?;
        }

        Commands::Ca { command } => match command {
            CaCommands::Install => {
                let msg = proxy::ca::install_ca_to_trust_store()?;
                println!("{}", msg);
            }
            CaCommands::Path => {
                let path = proxy::ca::ca_cert_path()?;
                println!("{}", path.display());
            }
        },

        Commands::Gui => {
            println!("🚀 Launching Cloak Hybrid HUD desktop app...");
            let sibling_gui = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("cloak-gui")));
            let app_bundle_gui =
                std::path::PathBuf::from("/Applications/Cloak.app/Contents/MacOS/cloak-gui");
            let status = if let Some(ref path) = sibling_gui.filter(|p| p.exists()) {
                std::process::Command::new(path).spawn()
            } else if app_bundle_gui.exists() {
                std::process::Command::new(app_bundle_gui).spawn()
            } else {
                std::process::Command::new("cloak-gui")
                    .spawn()
                    .or_else(|_| {
                        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                        let path = format!("{}/.cargo/bin/cloak-gui", home);
                        std::process::Command::new(path).spawn()
                    })
            };

            match status {
                Ok(_) => {
                    println!("✓ Cloak HUD is running.");
                }
                Err(e) => {
                    eprintln!("Failed to launch cloak-gui: {e}. Try running 'cloak-gui' directly.");
                }
            }
        }

        Commands::Setup => {
            println!("⚙️  Setting up Cloak across all local LLM agents and tools...\n");
            let rules = cloak::setup::ensure_agent_rules();
            for (path, modified) in rules {
                if modified {
                    println!("  ✓ Configured {}", path);
                } else {
                    println!("  ✓ Verified {}", path);
                }
            }
            if cloak::proxy::ca::CertificateAuthority::load_or_generate().is_ok() {
                if let Ok(ca_path) = cloak::proxy::ca::ca_cert_path() {
                    println!(
                        "  ✓ Local Certificate Authority active at {}",
                        ca_path.display()
                    );
                }
            }
            println!("\n✨ Cloak is active! All AI agents (Claude Code, Cursor, Antigravity, Windsurf, Copilot, Codex) will now route secrets through Cloak.");
        }
    }

    Ok(std::process::ExitCode::SUCCESS)
}

async fn handle_missing_get(
    store: &dyn SecretStore,
    target_scope: &TargetScope,
    key: &str,
    reveal: bool,
    no_prompt: bool,
) -> Result<std::process::ExitCode> {
    if no_prompt {
        match target_scope {
            TargetScope::Global => eprintln!("Error: Secret '{}' not found in Global scope", key),
            TargetScope::Project(name) => eprintln!(
                "Error: Secret '{}' not found in project '{}' or Global scope",
                key, name
            ),
        }
        return Ok(std::process::ExitCode::FAILURE);
    }

    // 1. Try JIT via active Cloak Proxy daemon
    if let Some(port) = proxy::active_proxy_port() {
        if let Ok(token) = proxy::get_or_create_session_token() {
            eprintln!(
                "⏸ [CLOAK JIT] Secret '{}' not found. Submitting JIT request to Cloak Proxy (:{})...",
                key, port
            );
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(65))
                .build()?;
            let url = format!("http://127.0.0.1:{}/cloak/jit/request", port);
            let payload = serde_json::json!({
                "agent": "CLI / Subprocess",
                "key": key,
                "target_endpoint": "cloak get"
            });

            match client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    if let Some(val) = body.get("value").and_then(|v| v.as_str()) {
                        print_val(val, reveal, "JIT Approved");
                        return Ok(std::process::ExitCode::SUCCESS);
                    }
                }
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    let err = body
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("Authorization rejected");
                    eprintln!("❌ JIT Request denied: {}", err);
                    return Ok(std::process::ExitCode::FAILURE);
                }
                Err(e) => {
                    eprintln!("⚠️ Failed to communicate with Cloak Proxy daemon: {e}");
                }
            }
        }
    }

    // 2. Standalone CLI interactive prompt on stderr
    if std::io::stderr().is_terminal() {
        eprintln!(
            "⏸ [CLOAK JIT] Secret '{}' requested. Enter value to continue (or Ctrl+C to cancel):",
            key
        );
        let entered_val = tokio::task::spawn_blocking({
            let key_owned = key.to_string();
            move || rpassword::prompt_password(format!("Enter {}: ", key_owned))
        })
        .await?
        .context("Failed to read secret value")?;

        let trimmed = entered_val.trim();
        if trimmed.is_empty() {
            eprintln!("Error: No secret entered. Aborting.");
            return Ok(std::process::ExitCode::FAILURE);
        }

        // Ask whether to save permanently
        eprint!("Save permanently in vault? (y/N): ");
        use std::io::Write;
        let _ = std::io::stderr().flush();

        let save_permanently = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            line.trim().eq_ignore_ascii_case("y")
        })
        .await
        .unwrap_or(false);

        if save_permanently {
            let ns = scope_to_namespace(target_scope);
            store.set(&ns, key, trimmed)?;
            eprintln!("✓ Secret '{}' saved to vault scope '{}'.", key, ns);
        } else {
            eprintln!(
                "✓ Secret '{}' authorized for one-time use (not persisted).",
                key
            );
        }

        print_val(trimmed, reveal, "JIT Authorized");
        return Ok(std::process::ExitCode::SUCCESS);
    }

    // Non-interactive and no daemon: fail
    match target_scope {
        TargetScope::Global => eprintln!("Error: Secret '{}' not found in Global scope", key),
        TargetScope::Project(name) => eprintln!(
            "Error: Secret '{}' not found in project '{}' or Global scope",
            key, name
        ),
    }
    Ok(std::process::ExitCode::FAILURE)
}

fn print_val(val: &str, reveal: bool, scope_label: &str) {
    if reveal {
        println!("{}", val);
    } else {
        println!(
            "{} [{}] (use --reveal to display in full)",
            mask_secret(val),
            scope_label
        );
    }
}
