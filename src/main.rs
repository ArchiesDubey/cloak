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
use std::path::PathBuf;
use storage::file_store::FileStore;
use storage::keyring_store::KeyringStore;
use storage::SecretStore;

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
    },
    /// Retrieve a secret value
    Get {
        /// Secret key name
        key: String,
        /// Reveal the full secret value (otherwise partially masked to prevent screen leaks)
        #[arg(long)]
        reveal: bool,
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
    /// Start the Local AI Loopback Proxy with JIT secret acquisition
    Proxy {
        /// Port to listen on (binds strictly to 127.0.0.1)
        #[arg(long, default_value_t = 4141)]
        port: u16,
    },
    /// Launch the Cloak Desktop GUI (Hybrid HUD)
    Gui,
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

            let passphrase = if let Ok(pass) = std::env::var("CLOAK_MASTER_KEY") {
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
    if value.len() <= 8 {
        "********".to_string()
    } else {
        let start = &value[..4];
        let end = &value[value.len() - 4..];
        format!("{}****{}", start, end)
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

#[tokio::main]
async fn main() -> Result<()> {
    // Apply process-level hardening (anti-core dump, disable ptrace where applicable)
    security::harden_process();

    let cli = Cli::parse();

    // Handle 'init' before loading stores if applicable
    if let Commands::Init { name } = &cli.command {
        let proj = project::init_project(name.clone())?;
        println!("✓ Initialized Cloak project '{}' in {:?}", proj.name, proj.root);
        println!("  Secrets saved in this directory will be scoped to '{}' by default.", proj.name);
        return Ok(());
    }

    let store = get_store(cli.store, cli.vault_path)?;
    let target_scope = resolve_target_scope(cli.global, cli.project.as_deref());

    match cli.command {
        Commands::Init { .. } => unreachable!(),

        Commands::Set { key, value } => {
            let val = match value {
                Some(v) => v,
                None => rpassword::prompt_password(format!("Enter value for '{}': ", key))
                    .context("Failed to read masked secret value")?,
            };

            let ns = scope_to_namespace(&target_scope);
            store.set(&ns, &key, &val)?;

            match target_scope {
                TargetScope::Global => {
                    println!("✓ Secret '{}' saved to Global scope (available machine-wide)", key);
                }
                TargetScope::Project(ref name) => {
                    println!("✓ Secret '{}' saved to project '{}'", key, name);
                }
            }
        }

        Commands::Get { key, reveal } => {
            match target_scope {
                TargetScope::Global => {
                    match store.get(GLOBAL_NAMESPACE, &key)? {
                        Some(val) => print_val(&val, reveal, "Global"),
                        None => {
                            eprintln!("Error: Secret '{}' not found in Global scope", key);
                            std::process::exit(1);
                        }
                    }
                }
                TargetScope::Project(ref name) => {
                    let ns = format!("proj-{}", name);
                    // Check project first, then fallback to global
                    if let Some(val) = store.get(&ns, &key)? {
                        print_val(&val, reveal, &format!("Project '{}'", name));
                    } else if let Some(val) = store.get(GLOBAL_NAMESPACE, &key)? {
                        print_val(&val, reveal, "Inherited from Global");
                    } else {
                        eprintln!(
                            "Error: Secret '{}' not found in project '{}' or Global scope",
                            key, name
                        );
                        std::process::exit(1);
                    }
                }
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
                            println!("    • {}", k);
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
                                println!("  • {}", k);
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
                                println!("  • {}", k);
                            }
                        }

                        println!("\n🌐 Inherited Global Secrets:");
                        if global_keys.is_empty() {
                            println!("  (none)");
                        } else {
                            for k in global_keys {
                                println!("  • {}", k);
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

        Commands::Run { command } => {
            if command.is_empty() {
                bail!("No command specified to run.");
            }

            let secrets: HashMap<String, String> = match target_scope {
                TargetScope::Global => store.get_all(GLOBAL_NAMESPACE)?,
                TargetScope::Project(ref name) => {
                    let ns = format!("proj-{}", name);
                    store.get_merged(GLOBAL_NAMESPACE, Some(&ns))?
                }
            };

            let (cmd_name, cmd_args) = command.split_first().unwrap();
            let exit_code = runner::run_with_secrets(&secrets, cmd_name, cmd_args)?;
            std::process::exit(exit_code);
        }

        Commands::Export { format } => {
            let secrets: HashMap<String, String> = match target_scope {
                TargetScope::Global => store.get_all(GLOBAL_NAMESPACE)?,
                TargetScope::Project(ref name) => {
                    let ns = format!("proj-{}", name);
                    store.get_merged(GLOBAL_NAMESPACE, Some(&ns))?
                }
            };

            match format {
                ExportFormat::Dotenv => {
                    for (k, v) in secrets {
                        println!("{}={}", k, v);
                    }
                }
                ExportFormat::Bash => {
                    for (k, v) in secrets {
                        println!("export {}=\"{}\"", k, v.replace('"', "\\\""));
                    }
                }
                ExportFormat::Json => {
                    let json = serde_json::to_string_pretty(&secrets)?;
                    println!("{}", json);
                }
            }
        }

        Commands::Proxy { port } => {
            let ns = scope_to_namespace(&target_scope);
            proxy::start_proxy(store, ns, port).await?;
        }

        Commands::Gui => {
            println!("🚀 Launching Cloak Hybrid HUD desktop app...");
            let status = std::process::Command::new("cloak-gui")
                .spawn()
                .or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    let path = format!("{}/.cargo/bin/cloak-gui", home);
                    std::process::Command::new(path).spawn()
                });

            match status {
                Ok(_) => {
                    println!("✓ Cloak HUD is running.");
                }
                Err(e) => {
                    eprintln!("Failed to launch cloak-gui: {e}. Try running 'cloak-gui' directly.");
                }
            }
        }
    }

    Ok(())
}

fn print_val(val: &str, reveal: bool, scope_label: &str) {
    if reveal {
        println!("{}", val);
    } else {
        println!("{} [{}] (use --reveal to display in full)", mask_secret(val), scope_label);
    }
}
