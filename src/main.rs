//! Cloak: Local-First Cross-Platform Secrets Manager & AI Proxy

mod crypto;
mod runner;
mod security;
mod storage;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use storage::file_store::FileStore;
use storage::keyring_store::KeyringStore;
use storage::SecretStore;

#[derive(Parser)]
#[command(name = "cloak")]
#[command(about = "Local-first cross-platform secrets manager & child process injector", long_about = None)]
#[command(version)]
struct Cli {
    /// Namespace to operate within
    #[arg(short, long, global = true, default_value = "default")]
    namespace: String,

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
    /// List all secret keys in the current namespace (values are never shown)
    List,
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
    /// Export secrets for the current namespace
    Export {
        /// Export format
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
}

fn get_store(backend: StoreBackend, custom_vault: Option<PathBuf>) -> Result<Box<dyn SecretStore>> {
    match backend {
        StoreBackend::Keyring => {
            let store = KeyringStore::new()
                .context("Failed to initialize OS Keyring backend. Consider using --store file on headless systems.")?;
            Ok(Box::new(store))
        }
        StoreBackend::File => {
            let vault_path = custom_vault.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".config").join("cloak").join("vault.enc")
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

fn main() -> Result<()> {
    // Apply process-level hardening (anti-core dump, disable ptrace where applicable)
    security::harden_process();

    let cli = Cli::parse();
    let store = get_store(cli.store, cli.vault_path)?;

    match cli.command {
        Commands::Set { key, value } => {
            let val = match value {
                Some(v) => v,
                None => rpassword::prompt_password(format!("Enter value for '{}': ", key))
                    .context("Failed to read masked secret value")?,
            };

            store.set(&cli.namespace, &key, &val)?;
            println!("✓ Secret '{}' saved in namespace '{}'", key, cli.namespace);
        }
        Commands::Get { key, reveal } => {
            match store.get(&cli.namespace, &key)? {
                Some(val) => {
                    if reveal {
                        println!("{}", val);
                    } else {
                        println!("{} (use --reveal to display in full)", mask_secret(&val));
                    }
                }
                None => {
                    eprintln!("Error: Secret '{}' not found in namespace '{}'", key, cli.namespace);
                    std::process::exit(1);
                }
            }
        }
        Commands::List => {
            let keys = store.list(&cli.namespace)?;
            if keys.is_empty() {
                println!("Namespace '{}' is empty.", cli.namespace);
            } else {
                println!("Secrets in namespace '{}':", cli.namespace);
                for k in keys {
                    println!("  • {}", k);
                }
            }
        }
        Commands::Delete { key } => {
            store.delete(&cli.namespace, &key)?;
            println!("✓ Secret '{}' deleted from namespace '{}'", key, cli.namespace);
        }
        Commands::Run { command } => {
            if command.is_empty() {
                bail!("No command specified to run.");
            }
            let (cmd_name, cmd_args) = command.split_first().unwrap();
            let exit_code = runner::run_with_secrets(&*store, &cli.namespace, cmd_name, cmd_args)?;
            std::process::exit(exit_code);
        }
        Commands::Export { format } => {
            let secrets = store.get_all(&cli.namespace)?;
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
    }

    Ok(())
}
