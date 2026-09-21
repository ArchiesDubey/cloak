//! Cloak Desktop Tauri App: Backend IPC bridge for Cloak Core & macOS Keychain.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cloak::storage::keyring_store::KeyringStore;
use cloak::storage::SecretStore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretItemDto {
    pub id: String,
    pub key: String,
    pub masked_value: String,
    pub scope: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyStatusDto {
    pub active: bool,
    pub port: u16,
    pub openai_configured: bool,
    pub anthropic_configured: bool,
}

pub struct AppState {
    pub store: Mutex<KeyringStore>,
}

fn mask_val(val: &str) -> String {
    if val.len() <= 8 {
        "••••••••".to_string()
    } else {
        let start = &val[..4];
        let end = &val[val.len() - 4..];
        format!("{}••••••••{}", start, end)
    }
}

#[tauri::command]
fn list_secrets(state: State<AppState>) -> Result<Vec<SecretItemDto>, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    let namespaces = store.list_namespaces().map_err(|e| e.to_string())?;

    let mut result = Vec::new();

    for ns in namespaces {
        let keys = store.list(&ns).map_err(|e| e.to_string())?;
        for key in keys {
            let masked = if let Ok(Some(val)) = store.get(&ns, &key) {
                mask_val(&val)
            } else {
                "••••••••".to_string()
            };

            let scope_label = if ns == "global" {
                "global".to_string()
            } else if let Some(p) = ns.strip_prefix("proj-") {
                p.to_string()
            } else {
                ns.clone()
            };

            result.push(SecretItemDto {
                id: format!("{}:{}", ns, key),
                key,
                masked_value: masked,
                scope: scope_label,
                updated_at: "Stored in Keychain".to_string(),
            });
        }
    }

    Ok(result)
}

#[tauri::command]
fn reveal_secret(state: State<AppState>, scope: String, key: String) -> Result<String, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    match store.get(&ns, &key) {
        Ok(Some(val)) => Ok(val),
        Ok(None) => Err(format!("Secret '{}' not found in scope '{}'", key, scope)),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn save_secret(state: State<AppState>, scope: String, key: String, value: String) -> Result<(), String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    store.set(&ns, &key, &value).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_secret(state: State<AppState>, scope: String, key: String) -> Result<(), String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    store.delete(&ns, &key).map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_proxy_status() -> ProxyStatusDto {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(800))
        .build()
        .unwrap();

    if let Ok(res) = client.get("http://127.0.0.1:4141/health").send().await {
        if let Ok(json) = res.json::<serde_json::Value>().await {
            let openai = json["providers"]["openai"]["configured"].as_bool().unwrap_or(false);
            let anthropic = json["providers"]["anthropic"]["configured"].as_bool().unwrap_or(false);
            return ProxyStatusDto {
                active: true,
                port: 4141,
                openai_configured: openai,
                anthropic_configured: anthropic,
            };
        }
    }

    ProxyStatusDto {
        active: false,
        port: 4141,
        openai_configured: false,
        anthropic_configured: false,
    }
}

#[tauri::command]
fn toggle_window_mode(window: tauri::Window, expanded: bool) -> Result<(), String> {
    if expanded {
        window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: 960.0,
            height: 700.0,
        })).map_err(|e| e.to_string())?;
    } else {
        window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: 460.0,
            height: 640.0,
        })).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let store = KeyringStore::new().expect("Failed to initialize Keyring store");

    tauri::Builder::default()
        .manage(AppState {
            store: Mutex::new(store),
        })
        .invoke_handler(tauri::generate_handler![
            list_secrets,
            reveal_secret,
            save_secret,
            delete_secret,
            check_proxy_status,
            toggle_window_mode,
        ])
        .run(tauri::generate_context!())
        .expect("error while running cloak desktop application");
}
