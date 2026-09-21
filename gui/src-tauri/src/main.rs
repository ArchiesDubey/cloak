//! Cloak Desktop Tauri App: Backend IPC bridge for Cloak Core & macOS Keychain.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cloak::storage::keyring_store::KeyringStore;
use cloak::storage::SecretStore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

extern "C" {
    fn cloak_authenticate_biometrics(reason_str: *const std::os::raw::c_char) -> std::os::raw::c_int;
}

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecurityStatusDto {
    pub is_unlocked: bool,
    pub hardware_backend: String,
    pub biometric_type: String,
}

pub struct AppState {
    pub store: Mutex<KeyringStore>,
    pub is_unlocked: Mutex<bool>,
}

#[tauri::command]
fn list_secrets(state: State<AppState>) -> Result<Vec<SecretItemDto>, String> {
    let unlocked = *state.is_unlocked.lock().map_err(|e| e.to_string())?;
    if !unlocked {
        return Ok(Vec::new());
    }

    let store = state.store.lock().map_err(|e| e.to_string())?;
    let namespaces = store.list_namespaces().map_err(|e| e.to_string())?;

    let mut result = Vec::new();

    for ns in namespaces {
        let keys = store.list(&ns).map_err(|e| e.to_string())?;
        for key in keys {
            let masked = "••••••••••••••••".to_string();

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
    let unlocked = *state.is_unlocked.lock().map_err(|e| e.to_string())?;
    if !unlocked {
        return Err("Hardware Vault is locked. Authenticate with Touch ID to access.".to_string());
    }

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
    let unlocked = *state.is_unlocked.lock().map_err(|e| e.to_string())?;
    if !unlocked {
        return Err("Hardware Vault is locked. Authenticate with Touch ID to store secrets.".to_string());
    }

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
    let unlocked = *state.is_unlocked.lock().map_err(|e| e.to_string())?;
    if !unlocked {
        return Err("Hardware Vault is locked. Authenticate with Touch ID to delete secrets.".to_string());
    }

    let store = state.store.lock().map_err(|e| e.to_string())?;
    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    store.delete(&ns, &key).map_err(|e| e.to_string())
}

#[tauri::command]
async fn authenticate_vault(state: State<'_, AppState>) -> Result<bool, String> {
    let success = tokio::task::spawn_blocking(|| {
        let reason = std::ffi::CString::new("Unlock Cloak Hardware Vault").unwrap();
        let res = unsafe { cloak_authenticate_biometrics(reason.as_ptr()) };
        res == 1
    })
    .await
    .map_err(|e| e.to_string())?;

    if success {
        let mut unlocked = state.is_unlocked.lock().map_err(|e| e.to_string())?;
        *unlocked = true;
    }

    Ok(success)
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<bool, String> {
    let mut unlocked = state.is_unlocked.lock().map_err(|e| e.to_string())?;
    *unlocked = false;
    Ok(false)
}

#[tauri::command]
fn get_security_status(state: State<'_, AppState>) -> Result<SecurityStatusDto, String> {
    let unlocked = *state.is_unlocked.lock().map_err(|e| e.to_string())?;
    Ok(SecurityStatusDto {
        is_unlocked: unlocked,
        hardware_backend: "macOS Keychain & Secure Enclave".to_string(),
        biometric_type: "Touch ID / Device Passcode".to_string(),
    })
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
            is_unlocked: Mutex::new(true),
        })
        .invoke_handler(tauri::generate_handler![
            list_secrets,
            reveal_secret,
            save_secret,
            delete_secret,
            check_proxy_status,
            toggle_window_mode,
            authenticate_vault,
            lock_vault,
            get_security_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running cloak desktop application");
}
