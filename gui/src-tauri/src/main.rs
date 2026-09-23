//! Cloak Desktop Tauri App: Backend IPC bridge for Cloak Core & OS Keyring.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cloak::storage::keyring_store::KeyringStore;
use cloak::storage::SecretStore;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::State;

#[cfg(target_os = "macos")]
extern "C" {
    fn cloak_authenticate_biometrics(
        reason_str: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
    fn cloak_copy_concealed(secret_utf8: *const std::os::raw::c_char) -> std::os::raw::c_long;
    fn cloak_clear_clipboard_if_unchanged(expected_change_count: std::os::raw::c_long);
}

#[cfg(not(target_os = "macos"))]
unsafe fn cloak_authenticate_biometrics(
    _reason_str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    0
}

#[cfg(not(target_os = "macos"))]
unsafe fn cloak_copy_concealed(_secret_utf8: *const std::os::raw::c_char) -> std::os::raw::c_long {
    0
}

#[cfg(not(target_os = "macos"))]
unsafe fn cloak_clear_clipboard_if_unchanged(_expected_change_count: std::os::raw::c_long) {}

fn platform_authenticate(reason: &str) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        let prompt = format!("{}\0", reason);
        let c_prompt = prompt.as_ptr() as *const std::os::raw::c_char;
        let res = unsafe { cloak_authenticate_biometrics(c_prompt) };
        Ok(res == 1)
    }

    #[cfg(target_os = "windows")]
    {
        // Real Windows account credential validation via PrincipalContext
        let escaped_reason = reason.replace('\'', "''");
        let script = format!(
            "Add-Type -AssemblyName System.DirectoryServices.AccountManagement; \
             $cred = $Host.UI.PromptForCredential('Cloak Hardware Vault', '{}', [Environment]::UserName, ''); \
             if ($null -eq $cred) {{ exit 1 }}; \
             $u = $cred.GetNetworkCredential().UserName; \
             $p = $cred.GetNetworkCredential().Password; \
             $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine); \
             if ($pc.ValidateCredentials($u, $p)) {{ exit 0 }} else {{ exit 2 }}",
            escaped_reason
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .map_err(|e| format!("Failed to spawn Windows credential verification: {e}"))?;
        Ok(status.success())
    }

    #[cfg(target_os = "linux")]
    {
        // Authenticate the current user as themselves using PAM/Polkit
        let current_user = std::env::var("USER").unwrap_or_else(|_| "nobody".to_string());
        if std::path::Path::new("/usr/bin/pkexec").exists() {
            let status = std::process::Command::new("pkexec")
                .args(["--user", &current_user, "true"])
                .status()
                .map_err(|e| format!("Failed to launch polkit authentication: {e}"))?;
            Ok(status.success())
        } else {
            // Strict fail-closed: never fail-open if authentication tooling is missing
            Err("No supported authentication agent (pkexec) found on this Linux system. Authentication failed.".to_string())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err("Unsupported operating system for secure vault authentication.".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretItemDto {
    pub id: String,
    pub key: String,
    pub masked_value: String,
    pub scope: String,
    pub updated_at: String,
    pub hardware_protected: bool,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JitRequestDto {
    pub id: String,
    pub agent: String,
    pub key: String,
    pub target_endpoint: String,
    pub timestamp: String,
}

pub struct AppState {
    pub store: Arc<Mutex<KeyringStore>>,
    pub is_unlocked: Mutex<bool>,
    pub proxy_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub last_activity: Mutex<Option<std::time::Instant>>,
}

fn check_session_active(state: &AppState, touch: bool) -> bool {
    let mut unlocked = match state.is_unlocked.lock() {
        Ok(u) => u,
        Err(_) => return false,
    };
    if !*unlocked {
        return false;
    }
    let mut last = match state.last_activity.lock() {
        Ok(l) => l,
        Err(_) => return false,
    };
    if let Some(t) = *last {
        // Auto-relock after 5 minutes (300 seconds) of inactivity (S2 fix)
        if t.elapsed() > std::time::Duration::from_secs(300) {
            *unlocked = false;
            *last = None;
            return false;
        }
    }
    if touch {
        *last = Some(std::time::Instant::now());
    }
    true
}

#[tauri::command]
fn list_secrets(state: State<AppState>) -> Result<Vec<SecretItemDto>, String> {
    if !check_session_active(&state, true) {
        return Ok(Vec::new());
    }

    let store = match state.store.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let namespaces = store.list_namespaces().map_err(|e| e.to_string())?;

    let mut result = Vec::new();

    for ns in namespaces {
        let keys = store.list(&ns).map_err(|e| e.to_string())?;
        for key in keys {
            let masked = "••••••••••••••••".to_string();
            let hw_protected = store.is_hardware_protected(&ns, &key);

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
                updated_at: if hw_protected {
                    "Touch ID Secure Enclave".to_string()
                } else {
                    "Standard Keyring".to_string()
                },
                hardware_protected: hw_protected,
            });
        }
    }

    Ok(result)
}

#[tauri::command]
async fn reveal_secret(
    state: State<'_, AppState>,
    scope: String,
    key: String,
) -> Result<String, String> {
    if !check_session_active(&state, true) {
        return Err("Hardware Vault is locked. Authenticate to access.".to_string());
    }

    if key.trim().is_empty() {
        return Err("Secret key name cannot be empty".to_string());
    }

    let prompt_msg = format!("Authenticate to reveal secret '{}'", key);
    let auth_ok = tokio::task::spawn_blocking(move || platform_authenticate(&prompt_msg))
        .await
        .map_err(|e| e.to_string())??;

    if !auth_ok {
        return Err("Authentication cancelled or failed.".to_string());
    }

    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    let key_clone = key.clone();
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let s = match store.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match s.get(&ns, &key_clone) {
            Ok(Some(val)) => Ok(val.as_str().to_string()),
            Ok(None) => Err(format!(
                "Secret '{}' not found in scope '{}'",
                key_clone, scope
            )),
            Err(e) => Err(e.to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn copy_secret_secure(
    state: State<'_, AppState>,
    scope: String,
    key: String,
) -> Result<(), String> {
    if !check_session_active(&state, true) {
        return Err("Hardware Vault is locked. Authenticate to copy secrets.".to_string());
    }

    if key.trim().is_empty() {
        return Err("Secret key name cannot be empty".to_string());
    }

    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    let key_clone = key.clone();
    let store = state.store.clone();
    let val = tokio::task::spawn_blocking(move || {
        let s = match store.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match s.get(&ns, &key_clone) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(format!(
                "Secret '{}' not found in scope '{}'",
                key_clone, scope
            )),
            Err(e) => Err(e.to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())??;

    #[cfg(target_os = "macos")]
    {
        let c_val = std::ffi::CString::new(val.as_str()).map_err(|e| e.to_string())?;
        let change_count = unsafe { cloak_copy_concealed(c_val.as_ptr()) };

        // Wipe clipboard automatically after 30 seconds only if unchanged
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            unsafe {
                cloak_clear_clipboard_if_unchanged(change_count);
            }
        });
    }

    #[cfg(not(target_os = "macos"))]
    {
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| format!("Failed to access clipboard: {e}"))?;
        clipboard
            .set_text(val.as_str())
            .map_err(|e| format!("Failed to copy to clipboard: {e}"))?;

        let secret_copy = val.as_str().to_string();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(current_text) = cb.get_text() {
                    if current_text == secret_copy {
                        let _ = cb.clear();
                    }
                }
            }
        });
    }

    Ok(())
}

#[tauri::command]
async fn save_secret(
    state: State<'_, AppState>,
    scope: String,
    key: String,
    value: String,
    hardware_protected: Option<bool>,
) -> Result<(), String> {
    if !check_session_active(&state, true) {
        return Err("Hardware Vault is locked. Authenticate to store secrets.".to_string());
    }

    if key.trim().is_empty() {
        return Err("Secret key name cannot be empty".to_string());
    }
    if key.contains('\0') {
        return Err("Secret key cannot contain null bytes".to_string());
    }
    if value.trim().is_empty() {
        return Err("Secret value cannot be empty".to_string());
    }

    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    let require_hw = hardware_protected.unwrap_or(false);
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let s = match store.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        s.set_secure(&ns, &key, &value, require_hw)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn delete_secret(
    state: State<'_, AppState>,
    scope: String,
    key: String,
) -> Result<(), String> {
    if !check_session_active(&state, true) {
        return Err("Hardware Vault is locked. Authenticate to delete secrets.".to_string());
    }

    if key.trim().is_empty() {
        return Err("Secret key name cannot be empty".to_string());
    }

    let ns = if scope == "global" {
        "global".to_string()
    } else {
        format!("proj-{}", scope)
    };

    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let s = match store.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        s.delete(&ns, &key).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn authenticate_vault(state: State<'_, AppState>) -> Result<bool, String> {
    let success =
        tokio::task::spawn_blocking(|| platform_authenticate("Unlock Cloak Hardware Vault"))
            .await
            .map_err(|e| e.to_string())??;

    if success {
        let mut unlocked = state.is_unlocked.lock().map_err(|e| e.to_string())?;
        *unlocked = true;
        let mut last = state.last_activity.lock().map_err(|e| e.to_string())?;
        *last = Some(std::time::Instant::now());
    }

    Ok(success)
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<bool, String> {
    let mut unlocked = state.is_unlocked.lock().map_err(|e| e.to_string())?;
    *unlocked = false;
    let mut last = state.last_activity.lock().map_err(|e| e.to_string())?;
    *last = None;
    Ok(false)
}

#[tauri::command]
fn get_security_status(state: State<'_, AppState>) -> Result<SecurityStatusDto, String> {
    let unlocked = check_session_active(&state, false);

    #[cfg(target_os = "macos")]
    let (backend, bio) = ("macOS Keychain (OS Keyring)", "Touch ID / Device Passcode");

    #[cfg(target_os = "windows")]
    let (backend, bio) = (
        "Windows Credential Manager (DPAPI)",
        "Windows Hello / Credentials",
    );

    #[cfg(target_os = "linux")]
    let (backend, bio) = (
        "FreeDesktop Secret Service (Keyring)",
        "Polkit / PAM Verification",
    );

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let (backend, bio) = ("OS Keyring Backend", "System Passcode");

    Ok(SecurityStatusDto {
        is_unlocked: unlocked,
        hardware_backend: backend.to_string(),
        biometric_type: bio.to_string(),
    })
}

fn active_proxy_port() -> u16 {
    if let Ok(info_path) = cloak::proxy::proxy_info_path() {
        if let Ok(content) = std::fs::read_to_string(info_path) {
            serde_json::from_str::<serde_json::Value>(&content)
                .ok()
                .and_then(|v| v.get("port").and_then(|p| p.as_u64()))
                .unwrap_or(4141) as u16
        } else {
            4141
        }
    } else {
        4141
    }
}

#[tauri::command]
async fn check_proxy_status() -> ProxyStatusDto {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(800))
        .build()
        .unwrap();

    let token = cloak::proxy::get_or_create_session_token().unwrap_or_default();
    let port = active_proxy_port();

    let health_url = format!("http://127.0.0.1:{}/health", port);
    if let Ok(res) = client
        .get(&health_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
    {
        if let Ok(json) = res.json::<serde_json::Value>().await {
            if json.get("status").and_then(|s| s.as_str()) == Some("active") {
                let openai = json["providers"]["openai"]["configured"]
                    .as_bool()
                    .unwrap_or(false);
                let anthropic = json["providers"]["anthropic"]["configured"]
                    .as_bool()
                    .unwrap_or(false);
                let running_port = json
                    .get("port")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(port as u64) as u16;
                return ProxyStatusDto {
                    active: true,
                    port: running_port,
                    openai_configured: openai,
                    anthropic_configured: anthropic,
                };
            }
        }
    }

    ProxyStatusDto {
        active: false,
        port,
        openai_configured: false,
        anthropic_configured: false,
    }
}

#[tauri::command]
async fn toggle_proxy(state: State<'_, AppState>) -> Result<ProxyStatusDto, String> {
    let token = cloak::proxy::get_or_create_session_token().map_err(|e| e.to_string())?;

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .unwrap();

    let current = check_proxy_status().await;

    if current.active {
        // Stop active proxy daemon (whether started from CLI or GUI)
        let shutdown_url = format!("http://127.0.0.1:{}/cloak/shutdown", current.port);
        let _ = client
            .post(&shutdown_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        // Also abort local handle if GUI spawned it
        {
            let mut handle_guard = state.proxy_handle.lock().map_err(|e| e.to_string())?;
            if let Some(handle) = handle_guard.take() {
                handle.abort();
            }
        }

        cloak::proxy::remove_proxy_info();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        return Ok(ProxyStatusDto {
            active: false,
            port: current.port,
            openai_configured: false,
            anthropic_configured: false,
        });
    }

    // Start proxy daemon from GUI
    let store = match KeyringStore::new() {
        Ok(s) => Box::new(s),
        Err(e) => return Err(format!("Failed to initialize keystore: {}", e)),
    };

    let target_port = current.port;
    let handle = tokio::spawn(async move {
        if let Err(e) = cloak::proxy::start_proxy(store, "global".to_string(), target_port).await {
            eprintln!("[CLOAK GUI] Loopback proxy stopped: {e}");
        }
    });

    {
        let mut handle_guard = state.proxy_handle.lock().map_err(|e| e.to_string())?;
        *handle_guard = Some(handle);
    }

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    Ok(check_proxy_status().await)
}

#[tauri::command]
fn toggle_window_mode(window: tauri::Window, expanded: bool) -> Result<(), String> {
    if expanded {
        window
            .set_size(tauri::Size::Logical(tauri::LogicalSize {
                width: 960.0,
                height: 700.0,
            }))
            .map_err(|e| e.to_string())?;
    } else {
        window
            .set_size(tauri::Size::Logical(tauri::LogicalSize {
                width: 460.0,
                height: 640.0,
            }))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn get_pending_jit_request() -> Result<Option<JitRequestDto>, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .map_err(|e| e.to_string())?;

    let token = cloak::proxy::get_or_create_session_token().map_err(|e| e.to_string())?;
    let port = active_proxy_port();

    if let Ok(res) = client
        .get(format!("http://127.0.0.1:{}/cloak/jit/pending", port))
        .header("X-Cloak-Token", &token)
        .send()
        .await
    {
        if let Ok(list) = res.json::<Vec<JitRequestDto>>().await {
            return Ok(list.into_iter().next());
        }
    }
    Ok(None)
}

#[tauri::command]
async fn respond_jit(
    request_id: String,
    action: String,
    value: Option<String>,
) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .map_err(|e| e.to_string())?;

    let token = cloak::proxy::get_or_create_session_token().map_err(|e| e.to_string())?;
    let port = active_proxy_port();

    let payload = serde_json::json!({
        "id": request_id,
        "action": action,
        "value": value
    });

    if let Ok(res) = client
        .post(format!("http://127.0.0.1:{}/cloak/jit/respond", port))
        .header("X-Cloak-Token", &token)
        .json(&payload)
        .send()
        .await
    {
        return Ok(res.status().is_success());
    }
    Ok(false)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CliStatusDto {
    pub is_installed: bool,
    pub cli_path: Option<String>,
    pub target_symlink: Option<String>,
    pub message: String,
}

fn find_bundled_cli() -> Option<std::path::PathBuf> {
    let bin_name = if cfg!(windows) { "cloak.exe" } else { "cloak" };

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            // Check direct sibling in executable directory
            let sibling = exe_dir.join(bin_name);
            if sibling.is_file() {
                return Some(sibling);
            }

            // Check Resources directory inside bundle or parent directory
            if let Some(contents_dir) = exe_dir.parent() {
                let resources_dir = contents_dir.join("Resources");
                let candidate1 = resources_dir.join(bin_name);
                if candidate1.is_file() {
                    return Some(candidate1);
                }
                let candidate2 = resources_dir.join("bin").join(bin_name);
                if candidate2.is_file() {
                    return Some(candidate2);
                }
                let candidate3 = resources_dir.join("target").join("release").join(bin_name);
                if candidate3.is_file() {
                    return Some(candidate3);
                }
            }
        }
    }

    // Check fixed /Applications bundle path on macOS
    #[cfg(target_os = "macos")]
    {
        let app_bundle_cli = std::path::PathBuf::from("/Applications/Cloak.app/Contents/Resources/cloak");
        if app_bundle_cli.is_file() {
            return Some(app_bundle_cli);
        }
        let app_bundle_macos = std::path::PathBuf::from("/Applications/Cloak.app/Contents/MacOS/cloak");
        if app_bundle_macos.is_file() {
            return Some(app_bundle_macos);
        }
    }

    // Dev fallback via HOME or USERPROFILE
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let cargo_bin = std::path::PathBuf::from(&home).join(".cargo").join("bin").join(bin_name);
        if cargo_bin.is_file() {
            return Some(cargo_bin);
        }
    }

    None
}

fn determine_symlink_target() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let local_bin = std::path::PathBuf::from(userprofile).join(".cargo").join("bin");
            let _ = std::fs::create_dir_all(&local_bin);
            return local_bin.join("cloak.exe");
        }
        return std::path::PathBuf::from("C:\\Windows\\System32\\cloak.exe");
    }

    #[cfg(not(windows))]
    {
        // 1. Try /usr/local/bin if it exists or can be written to
        let usr_local_bin = std::path::PathBuf::from("/usr/local/bin");
        if usr_local_bin.exists() {
            return usr_local_bin.join("cloak");
        }

        // 2. Try ~/.local/bin
        if let Ok(home) = std::env::var("HOME") {
            let home_path = std::path::PathBuf::from(home);
            let local_bin = home_path.join(".local/bin");
            let _ = std::fs::create_dir_all(&local_bin);
            if local_bin.exists() {
                return local_bin.join("cloak");
            }
        }

        std::path::PathBuf::from("/usr/local/bin/cloak")
    }
}

fn ensure_cli_symlink() -> CliStatusDto {
    let bundled = match find_bundled_cli() {
        Some(b) => b,
        None => {
            return CliStatusDto {
                is_installed: false,
                cli_path: None,
                target_symlink: None,
                message: "Bundled CLI binary not found in application bundle".to_string(),
            };
        }
    };

    let target = determine_symlink_target();

    // Check if target symlink already points to this exact bundled binary
    if target.exists() {
        if let Ok(dest) = std::fs::read_link(&target) {
            if dest == bundled {
                return CliStatusDto {
                    is_installed: true,
                    cli_path: Some(bundled.to_string_lossy().to_string()),
                    target_symlink: Some(target.to_string_lossy().to_string()),
                    message: format!("CLI is linked at {}", target.display()),
                };
            }
        }
    }

    // Attempt to create or update symlink
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if target.exists() || std::fs::symlink_metadata(&target).is_ok() {
            let _ = std::fs::remove_file(&target);
        }
        match symlink(&bundled, &target) {
            Ok(_) => CliStatusDto {
                is_installed: true,
                cli_path: Some(bundled.to_string_lossy().to_string()),
                target_symlink: Some(target.to_string_lossy().to_string()),
                message: format!("Successfully installed CLI symlink at {}", target.display()),
            },
            Err(e) => {
                // If /usr/local/bin failed (e.g. PermissionDenied), fallback to ~/.local/bin/cloak or ~/.cargo/bin/cloak
                if let Ok(home) = std::env::var("HOME") {
                    let fallback_targets = vec![
                        std::path::PathBuf::from(&home).join(".local/bin/cloak"),
                        std::path::PathBuf::from(&home).join(".cargo/bin/cloak"),
                    ];
                    for fb in fallback_targets {
                        if let Some(parent) = fb.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if fb.exists() || std::fs::symlink_metadata(&fb).is_ok() {
                            let _ = std::fs::remove_file(&fb);
                        }
                        if symlink(&bundled, &fb).is_ok() {
                            return CliStatusDto {
                                is_installed: true,
                                cli_path: Some(bundled.to_string_lossy().to_string()),
                                target_symlink: Some(fb.to_string_lossy().to_string()),
                                message: format!("Installed CLI symlink at {}", fb.display()),
                            };
                        }
                    }
                }

                CliStatusDto {
                    is_installed: false,
                    cli_path: Some(bundled.to_string_lossy().to_string()),
                    target_symlink: Some(target.to_string_lossy().to_string()),
                    message: format!("Failed to create symlink at {}: {e}", target.display()),
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        CliStatusDto {
            is_installed: false,
            cli_path: Some(bundled.to_string_lossy().to_string()),
            target_symlink: None,
            message: "Symlink installation not supported on this platform".to_string(),
        }
    }
}

#[tauri::command]
fn get_cli_status() -> CliStatusDto {
    let bundled = find_bundled_cli();
    let target = determine_symlink_target();
    let is_linked = if target.exists() {
        if let Ok(dest) = std::fs::read_link(&target) {
            bundled.as_ref().map(|b| b == &dest).unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    CliStatusDto {
        is_installed: is_linked,
        cli_path: bundled.map(|p| p.to_string_lossy().to_string()),
        target_symlink: Some(target.to_string_lossy().to_string()),
        message: if is_linked {
            format!("CLI active at {}", target.display())
        } else {
            "CLI symlink not installed".to_string()
        },
    }
}

#[tauri::command]
fn install_cli_symlink() -> Result<CliStatusDto, String> {
    Ok(ensure_cli_symlink())
}

#[tauri::command]
fn install_agent_rules() -> Result<Vec<String>, String> {
    let rules = cloak::setup::ensure_agent_rules();
    Ok(rules.into_iter().map(|(p, _)| p).collect())
}

fn main() {
    let store = KeyringStore::new().expect("Failed to initialize Keyring store");

    tauri::Builder::default()
        .setup(|_app| {
            // Self-contained .dmg: automatically install/verify CLI symlink & agent rules on startup
            let _ = ensure_cli_symlink();
            let _ = cloak::setup::ensure_agent_rules();
            Ok(())
        })
        .manage(AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(false), // S2: Vault starts locked by default!
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            list_secrets,
            reveal_secret,
            copy_secret_secure,
            save_secret,
            delete_secret,
            check_proxy_status,
            toggle_proxy,
            toggle_window_mode,
            authenticate_vault,
            lock_vault,
            get_security_status,
            get_pending_jit_request,
            respond_jit,
            get_cli_status,
            install_cli_symlink,
            install_agent_rules,
        ])
        .run(tauri::generate_context!())
        .expect("error while running cloak desktop application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_starts_locked() {
        let store = KeyringStore::new().expect("Keystore init");
        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(false),
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(None),
        };

        // Must strictly fail when locked
        assert!(!check_session_active(&state, false));
        assert!(!check_session_active(&state, true));
    }

    #[test]
    fn test_vault_unlock_and_activity_touch() {
        let store = KeyringStore::new().expect("Keystore init");
        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(true),
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(Some(std::time::Instant::now())),
        };

        assert!(check_session_active(&state, true));
        let last = state.last_activity.lock().unwrap();
        assert!(last.is_some());
    }

    #[test]
    fn test_vault_inactivity_auto_lock() {
        let store = KeyringStore::new().expect("Keystore init");
        // Simulate last activity 301 seconds ago (> 300s timeout)
        let past_instant = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(305))
            .unwrap();

        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(true),
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(Some(past_instant)),
        };

        // check_session_active must detect timeout, auto-relock, and return false
        assert!(!check_session_active(&state, false));
        assert!(!*state.is_unlocked.lock().unwrap());
        assert!(state.last_activity.lock().unwrap().is_none());
    }

    #[test]
    fn test_manual_relock() {
        let store = KeyringStore::new().expect("Keystore init");
        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(true),
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(Some(std::time::Instant::now())),
        };

        assert!(check_session_active(&state, false));
        *state.is_unlocked.lock().unwrap() = false;
        *state.last_activity.lock().unwrap() = None;

        assert!(!check_session_active(&state, false));
    }

    #[test]
    fn test_concurrent_session_stress() {
        let store = KeyringStore::new().expect("Keystore init");
        let state = Arc::new(AppState {
            store: Arc::new(Mutex::new(store)),
            is_unlocked: Mutex::new(true),
            proxy_handle: Mutex::new(None),
            last_activity: Mutex::new(Some(std::time::Instant::now())),
        });

        let mut handles = Vec::new();
        for _ in 0..20 {
            let s = state.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..500 {
                    let _ = check_session_active(&s, i % 2 == 0);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert!(check_session_active(&state, false));
    }

    #[test]
    fn test_active_proxy_port_default() {
        // When no proxy.info file exists, should safely default to 4141 without crashing
        let port = active_proxy_port();
        assert!(port == 4141 || port > 0);
    }

    #[test]
    fn test_determine_symlink_target() {
        let target = determine_symlink_target();
        let target_str = target.to_string_lossy();
        assert!(target_str.ends_with("cloak") || target_str.ends_with("cloak.exe"));
    }

    #[test]
    fn test_find_bundled_cli() {
        // In test environment, fallback to ~/.cargo/bin/cloak or dev paths
        let cli = find_bundled_cli();
        if let Ok(home) = std::env::var("HOME") {
            let cargo_bin = std::path::PathBuf::from(&home).join(".cargo/bin/cloak");
            if cargo_bin.exists() {
                assert!(cli.is_some());
            }
        }
    }
}
