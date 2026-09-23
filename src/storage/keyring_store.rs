//! OS-native Keyring storage backend (macOS Keychain, Windows Credential Manager, Linux Secret Service).

use super::SecretStore;
use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use zeroize::Zeroizing;

const APP_NAME: &str = "cloak";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct KeyInfo {
    #[serde(default)]
    pub hardware_protected: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct KeyringMetadata {
    namespaces: HashMap<String, HashMap<String, KeyInfo>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NamespacesData {
    Legacy(HashMap<String, HashSet<String>>),
    V2(HashMap<String, HashMap<String, KeyInfo>>),
}

#[derive(Deserialize)]
struct RawKeyringMetadata {
    namespaces: NamespacesData,
}

pub struct KeyringStore {
    metadata_path: PathBuf,
}

impl KeyringStore {
    pub fn new() -> Result<Self> {
        let base_dir = dirs_fallback()?;
        fs::create_dir_all(&base_dir)
            .with_context(|| format!("Failed to create config directory: {:?}", base_dir))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700));
        }

        let metadata_path = base_dir.join("metadata.json");
        Ok(Self { metadata_path })
    }

    fn service_name(namespace: &str) -> String {
        format!("{}-{}", APP_NAME, namespace)
    }

    fn load_metadata_unlocked(&self) -> KeyringMetadata {
        if let Ok(data) = fs::read_to_string(&self.metadata_path) {
            if let Ok(raw) = serde_json::from_str::<RawKeyringMetadata>(&data) {
                match raw.namespaces {
                    NamespacesData::V2(ns) => return KeyringMetadata { namespaces: ns },
                    NamespacesData::Legacy(legacy) => {
                        let mut converted = HashMap::new();
                        for (ns, keys) in legacy {
                            let mut map = HashMap::new();
                            for k in keys {
                                map.insert(
                                    k,
                                    KeyInfo {
                                        hardware_protected: false,
                                    },
                                );
                            }
                            converted.insert(ns, map);
                        }
                        return KeyringMetadata {
                            namespaces: converted,
                        };
                    }
                }
            }
        }
        KeyringMetadata::default()
    }

    fn save_metadata_unlocked(&self, meta: &KeyringMetadata) -> Result<()> {
        let data = serde_json::to_string_pretty(meta)?;
        if let Some(parent) = self.metadata_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let rand_suffix: u64 = rand::random();
        let tmp_path = format!(
            "{}.tmp.{}.{}",
            self.metadata_path.display(),
            std::process::id(),
            rand_suffix
        );
        fs::write(&tmp_path, data)
            .with_context(|| format!("Failed to write metadata tmpfile at {tmp_path}"))?;
        fs::rename(&tmp_path, &self.metadata_path).with_context(|| {
            format!(
                "Failed to rename metadata file from {tmp_path} to {}",
                self.metadata_path.display()
            )
        })?;
        Ok(())
    }

    fn update_metadata<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut KeyringMetadata),
    {
        static META_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = META_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut meta = self.load_metadata_unlocked();
        f(&mut meta);
        self.save_metadata_unlocked(&meta)
    }

    fn load_metadata(&self) -> KeyringMetadata {
        static META_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = META_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        self.load_metadata_unlocked()
    }
}

impl SecretStore for KeyringStore {
    fn is_hardware_protected(&self, namespace: &str, key: &str) -> bool {
        let meta = self.load_metadata();
        meta.namespaces
            .get(namespace)
            .and_then(|keys| keys.get(key))
            .map(|info| info.hardware_protected)
            .unwrap_or(false)
    }

    fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        let service = Self::service_name(namespace);
        let entry = Entry::new(&service, key).with_context(|| {
            format!("Failed to initialize keyring entry for service: {service}, key: {key}")
        })?;

        if entry.set_password(value).is_err() {
            let _ = entry.delete_credential();
            entry
                .set_password(value)
                .with_context(|| format!("Failed to write secret to OS keyring for key: {key}"))?;
        }

        // Update metadata index
        self.update_metadata(|meta| {
            meta.namespaces
                .entry(namespace.to_string())
                .or_default()
                .insert(
                    key.to_string(),
                    KeyInfo {
                        hardware_protected: false,
                    },
                );
        })?;

        Ok(())
    }

    fn set_secure(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        require_hardware_protection: bool,
    ) -> Result<()> {
        let service = Self::service_name(namespace);

        #[cfg(target_os = "macos")]
        if require_hardware_protection {
            use security_framework::access_control::SecAccessControl;
            use security_framework::passwords::{set_generic_password_options, PasswordOptions};
            use security_framework::passwords_options::AccessControlOptions;

            if let Ok(entry) = Entry::new(&service, key) {
                let _ = entry.delete_credential();
            }

            let mut options = PasswordOptions::new_generic_password(&service, key);
            // Gating access behind Touch ID biometrics and user presence
            let ac_result =
                SecAccessControl::create_with_flags(AccessControlOptions::USER_PRESENCE.bits());
            let hardware_applied = match ac_result {
                Ok(ac) => {
                    options.set_access_control(ac);
                    match set_generic_password_options(value.as_bytes(), options) {
                        Ok(()) => true,
                        Err(e) => {
                            eprintln!("[Cloak] Hardware ACL set failed ({e}). Storing in standard OS Keyring.");
                            self.set(namespace, key, value)?;
                            false
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[Cloak] SecAccessControl creation failed ({e}). Storing in standard OS Keyring.");
                    self.set(namespace, key, value)?;
                    false
                }
            };

            // Update metadata index
            self.update_metadata(|meta| {
                meta.namespaces
                    .entry(namespace.to_string())
                    .or_default()
                    .insert(
                        key.to_string(),
                        KeyInfo {
                            hardware_protected: hardware_applied,
                        },
                    );
            })?;

            return Ok(());
        }

        self.set(namespace, key, value)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<String>>> {
        let service = Self::service_name(namespace);
        let entry = Entry::new(&service, key).with_context(|| {
            format!("Failed to initialize keyring entry for service: {service}, key: {key}")
        })?;

        match entry.get_password() {
            Ok(pass) => Ok(Some(Zeroizing::new(pass))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Keyring retrieval failed: {e}")),
        }
    }

    fn list(&self, namespace: &str) -> Result<Vec<String>> {
        let meta = self.load_metadata();
        if let Some(keys) = meta.namespaces.get(namespace) {
            let mut list: Vec<String> = keys.keys().cloned().collect();
            list.sort();
            Ok(list)
        } else {
            Ok(Vec::new())
        }
    }

    fn list_namespaces(&self) -> Result<Vec<String>> {
        let meta = self.load_metadata();
        let mut namespaces: Vec<String> = meta.namespaces.keys().cloned().collect();
        namespaces.sort();
        Ok(namespaces)
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let service = Self::service_name(namespace);
        let entry = Entry::new(&service, key).with_context(|| {
            format!("Failed to initialize keyring entry for service: {service}, key: {key}")
        })?;

        // Ignore error if entry doesn't exist in keyring
        match entry.delete_credential() {
            Ok(_) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to delete from keyring: {e}")),
        }

        // Remove from metadata index
        self.update_metadata(|meta| {
            if let Some(keys) = meta.namespaces.get_mut(namespace) {
                keys.remove(key);
            }
        })?;

        Ok(())
    }

    fn get_all(&self, namespace: &str) -> Result<HashMap<String, Zeroizing<String>>> {
        #[cfg(target_os = "macos")]
        {
            use core_foundation::base::TCFType;
            use core_foundation::data::CFData;
            use core_foundation::string::CFString;
            use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
            use security_framework_sys::item::{kSecAttrAccount, kSecValueData};

            let service = Self::service_name(namespace);
            let results = ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(&service)
                .load_attributes(true)
                .load_data(true)
                .limit(security_framework::item::Limit::All)
                .search();

            if let Ok(items) = results {
                let mut map = HashMap::new();
                for item in items {
                    if let SearchResult::Dict(d) = item {
                        unsafe {
                            let key = d
                                .find(kSecAttrAccount as *const std::ffi::c_void)
                                .map(|p| CFString::wrap_under_get_rule(*p as _).to_string());
                            let val = d.find(kSecValueData as *const std::ffi::c_void).map(|p| {
                                let cf_data = CFData::wrap_under_get_rule(*p as _);
                                let s = String::from_utf8_lossy(cf_data.bytes()).to_string();
                                Zeroizing::new(s)
                            });

                            if let (Some(k), Some(v)) = (key, val) {
                                map.insert(k, v);
                            }
                        }
                    }
                }
                if let Ok(keys) = self.list(namespace) {
                    for k in keys {
                        if let std::collections::hash_map::Entry::Vacant(e) = map.entry(k.clone()) {
                            if let Ok(Some(val)) = self.get(namespace, &k) {
                                e.insert(val);
                            }
                        }
                    }
                }
                return Ok(map);
            }
        }

        // Fallback for non-macOS or if batch query returns an error
        let keys = self.list(namespace)?;
        let mut map = HashMap::new();
        for k in keys {
            if let Some(val) = self.get(namespace, &k)? {
                map.insert(k, val);
            }
        }
        Ok(map)
    }
}

fn dirs_fallback() -> Result<PathBuf> {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "cloak", "cloak") {
        Ok(proj_dirs.config_dir().to_path_buf())
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Ok(PathBuf::from(home).join(".config").join("cloak"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_store() {
        let store = KeyringStore::new().unwrap();
        let key = "CLOAK_UNITTEST_KEY";
        let val = "unittest_secret_999";

        // Set
        store.set("test-ns", key, val).unwrap();

        // Get
        let fetched = store.get("test-ns", key).unwrap();
        assert_eq!(fetched.as_deref().map(|s| s.as_str()), Some(val));

        // List
        let list = store.list("test-ns").unwrap();
        assert!(list.contains(&key.to_string()));

        // Delete
        store.delete("test-ns", key).unwrap();
        assert_eq!(store.get("test-ns", key).unwrap(), None);
    }

    #[test]
    fn test_keyring_store_get_all() {
        let store = KeyringStore::new().unwrap();
        let ns = "test-batch-ns";
        store.set(ns, "BATCH_K1", "val1").unwrap();
        store.set(ns, "BATCH_K2", "val2").unwrap();

        let all = store.get_all(ns).unwrap();
        assert_eq!(all.get("BATCH_K1").map(|s| s.as_str()), Some("val1"));
        assert_eq!(all.get("BATCH_K2").map(|s| s.as_str()), Some("val2"));

        store.delete(ns, "BATCH_K1").unwrap();
        store.delete(ns, "BATCH_K2").unwrap();
    }

    #[test]
    fn test_keyring_store_set_secure() {
        let store = KeyringStore::new().unwrap();
        let ns = "test-sec-ns";
        let key = "SEC_K1";
        let val = "sec_val_1";

        store.set_secure(ns, key, val, true).unwrap();
        let fetched = store.get(ns, key).unwrap();
        assert_eq!(fetched.as_deref().map(|s| s.as_str()), Some(val));
        store.delete(ns, key).unwrap();
    }
}
