//! OS-native Keyring storage backend (macOS Keychain, Windows Credential Manager, Linux Secret Service).

use super::SecretStore;
use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

const APP_NAME: &str = "cloak";

#[derive(Serialize, Deserialize, Default)]
struct KeyringMetadata {
    namespaces: HashMap<String, HashSet<String>>,
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

    fn load_metadata(&self) -> KeyringMetadata {
        if let Ok(data) = fs::read_to_string(&self.metadata_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            KeyringMetadata::default()
        }
    }

    fn save_metadata(&self, meta: &KeyringMetadata) -> Result<()> {
        let data = serde_json::to_string_pretty(meta)?;
        fs::write(&self.metadata_path, data)
            .with_context(|| format!("Failed to save metadata to {:?}", self.metadata_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.metadata_path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }
}

impl SecretStore for KeyringStore {
    fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        let service = Self::service_name(namespace);
        let entry = Entry::new(&service, key)
            .with_context(|| format!("Failed to initialize keyring entry for service: {service}, key: {key}"))?;
        
        entry.set_password(value)
            .with_context(|| format!("Failed to write secret to OS keyring for key: {key}"))?;

        // Update metadata index
        let mut meta = self.load_metadata();
        meta.namespaces
            .entry(namespace.to_string())
            .or_default()
            .insert(key.to_string());
        self.save_metadata(&meta)?;

        Ok(())
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let service = Self::service_name(namespace);
        let entry = Entry::new(&service, key)
            .with_context(|| format!("Failed to initialize keyring entry for service: {service}, key: {key}"))?;

        match entry.get_password() {
            Ok(pass) => Ok(Some(pass)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Keyring retrieval failed: {e}")),
        }
    }

    fn list(&self, namespace: &str) -> Result<Vec<String>> {
        let meta = self.load_metadata();
        if let Some(keys) = meta.namespaces.get(namespace) {
            let mut list: Vec<String> = keys.iter().cloned().collect();
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
        let entry = Entry::new(&service, key)
            .with_context(|| format!("Failed to initialize keyring entry for service: {service}, key: {key}"))?;

        // Ignore error if entry doesn't exist in keyring
        match entry.delete_credential() {
            Ok(_) | Err(keyring::Error::NoEntry) => {},
            Err(e) => return Err(anyhow::anyhow!("Failed to delete from keyring: {e}")),
        }

        // Remove from metadata index
        let mut meta = self.load_metadata();
        if let Some(keys) = meta.namespaces.get_mut(namespace) {
            keys.remove(key);
        }
        self.save_metadata(&meta)?;

        Ok(())
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
        assert_eq!(fetched, Some(val.to_string()));

        // List
        let list = store.list("test-ns").unwrap();
        assert!(list.contains(&key.to_string()));

        // Delete
        store.delete("test-ns", key).unwrap();
        assert_eq!(store.get("test-ns", key).unwrap(), None);
    }
}

