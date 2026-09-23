//! Standalone encrypted file vault backend (Argon2id + XChaCha20-Poly1305).
//! Ideal for headless Linux servers, Docker containers, and CI/CD pipelines.

use super::SecretStore;
use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    // namespace -> (key -> value)
    namespaces: HashMap<String, HashMap<String, String>>,
}

pub struct FileStore {
    path: PathBuf,
    master_key: Zeroizing<[u8; KEY_LEN]>,
}

impl FileStore {
    pub fn new(path: PathBuf, passphrase: &[u8]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create vault directory: {:?}", parent))?;
        }

        // If file already exists, read salt and derive key
        let master_key = if path.exists() {
            let content = fs::read(&path)
                .with_context(|| format!("Failed to read vault file at {:?}", path))?;
            let vault_file: VaultFile = serde_json::from_slice(&content)
                .with_context(|| "Corrupted vault file structure")?;
            crypto::derive_key(passphrase, &vault_file.salt)?
        } else {
            // New vault: generate new salt and derive key
            let salt = crypto::generate_salt();
            let key = crypto::derive_key(passphrase, &salt)?;
            // Initialize empty vault
            let initial_data = VaultData::default();
            let raw_json = serde_json::to_vec(&initial_data)?;
            let (nonce, ciphertext) = crypto::encrypt_bytes(&key, &raw_json)?;
            let vault_file = VaultFile {
                salt,
                nonce,
                ciphertext,
            };
            let serialized = serde_json::to_vec_pretty(&vault_file)?;
            fs::write(&path, serialized)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }

            key
        };

        Ok(Self { path, master_key })
    }

    fn load_data(&self) -> Result<VaultData> {
        if !self.path.exists() {
            return Ok(VaultData::default());
        }

        let content = fs::read(&self.path)?;
        let vault_file: VaultFile = serde_json::from_slice(&content)
            .map_err(|e| anyhow!("Failed to deserialize vault: {e}"))?;

        let decrypted =
            crypto::decrypt_bytes(&self.master_key, &vault_file.nonce, &vault_file.ciphertext)?;

        let data: VaultData = serde_json::from_slice(&decrypted)
            .map_err(|e| anyhow!("Corrupted decrypted vault payload: {e}"))?;

        Ok(data)
    }

    fn save_data(&self, data: &VaultData) -> Result<()> {
        let raw_json = serde_json::to_vec(data)?;
        let (nonce, ciphertext) = crypto::encrypt_bytes(&self.master_key, &raw_json)?;

        // Re-read salt
        let current_salt = if self.path.exists() {
            let content = fs::read(&self.path)?;
            let vf: VaultFile = serde_json::from_slice(&content)?;
            vf.salt
        } else {
            crypto::generate_salt()
        };

        let vf = VaultFile {
            salt: current_salt,
            nonce,
            ciphertext,
        };

        let serialized = serde_json::to_vec_pretty(&vf)?;
        let tmp_path = format!("{}.tmp.{}", self.path.display(), std::process::id());
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }

            f.write_all(&serialized)?;
            f.sync_all()?;
        }

        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

impl SecretStore for FileStore {
    fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()> {
        let mut data = self.load_data()?;
        data.namespaces
            .entry(namespace.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
        self.save_data(&data)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<String>>> {
        let data = self.load_data()?;
        Ok(data
            .namespaces
            .get(namespace)
            .and_then(|ns| ns.get(key).cloned())
            .map(Zeroizing::new))
    }

    fn get_all(&self, namespace: &str) -> Result<HashMap<String, Zeroizing<String>>> {
        let data = self.load_data()?;
        let mut result = HashMap::new();
        if let Some(ns) = data.namespaces.get(namespace) {
            for (k, v) in ns {
                result.insert(k.clone(), Zeroizing::new(v.clone()));
            }
        }
        Ok(result)
    }

    fn list(&self, namespace: &str) -> Result<Vec<String>> {
        let data = self.load_data()?;
        if let Some(ns) = data.namespaces.get(namespace) {
            let mut keys: Vec<String> = ns.keys().cloned().collect();
            keys.sort();
            Ok(keys)
        } else {
            Ok(Vec::new())
        }
    }

    fn list_namespaces(&self) -> Result<Vec<String>> {
        let data = self.load_data()?;
        let mut namespaces: Vec<String> = data.namespaces.keys().cloned().collect();
        namespaces.sort();
        Ok(namespaces)
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let mut data = self.load_data()?;
        if let Some(ns) = data.namespaces.get_mut(namespace) {
            ns.remove(key);
        }
        self.save_data(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_store_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("cloak_test_{}", rand::random::<u64>()));
        let vault_path = temp_dir.join("vault.enc");
        let password = b"passphrase-secret";

        let store = FileStore::new(vault_path.clone(), password).unwrap();
        store.set("default", "API_KEY", "sk-12345").unwrap();
        store
            .set("default", "DB_URL", "postgres://localhost")
            .unwrap();

        assert_eq!(
            store
                .get("default", "API_KEY")
                .unwrap()
                .as_deref()
                .map(|s| s.as_str()),
            Some("sk-12345")
        );

        let list = store.list("default").unwrap();
        assert_eq!(list, vec!["API_KEY", "DB_URL"]);

        // Re-open with same password
        let store2 = FileStore::new(vault_path.clone(), password).unwrap();
        assert_eq!(
            store2
                .get("default", "API_KEY")
                .unwrap()
                .as_deref()
                .map(|s| s.as_str()),
            Some("sk-12345")
        );

        // Re-open with wrong password should fail to read
        let store_bad = FileStore::new(vault_path.clone(), b"wrong-pass").unwrap();
        assert!(store_bad.get("default", "API_KEY").is_err());

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }
}
