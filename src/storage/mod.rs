//! Storage abstractions for secret vaults.

use anyhow::Result;
use std::collections::HashMap;

pub mod file_store;
pub mod keyring_store;

/// Core trait implemented by storage backends (OS Keyring, Encrypted File).
pub trait SecretStore: Send + Sync {
    /// Stores or updates a secret key-value pair under the specified namespace.
    fn set(&self, namespace: &str, key: &str, value: &str) -> Result<()>;

    /// Retrieves a secret value for a given key under the specified namespace.
    fn get(&self, namespace: &str, key: &str) -> Result<Option<String>>;

    /// Lists all secret key names registered under the specified namespace.
    fn list(&self, namespace: &str) -> Result<Vec<String>>;

    /// Deletes a secret for a given key under the specified namespace.
    fn delete(&self, namespace: &str, key: &str) -> Result<()>;

    /// Lists all known namespaces.
    fn list_namespaces(&self) -> Result<Vec<String>>;

    /// Retrieves all key-value secrets under the specified namespace.
    fn get_all(&self, namespace: &str) -> Result<HashMap<String, String>> {
        let keys = self.list(namespace)?;
        let mut map = HashMap::new();
        for k in keys {
            if let Some(val) = self.get(namespace, &k)? {
                map.insert(k, val);
            }
        }
        Ok(map)
    }

    /// Merges global secrets with project-level secrets.
    /// Project secrets take precedence over global secrets on key collisions.
    fn get_merged(&self, global_ns: &str, project_ns: Option<&str>) -> Result<HashMap<String, String>> {
        let mut merged = self.get_all(global_ns)?;
        if let Some(p_ns) = project_ns {
            let project_secrets = self.get_all(p_ns)?;
            for (k, v) in project_secrets {
                merged.insert(k, v);
            }
        }
        Ok(merged)
    }
}
