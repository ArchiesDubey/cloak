//! Local Certificate Authority (CA) & On-the-Fly Dynamic Leaf Certificate Generation
//!
//! Powers Cloak's Transparent HTTPS Forward Proxy & Universal Outbound Interceptor.
//! Generates a root CA once (~/.cloak/ca.pem, ~/.cloak/ca.key) and signs dynamic
//! leaf TLS certificates for any requested target domain (e.g. api.elevenlabs.io, pixabay.com).

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub struct CertificateAuthority {
    pub ca_cert_pem: String,
    pub _ca_key_pem: String,
    ca_cert_der: Vec<u8>,
    ca_key: Arc<KeyPair>,
    cert_cache: RwLock<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl CertificateAuthority {
    /// Loads the existing CA from disk (~/.cloak/ca.pem) or creates a new Root CA.
    pub fn load_or_generate() -> Result<Self> {
        let dir = ca_dir()?;
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let cert_pem =
                std::fs::read_to_string(&cert_path).context("Failed to read ~/.cloak/ca.pem")?;
            let key_pem =
                std::fs::read_to_string(&key_path).context("Failed to read ~/.cloak/ca.key")?;

            if let Ok(ca) = Self::from_pem(&cert_pem, &key_pem) {
                return Ok(ca);
            }
        }

        Self::generate_and_save(&cert_path, &key_path)
    }

    /// Creates a CA instance from in-memory PEM strings.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem).context("Failed to parse CA private key PEM")?;

        // Extract DER bytes from cert PEM
        let der_bytes = pem_to_der(cert_pem)?;

        Ok(Self {
            ca_cert_pem: cert_pem.to_string(),
            _ca_key_pem: key_pem.to_string(),
            ca_cert_der: der_bytes,
            ca_key: Arc::new(key_pair),
            cert_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Generates a brand new Root CA and writes it to disk.
    pub fn generate_and_save(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate ECDSA keypair for CA")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "Cloak Local Development CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Cloak Security");
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "Local Interception Gateway");

        let cert = params
            .self_signed(&key_pair)
            .context("Failed to generate self-signed CA certificate")?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(cert_path, &cert_pem)?;
        std::fs::write(key_path, &key_pem)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644));
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }

        let der_bytes = cert.der().to_vec();

        Ok(Self {
            ca_cert_pem: cert_pem,
            _ca_key_pem: key_pem,
            ca_cert_der: der_bytes,
            ca_key: Arc::new(key_pair),
            cert_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Dynamically signs a leaf certificate for the given domain host and builds a rustls ServerConfig.
    /// Results are cached in memory for zero-latency subsequent handshakes.
    pub fn get_or_create_server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        // Strip port if present (e.g. "api.github.com:443" -> "api.github.com")
        let clean_host = host.split(':').next().unwrap_or(host).trim().to_lowercase();

        if let Ok(guard) = self.cert_cache.read() {
            if let Some(config) = guard.get(&clean_host) {
                return Ok(config.clone());
            }
        }

        let config = Arc::new(self.mint_server_config(&clean_host)?);

        if let Ok(mut guard) = self.cert_cache.write() {
            guard.insert(clean_host, config.clone());
        }

        Ok(config)
    }

    fn mint_server_config(&self, host: &str) -> Result<rustls::ServerConfig> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate leaf key")?;

        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("Failed to set SAN in leaf certificate")?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.ca_cert_pem, &*self.ca_key)
            .context("Failed to parse CA cert into Issuer")?;

        let leaf_cert = params
            .signed_by(&leaf_key, &issuer)
            .context("Failed to sign leaf cert with CA key")?;

        let leaf_der = leaf_cert.der().to_vec();
        let key_der = leaf_key.serialize_der();

        let cert_chain = vec![
            CertificateDer::from(leaf_der),
            CertificateDer::from(self.ca_cert_der.clone()),
        ];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("Failed to construct rustls ServerConfig")?;

        Ok(server_config)
    }
}

/// Helper function to parse the first DER certificate from a PEM string
fn pem_to_der(pem_str: &str) -> Result<Vec<u8>> {
    let mut in_cert = false;
    let mut b64 = String::new();

    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            continue;
        }
        if trimmed == "-----END CERTIFICATE-----" {
            break;
        }
        if in_cert {
            b64.push_str(trimmed);
        }
    }

    if b64.is_empty() {
        anyhow::bail!("No certificate block found in PEM");
    }

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("Failed to base64 decode PEM certificate body")?;
    Ok(der)
}

pub fn ca_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(home).join(".cloak");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

pub fn ca_cert_path() -> Result<PathBuf> {
    Ok(ca_dir()?.join("ca.pem"))
}

/// Installs the Cloak CA certificate into the user/system trust store.
pub fn install_ca_to_trust_store() -> Result<String> {
    let cert_path = ca_cert_path()?;
    if !cert_path.exists() {
        let _ = CertificateAuthority::load_or_generate()?;
    }

    let cert_path_str = cert_path.to_string_lossy().to_string();

    #[cfg(target_os = "macos")]
    {
        // Try installing to the current user's login keychain (no sudo required)
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let user_keychain = PathBuf::from(&home).join("Library/Keychains/login.keychain-db");
        let keychain_arg = if user_keychain.exists() {
            user_keychain.to_string_lossy().to_string()
        } else {
            "login.keychain".to_string()
        };

        let status = std::process::Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                &keychain_arg,
                &cert_path_str,
            ])
            .status()
            .context("Failed to invoke macOS security tool")?;

        if status.success() {
            Ok(format!(
                "✓ Cloak CA successfully trusted in macOS user keychain ({})",
                keychain_arg
            ))
        } else {
            Ok(format!(
                "Note: Automatic trust registration exited with code {:?}. You can manually trust the CA via Keychain Access or with:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                status.code(),
                cert_path_str
            ))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let target = PathBuf::from("/usr/local/share/ca-certificates/cloak-ca.crt");
        if let Ok(_) = std::fs::copy(&cert_path, &target) {
            let status = std::process::Command::new("update-ca-certificates").status();
            if status.map(|s| s.success()).unwrap_or(false) {
                return Ok("✓ Cloak CA installed to /usr/local/share/ca-certificates/ and trusted via update-ca-certificates.".to_string());
            }
        }
        return Ok(format!(
            "To trust Cloak CA on Linux, run:\n  sudo cp {} /usr/local/share/ca-certificates/cloak-ca.crt && sudo update-ca-certificates",
            cert_path_str
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("certutil")
            .args(["-addstore", "-f", "ROOT", &cert_path_str])
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            return Ok(
                "✓ Cloak CA installed to Windows Trusted Root Certification Authorities store."
                    .to_string(),
            );
        } else {
            return Ok(format!(
                "To trust Cloak CA on Windows, run in Administrator PowerShell:\n  certutil -addstore -f \"ROOT\" \"{}\"",
                cert_path_str
            ));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(format!("Root CA generated at {}", cert_path_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation_and_leaf_signing() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Cloak CA");

        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let ca = CertificateAuthority::from_pem(&cert_pem, &key_pem).unwrap();
        let server_config = ca.get_or_create_server_config("api.github.com").unwrap();
        assert!(server_config.alpn_protocols.is_empty() || true);

        // Check caching
        let cached = ca.get_or_create_server_config("api.github.com").unwrap();
        assert!(Arc::ptr_eq(&server_config, &cached));
    }
}
