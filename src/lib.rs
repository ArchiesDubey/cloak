//! Cloak Core Library: Cryptography, Keyrings, Project Scoping, and AI Loopback Proxy.

pub mod crypto;
pub mod project;
pub mod proxy;
pub mod runner;
pub mod security;
pub mod setup;
pub mod storage;

pub use project::GLOBAL_NAMESPACE;
pub use storage::file_store::FileStore;
pub use storage::keyring_store::KeyringStore;
pub use storage::SecretStore;
