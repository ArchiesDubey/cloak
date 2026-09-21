# Cloak

**Local-First, Cross-Platform Developer Secrets Manager & Child Process Injector**

Cloak is designed to eliminate plaintext `.env` files and avoid cloud-vendor lock-in. It stores secrets securely in your OS-native hardware credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service) and injects them directly into child process memory on demand.

---

## Key Features

- **Local-First & Zero Plaintext**: No `.env` files sitting on disk or getting accidentally committed to Git.
- **Hardware & OS-Native Keyrings**:
  - **macOS**: Apple Keychain Services (`Security.framework`) backed by Secure Enclave / Touch ID.
  - **Windows**: Windows Credential Manager / DPAPI (`CryptProtectData`).
  - **Linux**: FreeDesktop Secret Service API (GNOME Keyring / KWallet via D-Bus).
- **Headless Fallback**: Standalone encrypted vault file (`--store file`) using **Argon2id** (OWASP/NIST parameters) and **XChaCha20-Poly1305 AEAD** for remote Linux servers and CI/CD pipelines.
- **Process Memory Isolation**: Secrets are passed strictly to the child process's environment block in memory (`cloak run -- <cmd>`). Secrets are **never** passed via CLI arguments (protecting against `ps aux` and `/proc/<pid>/cmdline` snooping) and never leak to the parent shell.
- **Screen Leak Prevention**: `cloak get <KEY>` automatically masks credentials (`sk-p****9999`) unless explicitly run with `--reveal`.
- **Memory Hardening**: `ZeroizeOnDrop` memory wiping on deallocation and disabled core dumps (`RLIMIT_CORE = 0`) to prevent secrets leaking in crash dumps.

---

## Installation & Build

### Build from source:
```bash
cargo build --release
```

The compiled binary will be located at `./target/release/cloak`.

To install it system-wide to your PATH:
```bash
cp ./target/release/cloak /usr/local/bin/
```

---

## CLI Usage

### 1. Store a Secret
```bash
# Provide value directly:
cloak set OPENAI_API_KEY sk-proj-123456789

# Or omit the value to be prompted with secure, masked stdin (no terminal echo):
cloak set AWS_SECRET_ACCESS_KEY
```

### 2. Run Any CLI Tool with Injected Secrets
Secrets are fetched on demand and passed exclusively to the child process:
```bash
# Run a Python script or CLI command:
cloak run -- python main.py

# Run a curl command:
cloak run -- curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Open an interactive subshell with all secrets loaded:
cloak run -- $SHELL
```

### 3. Retrieve or Inspect Secrets
```bash
# Masked display (safe against shoulder surfing & screen sharing):
cloak get OPENAI_API_KEY
# Output: sk-p****6789 (use --reveal to display in full)

# Reveal full value:
cloak get OPENAI_API_KEY --reveal

# List all stored keys (values are never displayed):
cloak list
```

### 4. Delete a Secret
```bash
cloak delete OPENAI_API_KEY
```

### 5. Namespaces (Environments)
Organize keys across different projects or environments:
```bash
# Save to 'staging' namespace:
cloak set -n staging DATABASE_URL "postgres://staging-db:5432"

# Run within 'staging' namespace:
cloak run -n staging -- npm start
```

### 6. Export for Shell Tooling
```bash
# Standard dotenv format:
cloak export --format dotenv

# Shell export statements (for `eval $(cloak export --format bash)`):
cloak export --format bash

# JSON format:
cloak export --format json
```

### 7. Headless / Server / CI Mode (`--store file`)
When running on headless Linux servers or Docker containers without a desktop keyring:
```bash
export CLOAK_MASTER_KEY="your-secure-passphrase"
cloak --store file set PROD_API_KEY "secret_key"
cloak --store file run -- ./deploy.sh
```

---

## Running the Automated Test Suite

```bash
cargo test
```

Verifies:
- Argon2id key derivation & CSPRNG salt generation
- XChaCha20-Poly1305 authenticated encryption & tampering detection
- OS Keyring lifecycle (`set`, `get`, `list`, `delete`)
- Standalone encrypted file vault persistence & wrong-key rejection
