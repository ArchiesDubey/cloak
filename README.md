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

---

## Installation & Setup

### Prerequisites
- **Rust Toolchain**: `cargo` & `rustc` (1.78+)
- **Node.js & pnpm**: Node 18+ and `pnpm` 9+ (strictly used for frontend)
- **Platform Dependencies**:
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Linux**: `sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libssl-dev libsecret-1-dev`
  - **Windows**: Microsoft C++ Build Tools & WebView2 (included in Windows 10/11)

### 1. Build CLI & Install Globally:
```bash
cargo build --release
cp ./target/release/cloak ~/.cargo/bin/
```

### 2. Desktop GUI Setup:
```bash
cd gui
pnpm install
pnpm run build
```

---

## Running the Desktop App

You have two ways to run the Cloak Desktop GUI:

### Option A: Direct Launch (Pre-compiled Native App)
```bash
# Launch via CLI command
cloak gui

# Or launch the native binary directly from terminal
cloak-gui

# Or open the packaged macOS application
open gui/src-tauri/target/release/bundle/macos/Cloak.app
```

### Option B: Development Mode (Live Hot-Reloading)
Inside `gui/`:
```bash
pnpm tauri dev
```
This runs the Vite dev server with fast hot-reloading and mounts the Tauri native desktop window.

### Desktop HUD Features & Keyboard Shortcuts:
- **`⌘E`**: Instant toggle between 420px compact HUD popover and full workstation window.
- **`⌘N`**: Open modal to store a new credential into Apple Keychain / Hardware Enclave.
- **`⌘K`**: Focus fuzzy search across all secret keys and project scopes.
- **`COPY` Button**: One-click tactile copy with a 30-second progress bar before memory-safe auto-wipe.
- **`EYE` Button**: Decrypt and reveal secret in-place via Touch ID / hardware credentials.

---

## How to Distribute (Packaging & Installers)

Cloak compiles to lightweight, native executables (**~3.9MB DMG** compared to 150MB+ Electron apps).

### 1. Local Installer Generation
To build the distribution bundles on your current operating system:
```bash
cd gui
pnpm tauri build
```

The output bundles will be generated in `gui/src-tauri/target/release/bundle/`:
- **macOS**:
  - `.dmg` installer: `gui/src-tauri/target/release/bundle/dmg/Cloak_0.1.0_aarch64.dmg`
  - `.app` bundle: `gui/src-tauri/target/release/bundle/macos/Cloak.app`
- **Windows**:
  - `.msi` Windows installer & `.exe` setup package
- **Linux**:
  - `.deb` package (Debian/Ubuntu) & `.AppImage` (Universal Linux)

### 2. Multi-Platform Automated CI/CD (GitHub Actions)
A complete multi-platform release pipeline is pre-configured in [`.github/workflows/release.yml`](.github/workflows/release.yml).

Whenever you push a Git release tag:
```bash
git tag v0.1.0
git push origin v0.1.0
```
GitHub Actions will automatically matrix-build:
- Apple Silicon (`aarch64-apple-darwin`) `.dmg`
- Intel Mac (`x86_64-apple-darwin`) `.dmg`
- Linux (`x86_64-unknown-linux-gnu`) `.deb` & `.AppImage`
- Windows (`x86_64-pc-windows-msvc`) `.msi` & `.exe`

And publish all signed binary installers directly to your repository's GitHub Releases page.

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

### 7. Local AI Loopback Proxy (`cloak proxy`)
Solve mid-session key requests from AI coding agents (Claude Code, Aider, Cursor) without restarting sessions:

```bash
# Start the proxy (binds to loopback 127.0.0.1:4141)
cloak proxy
```

Then point your AI tools or terminal environment to it:
```bash
export OPENAI_BASE_URL="http://127.0.0.1:4141/v1"
export ANTHROPIC_BASE_URL="http://127.0.0.1:4141"
```

**What happens when a key is missing midway?**
The proxy **pauses the HTTP request** without dropping the socket, prompts you securely on your terminal:
```text
┌─────────────────────────────────────────────────────────────┐
│ [CLOAK JIT PROXY] ⏸ Request Paused: Key Missing            │
├─────────────────────────────────────────────────────────────┤
│ An AI tool or agent is requesting access to 'OPENAI_API_KEY'│
│ Enter value below to authorize & continue without restart:  │
└─────────────────────────────────────────────────────────────┘
```
Once entered, it saves the key to Cloak and immediately resumes the request!

### 8. Headless / Server / CI Mode (`--store file`)
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
