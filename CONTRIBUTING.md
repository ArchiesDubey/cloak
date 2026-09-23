# Contributing to Cloak

Thank you for your interest in contributing to Cloak! This document outlines our development workflow, coding standards, and testing procedures.

---

## Development Setup

### Prerequisites
- **Rust Toolchain**: `rustc` & `cargo` (1.78+) -> [rustup.rs](https://rustup.rs/)
- **Node.js & pnpm**: Node.js 18+ and `pnpm` 9+ -> [pnpm.io](https://pnpm.io/)
- **Platform Dependencies**:
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Linux**: `libsecret-1-dev`, `libssl-dev`, `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`
  - **Windows**: Microsoft C++ Build Tools & WebView2

### Repository Structure
```text
cloak/
├── src/               # Rust Core Library & CLI
│   ├── crypto.rs      # Argon2id + XChaCha20-Poly1305 encryption
│   ├── storage/       # OS Keyring & standalone file vault backends
│   ├── runner.rs      # Child process memory injector & least-privilege
│   ├── proxy/         # Local AI loopback proxy, HTTPS MITM & auto-inference
│   ├── setup.rs       # Multi-agent auto-configuration engine
│   └── main.rs        # CLI entry point and subcommands
├── gui/               # Minimalist Desktop HUD
│   ├── src/           # React 18 + TypeScript + Tailwind CSS UI
│   └── src-tauri/     # Tauri v2 native bridge & macOS biometrics (Objective-C)
└── tests/             # End-to-end integration verification suite
```

---

## Building Locally

### 1. Build CLI
```bash
cargo build
# or optimized release:
cargo build --release
```

### 2. Run Desktop App in Development Mode
```bash
cd gui
pnpm install
pnpm tauri dev
```

---

## Testing Guidelines

Every change must pass our three testing layers before opening a Pull Request:

### 1. Rust Unit & Integration Tests
```bash
cargo test
```

### 2. Frontend Vitest Suite
```bash
cd gui
pnpm test
```

### 3. Comprehensive End-to-End Suite
Runs 40+ end-to-end tests verifying process isolation, keyring persistence, JIT simulation, proxy interception, and binary integrity:
```bash
./tests/e2e_test.sh
```

---

## Code Quality Standards

1. **Zero Secret Leaks**:
   - Never print sensitive credentials in logs, error messages, or terminal outputs.
   - Always wrap sensitive buffers in `zeroize::Zeroizing<String>` or ensure they are deallocated promptly.
2. **Fail-Closed Security**:
   - If an authentication or integrity check fails, the operation must abort with an error rather than falling back to unauthenticated execution.
3. **Cross-Platform Compatibility**:
   - Use `#[cfg(target_os = "...")]` guards appropriately.
   - Ensure headless Linux environments work via the file store backend (`--store file`).

---

## Pull Request Process

1. Fork the repository and create a feature branch from `master`.
2. Commit your changes with clear, descriptive commit messages (following [Conventional Commits](https://www.conventionalcommits.org/)).
3. Ensure all tests (`cargo test`, `pnpm test`, `./tests/e2e_test.sh`) pass locally.
4. Open a Pull Request against the `master` branch with a summary of the rationale and testing performed.
