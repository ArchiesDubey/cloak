//! Child process execution and in-memory environment variable injection.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::{Command, Stdio};

/// Executes a target command with secrets injected into the child process environment.
///
/// Security characteristics:
/// 1. Secrets are passed directly to the child process's environment block in memory.
/// 2. Secrets are NEVER passed as command-line arguments (preventing visibility in `ps aux`, `pgrep`, `/proc`).
/// 3. Parent shell environment remains unmodified.
pub fn run_with_secrets(
    secrets: &HashMap<String, String>,
    cmd_name: &str,
    cmd_args: &[String],
) -> Result<i32> {
    let mut cmd = Command::new(cmd_name);
    cmd.args(cmd_args);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Inject secrets into the child process's environment
    for (k, v) in secrets {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn child process: {}", cmd_name))?;

    let status = child
        .wait()
        .with_context(|| format!("Error while waiting for child process: {}", cmd_name))?;

    let exit_code = status.code().unwrap_or(if status.success() { 0 } else { 1 });
    Ok(exit_code)
}
