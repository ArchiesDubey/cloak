use std::path::PathBuf;

pub const CLOAK_AGENT_RULE: &str = r#"# Cloak Secrets & Tool Integration

When any command, script, tool, or task requires an API key, credential, or secret token (e.g. OpenAI, Anthropic, Pixabay, Pexels, ElevenLabs, GitHub, Stripe, AWS):

1. **Never ask the user to manually export variables or edit `.env` files.**
2. **Always check Cloak first**:
   - List available secrets: `cloak list`
   - Retrieve a secret value: `cloak get <KEY_NAME> --reveal`
   - Run commands with in-memory secret injection: `cloak run -- <command>` (or with least-privilege: `cloak run --keys <KEY_NAME> -- <command>`).
3. **Just-In-Time (JIT) Auto-Prompt**:
   - If a key is not yet stored, running `cloak get <KEY_NAME> --reveal` automatically triggers Cloak's Just-In-Time (JIT) prompt in the Cloak Desktop GUI HUD or terminal.
4. **Outbound HTTPS / AI Model Proxy**:
   - When launching agents or processes that make outbound HTTPS calls, use `cloak run --proxy -- <command>` to route through Cloak's local interceptor gateway.
"#;

pub const CLOAK_CURSOR_MDC: &str = r#"---
description: Cloak Secrets & Tool Integration
globs: *
alwaysApply: true
---

# Cloak Secrets & Tool Integration

When any command, script, tool, or task requires an API key, credential, or secret token (e.g. OpenAI, Anthropic, Pixabay, Pexels, ElevenLabs, GitHub, Stripe, AWS):

1. **Never ask the user to manually export variables or edit `.env` files.**
2. **Always check Cloak first**:
   - List available secrets: `cloak list`
   - Retrieve a secret value: `cloak get <KEY_NAME> --reveal`
   - Run commands with in-memory secret injection: `cloak run -- <command>` (or with least-privilege: `cloak run --keys <KEY_NAME> -- <command>`).
3. **Just-In-Time (JIT) Auto-Prompt**:
   - If a key is not yet stored, running `cloak get <KEY_NAME> --reveal` automatically triggers Cloak's Just-In-Time (JIT) prompt in the Cloak Desktop GUI HUD or terminal.
4. **Outbound HTTPS / AI Model Proxy**:
   - When launching agents or processes that make outbound HTTPS calls, use `cloak run --proxy -- <command>` to route through Cloak's local interceptor gateway.
"#;

/// Configures or updates Cloak integration rules across all supported LLM agents
/// Returns a vector of tuples: (file_path, was_created_or_appended)
pub fn ensure_agent_rules() -> Vec<(String, bool)> {
    let mut results = Vec::new();
    let home = match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(h) => PathBuf::from(h),
        Err(_) => return results,
    };

    let targets: Vec<(PathBuf, &str)> = vec![
        (home.join(".gemini/GEMINI.md"), CLOAK_AGENT_RULE),
        (home.join(".claude/CLAUDE.md"), CLOAK_AGENT_RULE),
        (home.join(".cursorrules"), CLOAK_AGENT_RULE),
        (home.join(".cursor/rules/cloak.mdc"), CLOAK_CURSOR_MDC),
        (home.join(".windsurfrules"), CLOAK_AGENT_RULE),
        (home.join(".codex/CODEX.md"), CLOAK_AGENT_RULE),
        (home.join(".copilot/instructions.md"), CLOAK_AGENT_RULE),
        (home.join(".agents/rules/cloak.md"), CLOAK_AGENT_RULE),
    ];

    for (path, content) in targets {
        let path_str = path.to_string_lossy().to_string();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if path.exists() {
            if let Ok(existing) = std::fs::read_to_string(&path) {
                if !existing.contains("Cloak Secrets & Tool Integration") {
                    let updated = format!("{}\n\n{}", existing.trim_end(), content);
                    if std::fs::write(&path, updated).is_ok() {
                        results.push((path_str, true));
                    }
                } else {
                    results.push((path_str, false));
                }
            }
        } else {
            if std::fs::write(&path, content).is_ok() {
                results.push((path_str, true));
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_content_sanity() {
        assert!(CLOAK_AGENT_RULE.contains("Always check Cloak first"));
        assert!(CLOAK_CURSOR_MDC.contains("alwaysApply: true"));
    }
}
