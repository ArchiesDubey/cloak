//! Domain Rule Registry for Outbound Target Interception & Secret Injection
//!
//! Maps target hostnames (e.g. *pixabay.com*, *api.elevenlabs.io*) to required
//! secrets and their injection strategy (HTTP header or URL query parameter).
//! Supports ~/.cloak/routes.json with built-in fallback rules.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretInjection {
    Header {
        name: String,
        prefix: Option<String>,
    },
    Query {
        param: String,
    },
}

impl SecretInjection {
    /// Parses an injection specifier, e.g.:
    /// - "header:Authorization:Bearer" -> Authorization: Bearer <val>
    /// - "header:xi-api-key" -> xi-api-key: <val>
    /// - "query:key" -> ?key=<val>
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            ["query", param] => SecretInjection::Query {
                param: param.to_string(),
            },
            ["header", name, "Bearer"] => SecretInjection::Header {
                name: name.to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            ["header", name, prefix] => SecretInjection::Header {
                name: name.to_string(),
                prefix: Some(format!("{} ", prefix)),
            },
            ["header", name] => SecretInjection::Header {
                name: name.to_string(),
                prefix: None,
            },
            _ => SecretInjection::Header {
                name: "Authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRule {
    pub pattern: String,
    pub secret: String,
    pub inject: SecretInjection,
}

impl DomainRule {
    /// Case-insensitive wildcard pattern matching against target host.
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        let pat_lower = self.pattern.to_lowercase();
        wildcard_match(&pat_lower, &host_lower)
    }
}

#[derive(Clone, Debug)]
pub struct RuleRegistry {
    pub rules: Vec<DomainRule>,
}

impl RuleRegistry {
    pub fn load_or_default() -> Self {
        if let Ok(routes_file) = routes_file_path() {
            if routes_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&routes_file) {
                    if let Ok(rules) = serde_json::from_str::<Vec<DomainRule>>(&content) {
                        return Self { rules };
                    }
                }
            }
        }

        Self::default()
    }

    pub fn match_host(&self, host: &str) -> Option<&DomainRule> {
        let clean_host = host.split(':').next().unwrap_or(host).trim();
        self.rules.iter().find(|r| r.matches(clean_host))
    }

    /// Matches an explicit rule or automatically infers a dynamic rule from the target host & vault keys.
    pub fn match_or_infer(
        &self,
        host: &str,
        available_keys: &[String],
        has_client_auth: bool,
    ) -> Option<DomainRule> {
        // 1. Explicit rule match takes precedence
        if let Some(rule) = self.match_host(host) {
            return Some(rule.clone());
        }

        let clean_host = host.split(':').next().unwrap_or(host).trim();
        let service = extract_service_name(clean_host);
        let candidates = candidate_secret_names(&service);

        // 2. Check if any candidate secret already exists in user's vault
        let matched_in_vault = candidates
            .iter()
            .find(|c| available_keys.iter().any(|k| k.eq_ignore_ascii_case(c)));

        if let Some(secret_name) = matched_in_vault {
            return Some(DomainRule {
                pattern: clean_host.to_string(),
                secret: secret_name.clone(),
                inject: default_injection_for_service(&service),
            });
        }

        // 3. If client sent an Authorization header, infer authentication is required
        // and prepare dynamic rule so proxy can JIT-prompt for <SERVICE>_API_KEY if needed.
        if has_client_auth {
            return Some(DomainRule {
                pattern: clean_host.to_string(),
                secret: format!("{}_API_KEY", service),
                inject: default_injection_for_service(&service),
            });
        }

        None
    }
}

/// Extracts the primary service identifier from a hostname, e.g.:
/// - "api.pexels.com" -> "PEXELS"
/// - "api.elevenlabs.io" -> "ELEVENLABS"
/// - "api.tavily.com" -> "TAVILY"
/// - "api.deepseek.com" -> "DEEPSEEK"
pub fn extract_service_name(host: &str) -> String {
    let clean = host.split(':').next().unwrap_or(host).trim().to_lowercase();
    let parts: Vec<&str> = clean.split('.').collect();

    // Filter out common subdomain prefixes and TLDs
    let prefixes = [
        "api", "v1", "v2", "rest", "gateway", "service", "sub", "www", "app",
    ];
    let tlds = [
        "com", "org", "net", "io", "ai", "co", "dev", "app", "sh", "me", "xyz", "uk", "us", "de",
        "fr", "jp", "eu", "in",
    ];

    let candidates: Vec<&str> = parts
        .iter()
        .filter(|p| !p.is_empty() && !prefixes.contains(p) && !tlds.contains(p))
        .copied()
        .collect();

    if let Some(name) = candidates.last() {
        name.to_uppercase()
    } else if let Some(first) = parts.first() {
        first.to_uppercase()
    } else {
        "SERVICE".to_string()
    }
}

/// Returns candidate secret variable names for a service in priority order
pub fn candidate_secret_names(service: &str) -> Vec<String> {
    vec![
        format!("{}_API_KEY", service),
        format!("{}_TOKEN", service),
        format!("{}_KEY", service),
        format!("{}_SECRET", service),
        service.to_string(),
    ]
}

/// Returns the standard secret injection strategy for a given service
pub fn default_injection_for_service(service: &str) -> SecretInjection {
    if service == "PEXELS" {
        // Pexels uses 'Authorization: <API_KEY>' without the Bearer prefix
        SecretInjection::Header {
            name: "Authorization".to_string(),
            prefix: None,
        }
    } else {
        // Standard modern API bearer auth
        SecretInjection::Header {
            name: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        }
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self {
            rules: vec![
                DomainRule {
                    pattern: "*pixabay.com*".to_string(),
                    secret: "PIXABAY_API_KEY".to_string(),
                    inject: SecretInjection::Query {
                        param: "key".to_string(),
                    },
                },
                DomainRule {
                    pattern: "*api.elevenlabs.io*".to_string(),
                    secret: "ELEVENLABS_API_KEY".to_string(),
                    inject: SecretInjection::Header {
                        name: "xi-api-key".to_string(),
                        prefix: None,
                    },
                },
                DomainRule {
                    pattern: "*api.github.com*".to_string(),
                    secret: "GITHUB_TOKEN".to_string(),
                    inject: SecretInjection::Header {
                        name: "Authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                },
                DomainRule {
                    pattern: "*api.stripe.com*".to_string(),
                    secret: "STRIPE_API_KEY".to_string(),
                    inject: SecretInjection::Header {
                        name: "Authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                },
                DomainRule {
                    pattern: "*httpbin.org*".to_string(),
                    secret: "CLOAK_TEST_KEY".to_string(),
                    inject: SecretInjection::Header {
                        name: "X-Cloak-Injected".to_string(),
                        prefix: None,
                    },
                },
            ],
        }
    }
}

pub fn routes_file_path() -> Result<PathBuf, anyhow::Error> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(PathBuf::from(home).join(".cloak").join("routes.json"))
}

/// Simple wildcard pattern matcher supporting '*'
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut current_pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            current_pos += part.len();
        } else if i == parts.len() - 1 {
            if !text[current_pos..].ends_with(part) {
                return false;
            }
        } else {
            match text[current_pos..].find(part) {
                Some(idx) => current_pos += idx + part.len(),
                None => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(wildcard_match("*pixabay.com*", "api.pixabay.com"));
        assert!(wildcard_match("*pixabay.com*", "pixabay.com"));
        assert!(wildcard_match("*pixabay.com*", "https://pixabay.com/"));
        assert!(!wildcard_match("*pixabay.com*", "example.com"));

        assert!(wildcard_match("*api.elevenlabs.io*", "api.elevenlabs.io"));
        assert!(wildcard_match("api.github.com", "api.github.com"));
        assert!(!wildcard_match("api.github.com", "api.gitlab.com"));
    }

    #[test]
    fn test_injection_parsing() {
        assert_eq!(
            SecretInjection::parse("query:key"),
            SecretInjection::Query {
                param: "key".to_string()
            }
        );
        assert_eq!(
            SecretInjection::parse("header:xi-api-key"),
            SecretInjection::Header {
                name: "xi-api-key".to_string(),
                prefix: None
            }
        );
        assert_eq!(
            SecretInjection::parse("header:Authorization:Bearer"),
            SecretInjection::Header {
                name: "Authorization".to_string(),
                prefix: Some("Bearer ".to_string())
            }
        );
    }

    #[test]
    fn test_registry_matching() {
        let registry = RuleRegistry::default();
        let rule = registry.match_host("api.pixabay.com:443").unwrap();
        assert_eq!(rule.secret, "PIXABAY_API_KEY");
        assert_eq!(
            rule.inject,
            SecretInjection::Query {
                param: "key".to_string()
            }
        );

        let rule2 = registry.match_host("api.elevenlabs.io").unwrap();
        assert_eq!(rule2.secret, "ELEVENLABS_API_KEY");
        assert_eq!(
            rule2.inject,
            SecretInjection::Header {
                name: "xi-api-key".to_string(),
                prefix: None,
            }
        );
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("api.pexels.com"), "PEXELS");
        assert_eq!(extract_service_name("api.tavily.com:443"), "TAVILY");
        assert_eq!(extract_service_name("api.deepseek.com"), "DEEPSEEK");
        assert_eq!(extract_service_name("subdomain.groq.io"), "GROQ");
    }

    #[test]
    fn test_auto_inference() {
        let registry = RuleRegistry::default();
        let available = vec!["PEXELS_API_KEY".to_string(), "TAVILY_TOKEN".to_string()];

        // Pexels has no explicit rule in registry, but is auto-inferred because PEXELS_API_KEY is in vault
        let pexels_rule = registry
            .match_or_infer("api.pexels.com", &available, false)
            .unwrap();
        assert_eq!(pexels_rule.secret, "PEXELS_API_KEY");
        assert_eq!(
            pexels_rule.inject,
            SecretInjection::Header {
                name: "Authorization".to_string(),
                prefix: None,
            }
        );

        // Tavily is auto-inferred with TAVILY_TOKEN from vault
        let tavily_rule = registry
            .match_or_infer("api.tavily.com:443", &available, false)
            .unwrap();
        assert_eq!(tavily_rule.secret, "TAVILY_TOKEN");

        // Unauthenticated arbitrary website with no key in vault returns None
        assert!(registry
            .match_or_infer("wikipedia.org", &available, false)
            .is_none());

        // But if client sends an Authorization header, it triggers inferred rule for JIT
        let unconfigured = registry
            .match_or_infer("api.resend.com", &available, true)
            .unwrap();
        assert_eq!(unconfigured.secret, "RESEND_API_KEY");
    }
}
