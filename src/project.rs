//! Project workspace detection and management.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const PROJECT_CONFIG_FILE: &str = ".cloak";
pub const GLOBAL_NAMESPACE: &str = "global";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectConfig {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct DetectedProject {
    pub name: String,
    pub root: PathBuf,
}

/// Discovers if the current working directory or any of its parent directories
/// contains a `.cloak` configuration file.
pub fn detect_project() -> Option<DetectedProject> {
    let current_dir = env::current_dir().ok()?;
    let mut dir: &Path = &current_dir;

    loop {
        let config_path = dir.join(PROJECT_CONFIG_FILE);
        if config_path.is_file() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(config) = serde_json::from_str::<ProjectConfig>(&content) {
                    return Some(DetectedProject {
                        name: config.name,
                        root: dir.to_path_buf(),
                    });
                }
            }
        }

        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    None
}

/// Initializes a `.cloak` file in the current working directory.
pub fn init_project(custom_name: Option<String>) -> Result<DetectedProject> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    let config_path = current_dir.join(PROJECT_CONFIG_FILE);

    if config_path.exists() {
        bail!("A project is already initialized in this directory (found .cloak)");
    }

    let project_name = match custom_name {
        Some(name) => name,
        None => current_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("project")
            .to_string(),
    };

    let config = ProjectConfig {
        name: project_name.clone(),
    };

    let serialized = serde_json::to_string_pretty(&config)?;
    fs::write(&config_path, serialized)
        .with_context(|| format!("Failed to write config to {:?}", config_path))?;

    Ok(DetectedProject {
        name: project_name,
        root: current_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_detect_project() {
        let temp_dir = env::temp_dir().join(format!("cloak_proj_test_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();

        // Change current directory to temp_dir
        let orig_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let proj = init_project(Some("test-suite-app".to_string())).unwrap();
        assert_eq!(proj.name, "test-suite-app");

        // Subdirectory should also detect project from parent
        let sub_dir = temp_dir.join("subdir/deep");
        fs::create_dir_all(&sub_dir).unwrap();
        env::set_current_dir(&sub_dir).unwrap();

        let detected = detect_project().expect("Should find project from parent dir");
        assert_eq!(detected.name, "test-suite-app");

        // Restore
        env::set_current_dir(orig_dir).unwrap();
        let _ = fs::remove_dir_all(temp_dir);
    }
}
