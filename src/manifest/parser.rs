use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("failed to read manifest file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse manifest YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("manifest validation failed: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Top-level manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub skill: SkillMeta,
    pub permissions: Permissions,
    #[serde(default)]
    pub resources: ResourceLimits,
    pub entrypoint: Entrypoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
}

// ---------------------------------------------------------------------------
// Permissions — the core of capability-based isolation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(default)]
    pub network: NetworkPermissions,
    #[serde(default)]
    pub filesystem: FilesystemPermissions,
    #[serde(default)]
    pub env_vars: EnvVarPermissions,
    #[serde(default)]
    pub syscalls: SyscallPermissions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPermissions {
    #[serde(default)]
    pub egress: Vec<EgressRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    pub domain: String,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_ports() -> Vec<u16> {
    vec![443]
}
fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPermissions {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvVarPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPermissions {
    #[serde(default = "default_profile")]
    pub profile: String,
}

impl Default for SyscallPermissions {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
        }
    }
}

fn default_profile() -> String {
    "default".to_string()
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default = "default_cpu")]
    pub cpu_shares: u64,
    #[serde(default = "default_runtime")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_output")]
    pub max_output_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 256,
            cpu_shares: 512,
            max_runtime_seconds: 60,
            max_output_bytes: 1_048_576,
        }
    }
}

fn default_memory() -> u64 {
    256
}
fn default_cpu() -> u64 {
    512
}
fn default_runtime() -> u64 {
    60
}
fn default_output() -> u64 {
    1_048_576
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_workdir")]
    pub workdir: String,
}

fn default_workdir() -> String {
    "/skill".to_string()
}

// ---------------------------------------------------------------------------
// Parsing & validation
// ---------------------------------------------------------------------------

impl SkillManifest {
    /// Load and validate a manifest from a YAML file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse_yaml(&content)
    }

    /// Parse and validate from a YAML string.
    pub fn parse_yaml(yaml: &str) -> Result<Self, ManifestError> {
        let manifest: Self = serde_yaml::from_str(yaml)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate invariants beyond what serde can enforce.
    fn validate(&self) -> Result<(), ManifestError> {
        if self.skill.name.is_empty() {
            return Err(ManifestError::Validation(
                "skill.name must not be empty".into(),
            ));
        }

        // Validate egress rules
        for rule in &self.permissions.network.egress {
            if rule.domain.is_empty() {
                return Err(ManifestError::Validation(
                    "network egress domain must not be empty".into(),
                ));
            }
            if rule.ports.is_empty() {
                return Err(ManifestError::Validation(format!(
                    "network egress rule for '{}' must specify at least one port",
                    rule.domain
                )));
            }
        }

        // Validate resource limits
        if self.resources.memory_mb == 0 {
            return Err(ManifestError::Validation(
                "memory_mb must be > 0".into(),
            ));
        }
        if self.resources.max_runtime_seconds == 0 {
            return Err(ManifestError::Validation(
                "max_runtime_seconds must be > 0".into(),
            ));
        }

        Ok(())
    }

    /// Return all allowed egress domains as a flat list.
    pub fn allowed_domains(&self) -> Vec<&str> {
        self.permissions
            .network
            .egress
            .iter()
            .map(|r| r.domain.as_str())
            .collect()
    }

    /// Return all allowed env var names.
    pub fn allowed_env_vars(&self) -> Vec<&str> {
        self.permissions
            .env_vars
            .allow
            .iter()
            .map(|s| s.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_weather_manifest() {
        let yaml = include_str!("../../examples/skills/weather/skillsandbox.yaml");
        let manifest = SkillManifest::parse_yaml(yaml).expect("should parse");
        assert_eq!(manifest.skill.name, "weather-lookup");
        assert_eq!(manifest.permissions.network.egress.len(), 1);
        assert_eq!(
            manifest.permissions.network.egress[0].domain,
            "api.openweathermap.org"
        );
        assert_eq!(manifest.allowed_env_vars(), vec!["OPENWEATHER_API_KEY", "LANG", "PATH"]);
    }

    #[test]
    fn reject_empty_name() {
        let yaml = r#"
skill:
  name: ""
  version: "0.1.0"
permissions:
  network:
    egress: []
entrypoint:
  command: "echo"
"#;
        let err = SkillManifest::parse_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }
}
