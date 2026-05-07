use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// System-wide configuration, read from /etc/pam-paski/config.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub relying_party: RelyingPartyConfig,
    pub tls: TlsConfig,
    pub enrollment: EnrollmentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingPartyConfig {
    /// The WebAuthn Relying Party ID — a domain name, no port, no scheme.
    /// e.g. "example.com"
    pub id: String,
    /// Human-readable name shown to the user during passkey enrollment.
    /// e.g. "Example Company"
    pub name: String,
    /// Allowed origins for WebAuthn ceremonies.
    /// e.g. ["https://example.com:443", "https://id.example.com:8443"]
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate chain (PEM).
    pub cert: PathBuf,
    /// Path to the TLS private key (PEM).
    pub key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentConfig {
    /// Port for the temporary enrollment HTTPS server.
    pub port: u16,
}

impl Config {
    /// Default system config path.
    pub fn default_path() -> PathBuf {
        PathBuf::from("/etc/pam-paski/config.yaml")
    }

    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;
        let config: Config = serde_yaml::from_str(&contents)
            .with_context(|| format!("Failed to parse config from {}", path.display()))?;
        Ok(config)
    }

    /// Load from the default system path.
    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_path())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            relying_party: RelyingPartyConfig {
                id: "localhost".to_string(),
                name: "pam-paski".to_string(),
                origins: vec!["https://localhost:8443".to_string()],
            },
            tls: TlsConfig {
                cert: PathBuf::from("/etc/letsencrypt/live/example.com/fullchain.pem"),
                key: PathBuf::from("/etc/letsencrypt/live/example.com/privkey.pem"),
            },
            enrollment: EnrollmentConfig { port: 8443 },
        }
    }
}
