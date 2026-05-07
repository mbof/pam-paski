use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use webauthn_rs::prelude::Passkey;

/// Metadata about an enrolled passkey, paired with the actual Passkey credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledPasskey {
    /// The webauthn-rs Passkey credential (contains cred_id, public key, counter, etc.)
    pub passkey: Passkey,
    /// User-visible name for this passkey (e.g. "iPhone", "YubiKey 5").
    pub name: String,
    /// When this passkey was enrolled.
    pub enrolled_at: DateTime<Utc>,
    /// When this passkey was last used for authentication (if ever).
    pub last_used: Option<DateTime<Utc>>,
}

/// The per-user credential store, serialized as ~/.config/pam-paski/enrolled_passkeys.json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialStore {
    /// All enrolled passkeys for this user.
    pub passkeys: Vec<EnrolledPasskey>,
}

impl CredentialStore {
    /// Get the default credential store path for the current user.
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .context("HOME environment variable not set")?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("pam-paski")
            .join("enrolled_passkeys.json"))
    }

    /// Get the credential store path for a specific user's home directory.
    pub fn path_for_user(home_dir: &Path) -> PathBuf {
        home_dir
            .join(".config")
            .join("pam-paski")
            .join("enrolled_passkeys.json")
    }

    /// Load the credential store from a JSON file.
    /// Returns an empty store if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read credentials from {}", path.display()))?;
        let store: CredentialStore = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse credentials from {}", path.display()))?;
        Ok(store)
    }

    /// Save the credential store to a JSON file.
    /// Creates parent directories if they don't exist.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }
        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize credentials")?;
        std::fs::write(path, &contents)
            .with_context(|| format!("Failed to write credentials to {}", path.display()))?;
        // Restrict permissions to owner only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load from the default path for the current user.
    pub fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load(&path)
    }

    /// Save to the default path for the current user.
    pub fn save_default(&self) -> Result<()> {
        let path = Self::default_path()?;
        self.save(&path)
    }

    /// Add a new passkey to the store.
    pub fn add(&mut self, passkey: EnrolledPasskey) {
        self.passkeys.push(passkey);
    }

    /// Remove a passkey by index (1-based, as shown to user).
    pub fn remove(&mut self, index: usize) -> Option<EnrolledPasskey> {
        if index == 0 || index > self.passkeys.len() {
            return None;
        }
        Some(self.passkeys.remove(index - 1))
    }

    /// Check if the user has any enrolled passkeys.
    pub fn has_passkeys(&self) -> bool {
        !self.passkeys.is_empty()
    }

    /// Get all Passkey references for use with webauthn-rs authentication.
    pub fn get_passkeys(&self) -> Vec<Passkey> {
        self.passkeys.iter().map(|e| e.passkey.clone()).collect()
    }
}
