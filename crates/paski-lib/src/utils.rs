use anyhow::{bail, Result};
use std::path::PathBuf;

/// User information retrieved from the system
#[derive(Debug)]
pub struct UserInfo {
    pub username: String,
    pub home_dir: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

/// Helper to find a user's home directory and UID/GID on Linux
pub fn get_user_info(username: &str) -> Result<UserInfo> {
    // Basic validation to prevent command injection
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("Invalid username format");
    }

    let output = std::process::Command::new("getent")
        .args(["passwd", username])
        .output()?;

    let out_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = out_str.split(':').collect();

    if parts.len() >= 6 {
        let uid: u32 = parts[2].parse()?;
        let gid: u32 = parts[3].parse()?;
        let home_dir = PathBuf::from(parts[5]);

        Ok(UserInfo {
            username: username.to_string(),
            home_dir,
            uid,
            gid,
        })
    } else {
        bail!("User not found")
    }
}
