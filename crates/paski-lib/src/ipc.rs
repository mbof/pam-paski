use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

/// Requests sent from the CLI client to the Daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Start a new enrollment session for the given username.
    EnrollStart { username: String },
}

/// Responses sent from the Daemon back to the CLI client.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// The URL the user should open in their browser.
    EnrollUrl { url: String },
    /// Enrollment was successful, here is the resulting credential.
    EnrollSuccess { passkey: Passkey, name: String },
    /// An error occurred during the process.
    Error { message: String },
}
