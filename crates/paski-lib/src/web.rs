use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use webauthn_rs::prelude::*;

use crate::config::Config;
use crate::credentials::CredentialStore;
use crate::utils::get_user_info;

pub struct EnrollmentSession {
    pub username: String,
    /// Channel to send the completed Passkey and its name back to the waiting CLI IPC connection.
    /// It's wrapped in an Option so we can take() it out when sending.
    pub completion_tx: Option<oneshot::Sender<(Passkey, String)>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Shared state for the web server.
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub config: Config,

    /// Active enrollment sessions initiated by the CLI over IPC, keyed by session token.
    pub enrollment_sessions: Mutex<HashMap<String, EnrollmentSession>>,

    /// In-flight registration challenges, keyed by a session token.
    pub reg_challenges: Mutex<HashMap<String, PasskeyRegistration>>,

    /// In-flight authentication challenges, keyed by a session token.
    pub auth_challenges: Mutex<HashMap<String, PasskeyAuthentication>>,

    /// Path to the credential store file (used for standalone auth testing).
    pub credential_store_path: std::path::PathBuf,
}

/// Create the axum router for enrollment and authentication.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Enrollment
        .route("/enroll", get(enroll_page))
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        // Authentication (for testing / standalone use)
        .route("/authenticate", get(authenticate_page))
        .route("/api/authenticate/start", post(authenticate_start))
        .route("/api/authenticate/finish", post(authenticate_finish))
        // Health check
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

// ── Enrollment ──────────────────────────────────────────────

async fn enroll_page() -> Html<&'static str> {
    Html(include_str!("../static/enroll.html"))
}

#[derive(Deserialize)]
struct RegisterStartRequest {
    session_token: String,
}

#[derive(Serialize)]
struct RegisterStartResponse {
    options: CreationChallengeResponse,
}

async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, AppError> {
    let mut sessions = state.enrollment_sessions.lock().await;
    let session = sessions.get(&req.session_token).ok_or_else(|| {
        anyhow::anyhow!("Invalid or expired session token. Please run pam-paski enroll again.")
    })?;

    if chrono::Utc::now().signed_duration_since(session.created_at) > chrono::Duration::minutes(5) {
        sessions.remove(&req.session_token);
        return Err(
            anyhow::anyhow!("Session token expired. Please run pam-paski enroll again.").into(),
        );
    }

    let user_unique_id = uuid::Uuid::new_v4();

    // In a real system, we might want to pass existing credentials over IPC to exclude them.
    // For now, we don't exclude existing credentials since the daemon doesn't have disk access.
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_unique_id, &session.username, &session.username, None)
        .map_err(|e| anyhow::anyhow!("Failed to start registration: {e}"))?;

    state
        .reg_challenges
        .lock()
        .await
        .insert(req.session_token.clone(), reg_state);

    Ok(Json(RegisterStartResponse { options: ccr }))
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    session_token: String,
    name: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct RegisterFinishResponse {
    success: bool,
    message: String,
}

async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, AppError> {
    let mut reg_challenges = state.reg_challenges.lock().await;
    let reg_state = reg_challenges
        .remove(&req.session_token)
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired registration challenge"))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| anyhow::anyhow!("Registration verification failed: {e}"))?;

    // Send the completed passkey back to the IPC connection
    let mut sessions = state.enrollment_sessions.lock().await;
    if let Some(session) = sessions.get_mut(&req.session_token) {
        if chrono::Utc::now().signed_duration_since(session.created_at)
            > chrono::Duration::minutes(5)
        {
            sessions.remove(&req.session_token);
            return Err(anyhow::anyhow!(
                "Session token expired. Please run pam-paski enroll again."
            )
            .into());
        }
        if let Some(tx) = session.completion_tx.take() {
            let _ = tx.send((passkey, req.name.clone()));
            tracing::info!(
                "Passkey verified and sent to IPC client for session {}",
                req.session_token
            );
        }
    }

    // Clean up the session
    sessions.remove(&req.session_token);

    Ok(Json(RegisterFinishResponse {
        success: true,
        message: "Passkey enrolled successfully".to_string(),
    }))
}

// ── Authentication ──────────────────────────────────────────

async fn authenticate_page() -> Html<&'static str> {
    Html(include_str!("../static/authenticate.html"))
}

#[derive(Deserialize)]
struct AuthenticateStartRequest {
    username: String,
}

#[derive(Serialize)]
struct AuthenticateStartResponse {
    session_token: String,
    options: RequestChallengeResponse,
}

async fn authenticate_start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticateStartRequest>,
) -> Result<Json<AuthenticateStartResponse>, AppError> {
    // Find the user's home directory and read their passkeys.
    // We are running as root (the daemon), so we have permission to read it.
    let user_info = get_user_info(&req.username)
        .map_err(|_| anyhow::anyhow!("User {} not found on system", req.username))?;

    let cred_path = CredentialStore::path_for_user(&user_info.home_dir);
    let store = CredentialStore::load(&cred_path)?;

    if !store.has_passkeys() {
        return Err(anyhow::anyhow!("No passkeys enrolled for user {}", req.username).into());
    }

    let passkeys = store.get_passkeys();

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| anyhow::anyhow!("Failed to start authentication: {e}"))?;

    let session_token = uuid::Uuid::new_v4().to_string();

    state
        .auth_challenges
        .lock()
        .await
        .insert(session_token.clone(), auth_state);

    Ok(Json(AuthenticateStartResponse {
        session_token,
        options: rcr,
    }))
}

#[derive(Deserialize)]
struct AuthenticateFinishRequest {
    session_token: String,
    credential: PublicKeyCredential,
}

#[derive(Serialize)]
struct AuthenticateFinishResponse {
    success: bool,
    message: String,
}

async fn authenticate_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticateFinishRequest>,
) -> Result<Json<AuthenticateFinishResponse>, AppError> {
    let auth_state = state
        .auth_challenges
        .lock()
        .await
        .remove(&req.session_token)
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired session token"))?;

    let _auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| anyhow::anyhow!("Authentication verification failed: {e}"))?;

    // Note: For this standalone test page, we INTENTIONALLY DO NOT save the updated
    // passkey signature counter back to disk.
    // The real PAM module handles credential updates safely.

    tracing::info!("Authentication successful (test mode, counter not updated)");

    Ok(Json(AuthenticateFinishResponse {
        success: true,
        message: "Passkey authentication successful".to_string(),
    }))
}

// ── Error handling ──────────────────────────────────────────

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("Request error: {}", self.0);
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": self.0.to_string()
            })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::create_webauthn;
    use chrono::{Duration, Utc};
    use std::path::PathBuf;
    use tokio::sync::oneshot;

    async fn setup_test_state() -> Arc<AppState> {
        let mut config = Config::default();
        config.relying_party.origins = vec!["http://localhost".to_string()];
        let webauthn = create_webauthn(&config).unwrap();
        Arc::new(AppState {
            webauthn,
            config,
            enrollment_sessions: Mutex::new(HashMap::new()),
            reg_challenges: Mutex::new(HashMap::new()),
            auth_challenges: Mutex::new(HashMap::new()),
            credential_store_path: PathBuf::from("/tmp/paski-test-creds"),
        })
    }

    #[tokio::test]
    async fn test_enrollment_expiration_in_start() {
        let state = setup_test_state().await;
        let session_token = "test-token".to_string();
        let (tx, _rx) = oneshot::channel();

        // Insert an expired session (6 minutes ago)
        state.enrollment_sessions.lock().await.insert(
            session_token.clone(),
            EnrollmentSession {
                username: "testuser".to_string(),
                completion_tx: Some(tx),
                created_at: Utc::now() - Duration::minutes(6),
            },
        );

        // Call register_start
        let req = RegisterStartRequest {
            session_token: session_token.clone(),
        };
        let result = register_start(State(state.clone()), Json(req)).await;

        assert!(result.is_err());
        let err_msg = result.err().unwrap().0.to_string();
        assert!(err_msg.contains("expired"));

        // Verify session was removed
        assert!(state
            .enrollment_sessions
            .lock()
            .await
            .get(&session_token)
            .is_none());
    }

    #[tokio::test]
    async fn test_enrollment_stays_if_not_expired() {
        let state = setup_test_state().await;
        let session_token = "test-token".to_string();
        let (tx, _rx) = oneshot::channel();

        // Insert a fresh session
        state.enrollment_sessions.lock().await.insert(
            session_token.clone(),
            EnrollmentSession {
                username: "testuser".to_string(),
                completion_tx: Some(tx),
                created_at: Utc::now(),
            },
        );

        // Call register_start
        let req = RegisterStartRequest {
            session_token: session_token.clone(),
        };
        let result = register_start(State(state.clone()), Json(req)).await;

        // It might still be an Err if WebAuthn fails (e.g. challenge creation),
        // but it should NOT be an "expired" error.
        if let Err(e) = result {
            let err_msg = e.0.to_string();
            assert!(!err_msg.contains("expired"));
        }

        // Verify session still exists
        assert!(state
            .enrollment_sessions
            .lock()
            .await
            .get(&session_token)
            .is_some());
    }
}
