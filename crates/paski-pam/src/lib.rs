use std::path::PathBuf;

use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule};
use tracing_subscriber::EnvFilter;

use paski_lib::config::Config;
use paski_lib::credentials::CredentialStore;
use paski_lib::utils::get_user_info;
use paski_lib::webauthn::create_webauthn;

struct PamPaski;

impl PamServiceModule for PamPaski {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        // Initialize logging (only once per process)
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("paski=info"))
            .try_init();

        // 1. Get the username
        let username_cstr = match pamh.get_user(None) {
            Ok(Some(u)) => u,
            _ => return PamError::USER_UNKNOWN,
        };
        let username = match username_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return PamError::USER_UNKNOWN,
        };

        tracing::info!("Starting pam_paski authentication for user: {}", username);

        // 2. Load Config
        let config_path = PathBuf::from("/etc/pam-paski/config.yaml");
        let config = match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to load config: {}", e);
                return PamError::AUTHINFO_UNAVAIL;
            }
        };

        // 3. Look up user home directory
        let user_info = match get_user_info(username) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("Could not find user info for {}: {}", username, e);
                return PamError::USER_UNKNOWN;
            }
        };

        // 4. Load Credentials
        let cred_path = CredentialStore::path_for_user(&user_info.home_dir);
        let mut store = match CredentialStore::load(&cred_path) {
            Ok(s) => s,
            Err(_) => {
                tracing::debug!("No passkeys enrolled for {}", username);
                return PamError::IGNORE; // Fall back to password seamlessly
            }
        };

        if !store.has_passkeys() {
            return PamError::IGNORE;
        }
        let passkeys = store.get_passkeys();

        // 5. Initialize WebAuthn
        let webauthn = match create_webauthn(&config) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to initialize webauthn: {}", e);
                return PamError::AUTHINFO_UNAVAIL;
            }
        };

        // 6. Start Authentication Challenge
        let (rcr, auth_state) = match webauthn.start_passkey_authentication(&passkeys) {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to generate challenge: {}", e);
                return PamError::AUTH_ERR;
            }
        };

        let challenge_json = match serde_json::to_string(&rcr) {
            Ok(j) => j,
            Err(_) => return PamError::AUTHINFO_UNAVAIL,
        };

        // 7. PAM Conversation - Send Challenge
        let prompt = format!("PASKI:{}", challenge_json);
        let response_cstr = match pamh.conv(Some(&prompt), PamMsgStyle::PROMPT_ECHO_ON) {
            Ok(Some(r)) => r,
            _ => {
                tracing::debug!("Conversation failed or returned empty");
                return PamError::AUTH_ERR;
            }
        };

        let response_str = match response_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return PamError::AUTH_ERR,
        };

        tracing::info!("PAM response length: {} bytes", response_str.len());
        if response_str.len() > 20 {
            tracing::info!("PAM response starts: {}...", &response_str[..20]);
            tracing::info!(
                "PAM response ends: ...{}",
                &response_str[response_str.len().saturating_sub(20)..]
            );
        } else {
            tracing::info!("PAM response (full): {}", response_str);
        }

        if !response_str.starts_with("PASKI:") {
            tracing::warn!(
                "Received non-PASKI response (len={}), aborting.",
                response_str.len()
            );
            return PamError::AUTH_ERR;
        }

        let assertion_json = &response_str["PASKI:".len()..];
        let credential: webauthn_rs::prelude::PublicKeyCredential =
            match serde_json::from_str(assertion_json) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse WebAuthn assertion (json len={}): {}",
                        assertion_json.len(),
                        e
                    );
                    return PamError::AUTH_ERR;
                }
            };

        // 8. Verify Assertion
        let auth_result = match webauthn.finish_passkey_authentication(&credential, &auth_state) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("WebAuthn verification failed: {}", e);
                return PamError::AUTH_ERR;
            }
        };

        // 9. Update counter and save
        let cred_id = auth_result.cred_id();
        if let Some(enrolled) = store
            .passkeys
            .iter_mut()
            .find(|p| p.passkey.cred_id() == cred_id)
        {
            enrolled.passkey.update_credential(&auth_result);
            enrolled.last_used = Some(chrono::Utc::now());
        }

        // Chown back to the user since PAM runs as root
        if let Err(e) = store.save(&cred_path, Some((user_info.uid, user_info.gid))) {
            tracing::error!("Failed to save updated credential counter: {}", e);
            // We return success anyway since auth technically succeeded, but warn.
        }

        tracing::info!("Successfully authenticated user {}", username);

        // Cockpit or subsequent modules in the stack might require PAM_AUTHTOK to be set.
        // Even though we authenticated via passkey, we'll set a dummy token just in case.
        let _ = pamh.set_authtok(&std::ffi::CString::new("passkey-auth").unwrap());

        PamError::SUCCESS
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    // Other functions (acct_mgmt, open_session, etc.) use default implementation returning SERVICE_ERR
}

pam_module!(PamPaski);
