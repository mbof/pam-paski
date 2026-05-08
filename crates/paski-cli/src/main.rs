use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};
use tracing_subscriber::EnvFilter;

use paski_lib::config::Config;
use paski_lib::credentials::{CredentialStore, EnrolledPasskey};
use paski_lib::ipc::{IpcRequest, IpcResponse};
use paski_lib::web::{create_router, AppState, EnrollmentSession};
use paski_lib::webauthn::create_webauthn;

#[derive(Parser)]
#[command(
    name = "pam-paski",
    about = "Passkey enrollment and management for Linux PAM"
)]
struct Cli {
    /// Path to the configuration file
    #[arg(long, default_value = "/etc/pam-paski/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll a new passkey. The daemon must be running.
    Enroll,
    /// List enrolled passkeys for the current user
    List,
    /// Remove an enrolled passkey by number
    Remove {
        /// The passkey number to remove (as shown by `list`)
        number: usize,
    },
    /// Start the pam-paskid service (daemon mode) or standalone test server
    Serve {
        /// Run in daemon mode (listens on Unix socket for IPC)
        #[arg(long)]
        daemon: bool,
        /// Port to listen on (defaults to config or 8443)
        #[arg(long)]
        port: Option<u16>,
        /// Disable TLS (use HTTP — only for localhost testing)
        #[arg(long)]
        no_tls: bool,
    },
    /// Print an example configuration file
    InitConfig,
    /// Generate a custom Cockpit login.html with the WebAuthn interceptor
    InstallCockpit,
}

const SOCKET_PATH: &str = "/run/pam-paski/daemon.sock";

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("paski=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Enroll => cmd_enroll().await,
        Commands::List => cmd_list(),
        Commands::Remove { number } => cmd_remove(number),
        Commands::Serve {
            daemon,
            port,
            no_tls,
        } => cmd_serve(&cli.config, daemon, port, no_tls).await,
        Commands::InitConfig => cmd_init_config(),
        Commands::InstallCockpit => cmd_install_cockpit(),
    }
}

fn cmd_init_config() -> Result<()> {
    let config = Config::default();
    let yaml = serde_yaml::to_string(&config)?;
    println!("# pam-paski configuration");
    println!("# Save this to /etc/pam-paski/config.yaml");
    println!("{yaml}");
    Ok(())
}

fn cmd_list() -> Result<()> {
    let store = CredentialStore::load_default()?;

    if store.passkeys.is_empty() {
        println!("No passkeys enrolled.");
        println!("Run `pam-paski enroll <name>` to enroll a passkey.");
        return Ok(());
    }

    println!("Enrolled passkeys:\n");
    for (i, pk) in store.passkeys.iter().enumerate() {
        let last_used = pk
            .last_used
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());
        println!("  {}. {}", i + 1, pk.name,);
        println!(
            "     enrolled {}   last used {}",
            pk.enrolled_at.format("%Y-%m-%d %H:%M"),
            last_used,
        );
    }
    println!();

    Ok(())
}

fn cmd_remove(number: usize) -> Result<()> {
    let path = CredentialStore::default_path()?;
    let mut store = CredentialStore::load(&path)?;

    match store.remove(number) {
        Some(removed) => {
            store.save(&path, None)?;
            println!("Removed passkey: {}", removed.name);
        }
        None => {
            println!("Invalid passkey number: {number}");
            println!("Run `pam-paski list` to see enrolled passkeys.");
        }
    }

    Ok(())
}

async fn cmd_enroll() -> Result<()> {
    let username = std::env::var("USER").context("Could not determine current username")?;

    println!("Connecting to pam-paskid daemon at {}...", SOCKET_PATH);
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .context("Failed to connect to daemon. Is pam-paskid running?")?;

    let req = IpcRequest::EnrollStart { username };
    let req_json = serde_json::to_string(&req)? + "\n";
    stream.write_all(req_json.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    // Read the EnrollUrl response
    reader.read_line(&mut line).await?;
    if line.is_empty() {
        anyhow::bail!("Daemon closed connection unexpectedly");
    }

    let resp: IpcResponse = serde_json::from_str(&line)?;
    match resp {
        IpcResponse::EnrollUrl { url } => {
            println!();
            println!("  🔑 pam-paski enrollment");
            println!("  ─────────────────────────────────");
            println!("  Open this URL in your browser:");
            println!();
            println!("    {url}");
            println!();
            println!("  Waiting for you to complete enrollment in the browser...");
            println!("  Press Ctrl+C to cancel.");
            println!();
        }
        IpcResponse::Error { message } => {
            anyhow::bail!("Daemon returned error: {message}");
        }
        _ => {
            anyhow::bail!("Unexpected response from daemon");
        }
    }

    // Wait for the EnrollSuccess response
    line.clear();
    reader.read_line(&mut line).await?;
    if line.is_empty() {
        anyhow::bail!("Daemon closed connection before enrollment finished");
    }

    let resp: IpcResponse = serde_json::from_str(&line)?;
    match resp {
        IpcResponse::EnrollSuccess { passkey, name } => {
            let enrolled = EnrolledPasskey {
                passkey,
                name: name.clone(),
                enrolled_at: chrono::Utc::now(),
                last_used: None,
            };

            let path = CredentialStore::default_path()?;
            let mut store = CredentialStore::load(&path)?;
            store.add(enrolled);
            store.save(&path, None)?;

            println!("✅ Successfully enrolled passkey '{}'!", name);
            println!("   Saved to {}", path.display());
        }
        IpcResponse::Error { message } => {
            anyhow::bail!("Enrollment failed: {message}");
        }
        _ => {
            anyhow::bail!("Unexpected response from daemon");
        }
    }

    Ok(())
}

async fn cmd_serve(
    config_path: &PathBuf,
    daemon: bool,
    port_arg: Option<u16>,
    no_tls: bool,
) -> Result<()> {
    let config = Config::load(config_path).or_else(|_| {
        tracing::warn!(
            "Could not load config from {}, using defaults",
            config_path.display()
        );
        Ok::<Config, anyhow::Error>(Config::default())
    })?;

    let port = port_arg.unwrap_or(config.enrollment.port);
    let webauthn = create_webauthn(&config)?;
    let cred_path = CredentialStore::default_path()?;

    let state = Arc::new(AppState {
        webauthn,
        config: config.clone(),
        enrollment_sessions: Mutex::new(Default::default()),
        reg_challenges: Mutex::new(Default::default()),
        auth_challenges: Mutex::new(Default::default()),
        credential_store_path: cred_path,
    });

    let app = create_router(state.clone());
    let addr = format!("0.0.0.0:{port}");

    if daemon {
        // Start the IPC listener for CLI enroll requests
        if std::path::Path::new(SOCKET_PATH).exists() {
            std::fs::remove_file(SOCKET_PATH)?;
        }

        // Ensure the directory exists
        if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let ipc_listener = UnixListener::bind(SOCKET_PATH)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
        }

        let state_clone = state.clone();
        let rp_id = config.relying_party.id.clone();

        tokio::spawn(async move {
            tracing::info!("Listening for IPC on {}", SOCKET_PATH);
            loop {
                match ipc_listener.accept().await {
                    Ok((stream, _addr)) => {
                        let state = state_clone.clone();
                        let rp_id = rp_id.clone();
                        tokio::spawn(handle_ipc_connection(stream, state, rp_id, port, no_tls));
                    }
                    Err(e) => tracing::error!("IPC accept error: {}", e),
                }
            }
        });
    }

    println!();
    println!("  🔐 pam-paskid web service");
    println!("  ───────────────────────────────");
    if no_tls {
        println!("  Listening on http://{addr}");
        println!("  Enroll:       http://localhost:{port}/enroll");
        println!("  Authenticate: http://localhost:{port}/authenticate");
    } else {
        println!("  Listening on https://{addr}");
        println!(
            "  Enroll:       https://{}:{port}/enroll",
            config.relying_party.id
        );
        println!(
            "  Authenticate: https://{}:{port}/authenticate",
            config.relying_party.id
        );
    }
    println!();

    if no_tls {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
    } else if config.tls.cert.exists() && config.tls.key.exists() {
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&config.tls.cert, &config.tls.key)
                .await
                .context("Failed to load TLS certificates")?;

        axum_server::bind_rustls(addr.parse()?, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        anyhow::bail!(
            "TLS certificates not found and --no-tls not specified. \
            Either provide certs in the config or use --no-tls for localhost testing."
        );
    }

    Ok(())
}

async fn handle_ipc_connection(
    mut stream: UnixStream,
    state: Arc<AppState>,
    rp_id: String,
    port: u16,
    no_tls: bool,
) {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    if let Err(e) = reader.read_line(&mut line).await {
        tracing::error!("Failed to read IPC request: {}", e);
        return;
    }

    let req: IpcRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Invalid IPC request: {}", e);
            return;
        }
    };

    match req {
        IpcRequest::EnrollStart { username } => {
            let session_token = uuid::Uuid::new_v4().to_string();
            let (tx, rx) = oneshot::channel();

            state.enrollment_sessions.lock().await.insert(
                session_token.clone(),
                EnrollmentSession {
                    username,
                    completion_tx: Some(tx),
                    created_at: chrono::Utc::now(),
                },
            );

            let protocol = if no_tls { "http" } else { "https" };
            let host = if no_tls { "localhost" } else { &rp_id };
            let url = format!(
                "{}://{}:{}/enroll?token={}",
                protocol, host, port, session_token
            );

            let resp = IpcResponse::EnrollUrl { url };
            let mut resp_json = serde_json::to_string(&resp).unwrap();
            resp_json.push('\n');

            if let Err(e) = writer.write_all(resp_json.as_bytes()).await {
                tracing::error!("Failed to send IPC response: {}", e);
                state
                    .enrollment_sessions
                    .lock()
                    .await
                    .remove(&session_token);
                return;
            }

            // Wait for WebAuthn completion from the web handler
            match rx.await {
                Ok((passkey, name)) => {
                    let resp = IpcResponse::EnrollSuccess { passkey, name };
                    let mut resp_json = serde_json::to_string(&resp).unwrap();
                    resp_json.push('\n');
                    let _ = writer.write_all(resp_json.as_bytes()).await;
                }
                Err(_) => {
                    // Channel closed without a message — means the session was aborted or errored out
                    let resp = IpcResponse::Error {
                        message: "Enrollment aborted".into(),
                    };
                    let mut resp_json = serde_json::to_string(&resp).unwrap();
                    resp_json.push('\n');
                    let _ = writer.write_all(resp_json.as_bytes()).await;
                }
            }
        }
    }
}

fn cmd_install_cockpit() -> Result<()> {
    let target_path = std::path::Path::new("/usr/share/cockpit/static/login.html");
    let backup_path = target_path.with_extension("html.bak");

    // Always start from a clean file to avoid duplicate/stale injections
    let source_path = if backup_path.exists() {
        backup_path.as_path()
    } else {
        target_path
    };

    if !source_path.exists() {
        anyhow::bail!(
            "Could not find standard Cockpit login page at {:?}",
            source_path
        );
    }

    let mut html = std::fs::read_to_string(source_path)?;

    // If we're reading the target path because no backup existed, create the backup now
    if source_path == target_path && !html.contains("PASKI Cockpit Interceptor") {
        std::fs::copy(target_path, &backup_path)?;
        println!("Created backup at {:?}", backup_path);
    }

    if html.contains("PASKI Cockpit Interceptor") {
        // This should only happen if the user somehow backed up the injected file
        anyhow::bail!("The source file already contains the interceptor. Please restore a clean /usr/share/cockpit/static/login.html");
    }
    let script = r#"
<!-- PASKI Cockpit Interceptor -->
<script type="text/javascript">
(function() {
    function base64urlToBuffer(baseurl64String) {
        const padding = '==='.slice((baseurl64String.length + 3) % 4);
        const base64String = baseurl64String.replace(/-/g, '+').replace(/_/g, '/') + padding;
        const binaryString = atob(base64String);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binaryString = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binaryString += String.fromCharCode(bytes[i]);
        }
        return btoa(binaryString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    function prepareRequestOptions(options) {
        const publicKey = JSON.parse(JSON.stringify(options.publicKey));
        publicKey.challenge = base64urlToBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
            for (let i = 0; i < publicKey.allowCredentials.length; i++) {
                publicKey.allowCredentials[i].id = base64urlToBuffer(publicKey.allowCredentials[i].id);
            }
        }
        return publicKey;
    }
    function serializeCredential(cred) {
        return {
            id: cred.id,
            rawId: bufferToBase64url(cred.rawId),
            type: cred.type,
            response: {
                authenticatorData: bufferToBase64url(cred.response.authenticatorData),
                clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
                signature: bufferToBase64url(cred.response.signature),
                userHandle: cred.response.userHandle ? bufferToBase64url(cred.response.userHandle) : null,
            },
            extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
        };
    }
    function showInfo(msg) {
        const info = document.getElementById('info-group');
        const msgEl = document.getElementById('login-info-message');
        if (info && msgEl) { msgEl.textContent = msg; info.hidden = false; }
    }
    function hideInfo() {
        const info = document.getElementById('info-group');
        if (info) info.hidden = true;
    }
    function showError(msg) {
        const err = document.getElementById('error-group');
        const msgEl = document.getElementById('login-error-message');
        if (err && msgEl) { msgEl.textContent = msg; err.hidden = false; }
    }

    const observer = new MutationObserver((mutations) => {
        const promptEl = document.getElementById('conversation-prompt');
        if (!promptEl || !promptEl.textContent.startsWith('PASKI:')) return;
        
        const challengeStr = promptEl.textContent.substring(6);
        promptEl.textContent = ''; // Clear it to prevent infinite loops from further mutations!
        
        let challengeJson;
        try { challengeJson = JSON.parse(challengeStr); } 
        catch(e) { showError("Invalid WebAuthn challenge from PAM"); return; }

        document.getElementById('conversation-group').hidden = true;
        showInfo('Please touch your passkey to log in...');
        
        const loginBtn = document.getElementById('login-button');
        if (loginBtn) {
            loginBtn.disabled = true;
            const btnText = loginBtn.querySelector('.button-text');
            if (btnText) btnText.textContent = 'Authenticating...';
        }

        try {
            const options = prepareRequestOptions(challengeJson);
            navigator.credentials.get({ publicKey: options })
                .then(credential => {
                    hideInfo();
                    const inputEl = document.getElementById('conversation-input');
                    inputEl.value = 'PASKI:' + JSON.stringify(serializeCredential(credential));
                    if (loginBtn) {
                        loginBtn.disabled = false;
                    }
                    // Simulate pressing Enter in the conversation input to trigger Cockpit's specific handler
                    // rather than clicking the login button which might trigger duplicate Basic Auth requests.
                    const enterEvent = new KeyboardEvent('keydown', {
                        bubbles: true, cancelable: true, keyCode: 13, which: 13
                    });
                    inputEl.dispatchEvent(enterEvent);
                })
                .catch(err => {
                    hideInfo();
                    if (err.name === 'NotAllowedError') showError('Passkey authentication was cancelled or timed out.');
                    else showError('WebAuthn Error: ' + err.message);
                    
                    document.getElementById('conversation-group').hidden = false;
                    if (loginBtn) {
                        loginBtn.disabled = false;
                        const btnText = loginBtn.querySelector('.button-text');
                        if (btnText) btnText.textContent = 'Log in';
                    }
                });
        } catch(e) {
            hideInfo();
            showError('Failed to parse WebAuthn options: ' + e.message);
            document.getElementById('conversation-group').hidden = false;
            if (loginBtn) {
                loginBtn.disabled = false;
                const btnText = loginBtn.querySelector('.button-text');
                if (btnText) btnText.textContent = 'Log in';
            }
        }
    });

    window.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    });
})();
</script>
</body>"#;
    html = html.replace("</body>", script);

    std::fs::write(target_path, html)?;

    println!(
        "✅ Successfully injected WebAuthn interceptor into {:?}",
        target_path
    );
    println!("No configuration changes are needed. Just refresh your Cockpit login page!");

    Ok(())
}
