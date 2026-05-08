# pam-paski

`pam-paski` is an experimental, modular, passkey-based authentication system for
Linux. It enables secure, passwordless authentication by bridging WebAuthn
ceremonies with the standard Linux PAM authentication stack. It includes an
experimental integration allowing passkey-based authentication to **Cockpit**
(not supported by the Cockpit team).

Demo video:

https://github.com/user-attachments/assets/f4fcc89a-2f82-419e-b16d-65f3bc36e8cd

## Architecture

1. **`pam-paskid` (Daemon)**: Runs as root and handles the WebAuthn cryptography
   and challenge generation.
2. **`pam-paski` (CLI)**: An unprivileged command-line tool for users to enroll
   and manage their own passkeys. It communicates with the daemon to trigger
   enrollment.
3. **`pam_paski.so` (PAM)**: A custom pluggable authentication module (PAM)
   which intercepts login attempts and communicates with the daemon to trigger
   WebAuthn flows.

[Learn more about the integration design](design.md).

## Prerequisites

- A domain for your server
- SSL certificates for the domain (e.g., LetsEncrypt)
- A web service that uses PAM for authentication (e.g., Cockpit)
- An open port for the enrollment service

## 1. Build and install

Build the project using Cargo:

```bash
cargo build --release
```

Copy the binaries and the PAM module to their appropriate system directories:

```bash
# Install the daemon and CLI
sudo cp target/release/pam-paski /usr/local/bin/

# Install the PAM module (example directory for Ubuntu - adapt for your own system)
sudo cp target/release/libpam_paski.so /lib/x86_64-linux-gnu/security/pam_paski.so
```

## 2. Configuration

Create the configuration directory and initialize the config file:

```bash
sudo mkdir -p /etc/pam-paski
sudo pam-paski init-config
```

Edit `/etc/pam-paski/config.yaml` to match your environment.

> [!IMPORTANT]
>
> WebAuthn is strictly bound to the origin. The `rp_origins` array **MUST
> exactly match** the URL (including the port) that you use to access Cockpit in
> your browser!

Example `/etc/pam-paski/config.yaml`:

```yaml
rp_id: "example.com"
rp_name: "My Linux Server"
rp_origins:
  - "https://example.com:9090" # Your Cockpit server
  - "https://example.com:9091" # Your enrollment server
```

## 4. Run the daemon

Start the background daemon. You can run it manually for testing:

```bash
sudo pam-paski serve --daemon
```

For a real installation, you'd want to run this as a service. TODO: add
instructions for doing this.

## 5. Enroll a passkey

As your normal user (not root), enroll a new passkey:

```bash
pam-paski enroll
```

This will display an enrollment URL. Open it in your browser, enter your
username, and register your passkey!

After your passkey is successfully registered, the daemon will store its public
key and metadata in your home directory in
`~/.config/pam-paski/enrolled_passkeys.json`.

## 5. Cockpit integration (experimental)

To use passkeys with the Cockpit web interface, you must inject the WebAuthn
interceptor into Cockpit's login page, and then configure the PAM stack.

> [!WARNING]
>
> This is experimental! Use at your own risk. It hasn't been thoroughly tested
> on all versions of Cockpit and may well break with your version, or when you
> update Cockpit.

### Inject the interceptor

```bash
sudo pam-paski install-cockpit
```

This command patches `/usr/share/cockpit/static/login.html` to intercept logins
and prompt your browser for passkeys. It automatically creates a backup
(`login.html.bak`) and is idempotent, so you can run it multiple times.

### Update Cockpit's PAM configuration

Edit the Cockpit PAM configuration file (`sudo nano /etc/pam.d/cockpit`).

You must add the following line to the **top** of the `auth` block:

```text
#%PAM-1.0
auth       sufficient   pam_paski.so  # <-- Add this line...
auth       required     pam_unix.so   # ...above whatever else in the auth section
```

> [!WARNING]
>
> You **MUST** use `sufficient` as the control flag! If you use `optional`, the
> PAM stack will continue to other options, which will instantly reject your
> empty password and fail the login.

## Usage

Navigate to your Cockpit URL, type your username, and hit "Log in" (leave the
password blank). Your browser will prompt you for your passkey.
