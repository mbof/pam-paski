// PAM module for pam-paski
//
// This crate only compiles on Linux where PAM headers are available.
// It produces a `pam_paski.so` shared library that plugs into the
// Linux PAM authentication stack.
//
// The authentication flow uses PAM conversation to shuttle WebAuthn
// challenge/response data between the PAM module and the web frontend.
//
// Protocol:
//   1. PAM module sends a challenge via pam_conv:
//      "PASKI:{json with challenge, rpId, allowCredentials}"
//   2. The web frontend (e.g. Cockpit's custom login.html) detects
//      the PASKI: prefix, calls navigator.credentials.get(), and
//      sends the assertion back as the conversation response:
//      "PASKI:{json with assertion}"
//   3. PAM module verifies the assertion and returns PAM_SUCCESS or PAM_AUTH_ERR.

#[cfg(target_os = "linux")]
mod linux {
    // TODO: Implement PAM module using the `pam` crate.
    // This will be Phase 3 of the implementation.
    //
    // Key functions to implement:
    //   - pam_sm_authenticate: generate challenge, verify assertion
    //   - pam_sm_setcred: no-op (return PAM_SUCCESS)
    //
    // The PAM conversation function is used to:
    //   1. Send the WebAuthn challenge to the frontend
    //   2. Receive the WebAuthn assertion from the frontend
    //
    // Credential lookup:
    //   - Get the username from PAM
    //   - Look up the user's home directory
    //   - Load ~/.config/pam-paski/enrolled_passkeys.json
    //   - If no passkeys found, return PAM_AUTHINFO_UNAVAIL (fall through)
}

// Stub so the crate compiles (empty) on non-Linux.
#[cfg(not(target_os = "linux"))]
fn _stub() {}
