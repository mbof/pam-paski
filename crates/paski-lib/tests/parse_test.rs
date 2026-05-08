use paski_lib::credentials::CredentialStore;

#[test]
fn test_parse() {
    let json = r#"{
  "passkeys": [
    {
      "passkey": {
        "cred": {
          "cred_id": "GdGSsni8gwxFElr81hAlsTDaMkyc2fiY-Uj0J4MK8pc",
          "cred": {
            "type_": "ES256",
            "key": {
              "EC_EC2": {
                "curve": "SECP256R1",
                "x": "VuNA1-Z9BdebbsLSAU-QEOy2MJBvV4nmsztnzLDq2AQ",
                "y": "OjRIlMcC4QDfBJg3W-p8d6hOpPbomYnTKeHrWs4dfmw"
              }
            }
          },
          "counter": 0,
          "transports": null,
          "user_verified": true,
          "backup_eligible": false,
          "backup_state": false,
          "registration_policy": "required",
          "extensions": {
            "cred_protect": "Ignored",
            "hmac_create_secret": "NotRequested",
            "appid": "NotRequested",
            "cred_props": {
              "Unsigned": {
                "rk": true
              }
            }
          },
          "attestation": {
            "data": "None",
            "metadata": "None"
          },
          "attestation_format": "none"
        }
      },
      "name": "user",
      "enrolled_at": "2026-05-07T07:54:31.650436430Z",
      "last_used": "2026-05-08T05:18:08.082257712Z"
    },
    {
      "passkey": {
        "cred": {
          "cred_id": "AeY4k4MKuFBL8qMeHCssrm6donXiBcZTGtMgMI2O4ECgFaMHk3vcJcFST0GrOmUpbV25PiUdU9FgvNn_cqAQC-Q",
          "cred": {
            "type_": "ES256",
            "key": {
              "EC_EC2": {
                "curve": "SECP256R1",
                "x": "TRc6AkoilCcPPh2ms2thUT64eQCARwAQhIa2D9n_Jpg",
                "y": "_pGINq8Aua47yZmvhxW1OClX5cW5VpKLJqrOs05woXE"
              }
            }
          },
          "counter": 3,
          "transports": null,
          "user_verified": true,
          "backup_eligible": false,
          "backup_state": false,
          "registration_policy": "required",
          "extensions": {
            "cred_protect": "Ignored",
            "hmac_create_secret": "NotRequested",
            "appid": "NotRequested",
            "cred_props": {
              "Unsigned": {
                "rk": false
              }
            }
          },
          "attestation": {
            "data": "None",
            "metadata": "None"
          },
          "attestation_format": "none"
        }
      },
      "name": "phone",
      "enrolled_at": "2026-05-08T00:51:02.450587433Z",
      "last_used": "2026-05-08T05:41:08.504693872Z"
    }
  ]
}"#;
    let store: CredentialStore = serde_json::from_str(json).unwrap();
    assert_eq!(store.passkeys.len(), 2);
}
