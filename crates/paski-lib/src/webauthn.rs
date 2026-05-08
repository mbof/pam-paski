use anyhow::{Context, Result};
use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::*;

use crate::config::Config;

/// Create a Webauthn instance from our configuration.
pub fn create_webauthn(config: &Config) -> Result<Arc<Webauthn>> {
    let rp_id = &config.relying_party.id;
    let rp_name = &config.relying_party.name;

    // Parse the first allowed origin as the primary origin.
    let rp_origin = config
        .relying_party
        .origins
        .first()
        .context("No origins configured in relying_party.origins")?;
    let rp_origin_url =
        Url::parse(rp_origin).with_context(|| format!("Invalid origin URL: {rp_origin}"))?;

    let mut builder = WebauthnBuilder::new(rp_id, &rp_origin_url)
        .context("Failed to create WebauthnBuilder")?
        .rp_name(rp_name);

    // Add additional allowed origins if configured.
    for origin_str in config.relying_party.origins.iter().skip(1) {
        if let Ok(origin_url) = Url::parse(origin_str) {
            builder = builder.append_allowed_origin(&origin_url);
        }
    }

    let webauthn = builder
        .build()
        .context("Failed to build Webauthn instance")?;
    Ok(Arc::new(webauthn))
}
