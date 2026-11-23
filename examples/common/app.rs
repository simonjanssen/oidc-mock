use anyhow::Error;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata, reqwest};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::config::TEST_AUDIENCE;

/// This could be your server state
#[derive(Clone)]
pub struct AppState {
    pub issuer_url: Url,
}

/// What you need as information from an access_token
#[derive(Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,
}

/// This could be your auth middleware to protect routes
#[derive(Debug, Serialize)]
pub struct AuthenticatedPrincipal {
    pub sub: String,
}

/// Fetch the AS's public keys to validate access_tokens.
/// With the OIDC mock in place your app runs OIDC discovery as in production.
async fn fetch_jwks(issuer_url: Url) -> Result<JwkSet, Error> {
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let issuer_url = IssuerUrl::from_url(issuer_url);

    // run OIDC discovery - fetches JWKs
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

    // load JWKs
    let oidc_jwks = provider_metadata.jwks();
    let jwks_data = serde_json::to_value(oidc_jwks)?;
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwks_data)?;

    Ok(jwks)
}

impl FromRequestParts<AppState> for AuthenticatedPrincipal {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // in production, you'd want to cache this instead of re-fetching at every request
        let Ok(jwks) = fetch_jwks(state.issuer_url.clone()).await else {
            return Err(StatusCode::BAD_GATEWAY);
        };

        let header = jsonwebtoken::decode_header(token).map_err(|_err| StatusCode::UNAUTHORIZED)?;
        let kid = header.kid.ok_or(StatusCode::UNAUTHORIZED)?;
        let jwk = jwks.find(&kid).ok_or(StatusCode::UNAUTHORIZED)?;
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut jwt_claims = Validation::new(Algorithm::RS256);
        jwt_claims.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        jwt_claims.set_issuer(std::slice::from_ref(&state.issuer_url));
        jwt_claims.set_audience(&[TEST_AUDIENCE]);

        let data = jsonwebtoken::decode::<AccessTokenClaims>(&token, &decoding_key, &jwt_claims)
            .map_err(|_err| StatusCode::UNAUTHORIZED)?;

        Ok(Self {
            sub: data.claims.sub,
        })
    }
}
