use axum::{Form, Json, extract::State, response::Redirect};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Basic},
};
use openidconnect::{
    AccessToken, Audience, ClientId, EmptyAdditionalProviderMetadata, EmptyExtraTokenFields,
    JsonWebKeySet, Nonce, PkceCodeChallenge, PkceCodeChallengeMethod, PkceCodeVerifier,
    RedirectUrl, ResponseTypes, Scope,
    core::{
        CoreGrantType, CoreIdTokenFields, CoreJsonWebKey, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType, CoreTokenResponse,
        CoreTokenType,
    },
    url::Url,
};
use rand::Rng;
use serde::Deserialize;
use tracing::warn;

use crate::{
    error::AuthServerError,
    state::{AuthGrant, AuthServerState},
};

/// Generate code
fn generate_code() -> String {
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a single form-urlencoded component (`+` → space, `%XX` → byte)
fn form_decode(s: &str) -> String {
    openidconnect::url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, _)| k)
        .collect()
}

/// OIDC discovery endpoint
pub(crate) async fn oidc_discovery(
    State(state): State<AuthServerState>,
) -> Result<Json<CoreProviderMetadata>, AuthServerError> {
    let metadata = CoreProviderMetadata::new(
        state.issuer_url,
        state.auth_url,
        state.jwks_url,
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(state.token_url))
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        Scope::new("email".to_string()),
        Scope::new("profile".to_string()),
    ]));

    Ok(Json(metadata))
}

/// JWKs endpoint returning the AS's public keys
pub(crate) async fn jwks(
    State(state): State<AuthServerState>,
) -> Result<Json<JsonWebKeySet<CoreJsonWebKey>>, AuthServerError> {
    Ok(Json(state.jwks))
}

/// Token endpoint requests
#[derive(Deserialize)]
pub(crate) struct AuthorizationRequest {
    response_type: String,
    client_id: ClientId,
    state: String,
    code_challenge: String,
    code_challenge_method: PkceCodeChallengeMethod,
    redirect_uri: RedirectUrl,
    scope: Scope,
    audience: Audience,
    nonce: Nonce,
}

/// Authorization endpoint
/// SECURITY: calling this and being logged in without providing credentials is of course totally insecure.
pub(crate) async fn authorize(
    State(state): State<AuthServerState>,
    Form(request): Form<AuthorizationRequest>,
) -> Result<Redirect, AuthServerError> {
    if request.response_type != "code" {
        return Err(AuthServerError::BadAuthRequest(
            "response_type not allowed".into(),
        ));
    }

    if *request.code_challenge_method != "S256" {
        return Err(AuthServerError::BadAuthRequest(
            "code_challenge_method not allowed".into(),
        ));
    }

    if state.client_id != request.client_id {
        return Err(AuthServerError::BadAuthRequest("client not allowed".into()));
    }

    if !state.audiences.contains(&request.audience) {
        return Err(AuthServerError::BadAuthRequest(
            "audience not allowed".into(),
        ));
    }

    if !request.scope.contains("openid") {
        return Err(AuthServerError::BadAuthRequest(
            "missing openid scope".into(),
        ));
    }

    let code = generate_code();
    let Ok(mut redirect_uri) = Url::parse(&request.redirect_uri) else {
        return Err(AuthServerError::BadAuthRequest(
            "invalid redirect_uri".into(),
        ));
    };
    redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request.state);

    let grant = AuthGrant {
        challenge: request.code_challenge,
        nonce: request.nonce,
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
    };

    {
        let Ok(mut guard) = state.grants.write() else {
            return Err(AuthServerError::Internal);
        };
        guard.insert(code, grant);
    }

    Ok(Redirect::to(redirect_uri.as_str()))
}

/// Token endpoint requests
#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    grant_type: CoreGrantType,
    code: String,
    code_verifier: PkceCodeVerifier,
    redirect_uri: RedirectUrl,
}

/// Token endpoint
pub(crate) async fn token(
    State(state): State<AuthServerState>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<CoreTokenResponse>, AuthServerError> {
    // oauth2's default is basic auth
    let Some(TypedHeader(Authorization(basic))) = auth else {
        return Err(AuthServerError::InvalidClient);
    };
    // RFC 6749 §2.3.1: id and secret are form-urlencoded before base64
    let username = form_decode(basic.username());
    let password = form_decode(basic.password());

    if *state.client_id != username {
        return Err(AuthServerError::InvalidClient);
    }

    if *state.client_secret.secret() != password {
        return Err(AuthServerError::InvalidClient);
    }

    if request.grant_type != CoreGrantType::AuthorizationCode {
        return Err(AuthServerError::BadTokenRequest(format!(
            "grant_type not allowed: {}",
            request.grant_type.as_ref()
        )));
    }

    let grant = {
        let Ok(mut guard) = state.grants.write() else {
            return Err(AuthServerError::Internal);
        };
        guard.remove(&request.code)
    };

    let Some(grant) = grant else {
        return Err(AuthServerError::InvalidGrant);
    };

    // we check against the grant not the state (was this code issued to this client?)
    if *grant.client_id != username {
        return Err(AuthServerError::InvalidClient);
    }

    if grant.redirect_uri != request.redirect_uri {
        return Err(AuthServerError::InvalidGrant);
    }

    // PkceCodeChallenge::from_code_verifier_sha256() panics if not 43..128 characters long
    if !(43..=128).contains(&request.code_verifier.secret().len()) {
        return Err(AuthServerError::InvalidGrant);
    }
    let request_challenge = PkceCodeChallenge::from_code_verifier_sha256(&request.code_verifier);
    if grant.challenge != request_challenge.as_str() {
        return Err(AuthServerError::InvalidGrant);
    }

    let access_token = match state.access_token() {
        Ok(token) => AccessToken::new(token),
        Err(err) => {
            warn!("failed to generate access token: {}", err);
            return Err(AuthServerError::Internal);
        }
    };

    let id_token_claims = state
        .token_claims()
        .set_nonce(Some(grant.nonce))
        // the grant's client id is the audience for id-tokens
        .set_audiences(vec![Audience::new(grant.client_id.into())]);
    let id_token = match state.sign_token(id_token_claims, Some(&access_token)) {
        Ok(token) => token,
        Err(err) => {
            warn!("failed to generate id token: {}", err);
            return Err(AuthServerError::Internal);
        }
    };

    Ok(Json(CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    )))
}
