use anyhow::{Error, anyhow};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use chrono::{Duration, Utc};
use openidconnect::{
    AccessToken, Audience, AuthUrl, ClientId, ClientSecret, EmptyAdditionalClaims, IssuerUrl,
    JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl, Nonce, PrivateSigningKey, RedirectUrl,
    StandardClaims, SubjectIdentifier, TokenUrl,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
    url::Url,
};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};

use crate::{
    error::AuthError,
    factory::{PATH_AUTHORIZE, PATH_JWKS, PATH_TOKEN},
};

// --- Helpers ---

/// Generate a new random private key in PEM-format
fn generate_pem() -> String {
    let private_key =
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("Failed to generate RSA key");
    private_key
        .to_pkcs1_pem(Default::default())
        .expect("Failed to encode private key")
        .to_string()
}

/// Convert to RSA signing key (the AS's secret to mint tokens)
fn generate_signing_key(pem: &str) -> CoreRsaPrivateSigningKey {
    let kid = JsonWebKeyId::new("key1".to_string());
    CoreRsaPrivateSigningKey::from_pem(pem, Some(kid)).expect("Invalid PEM")
}

#[cfg(test)]
#[test]
fn generated_pem_is_valid_signing_key() {
    generate_signing_key(&generate_pem());
}

/// Generate public JWKs for private signing key (hosted via jwks_uri)
fn generate_jwks(signing_key: CoreRsaPrivateSigningKey) -> JsonWebKeySet<CoreJsonWebKey> {
    CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()])
}

pub(crate) struct AuthServerStateBuilder {
    url: Option<Url>,
    aud: Option<String>,
    sub: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl AuthServerStateBuilder {
    pub fn new() -> Self {
        Self {
            aud: None,
            url: None,
            sub: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn url(self, url: Url) -> Self {
        Self {
            url: Some(url),
            ..self
        }
    }

    pub fn aud(self, aud: String) -> Self {
        Self {
            aud: Some(aud),
            ..self
        }
    }

    pub fn sub(self, sub: String) -> Self {
        Self {
            sub: Some(sub),
            ..self
        }
    }

    pub fn client_id(self, id: String) -> Self {
        Self {
            client_id: Some(id),
            ..self
        }
    }

    pub fn client_secret(self, secret: String) -> Self {
        Self {
            client_secret: Some(secret),
            ..self
        }
    }

    pub fn build(self) -> Result<AuthServerState, Error> {
        let pem = generate_pem();
        let signing_key = generate_signing_key(&pem);
        let jwks = generate_jwks(generate_signing_key(&pem));
        let url = self.url.ok_or(anyhow!("server url must be set"))?;
        let aud = self.aud.ok_or(anyhow!("audience must be set"))?;
        let sub = self.sub.ok_or(anyhow!("sub must be set"))?;
        let client_id = self.client_id.ok_or(anyhow!("client_id must be set"))?;
        let client_secret = self
            .client_secret
            .ok_or(anyhow!("client_secret must be set"))?;
        Ok(AuthServerState {
            signing_key: Arc::new(signing_key),
            jwks,
            issuer_url: IssuerUrl::from_url(url.clone()),
            audiences: vec![Audience::new(aud)],
            auth_url: AuthUrl::from_url(url.join(PATH_AUTHORIZE)?),
            jwks_url: JsonWebKeySetUrl::from_url(url.join(PATH_JWKS)?),
            token_url: TokenUrl::from_url(url.join(PATH_TOKEN)?),
            sub,
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            grants: Arc::default(),
        })
    }
}

pub(crate) struct AuthGrant {
    pub challenge: String,
    pub nonce: Nonce,
    pub client_id: ClientId,
    pub redirect_uri: RedirectUrl,
}

#[derive(Clone)]
pub(crate) struct AuthServerState {
    pub signing_key: Arc<CoreRsaPrivateSigningKey>,
    pub jwks: JsonWebKeySet<CoreJsonWebKey>,
    pub issuer_url: IssuerUrl,
    pub audiences: Vec<Audience>,
    pub auth_url: AuthUrl,
    pub jwks_url: JsonWebKeySetUrl,
    pub token_url: TokenUrl,
    pub sub: String,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,

    pub grants: Arc<RwLock<HashMap<String, AuthGrant>>>,
}

impl AuthServerState {
    pub fn builder() -> AuthServerStateBuilder {
        AuthServerStateBuilder::new()
    }

    /// Generate valid token claims for this AS
    pub fn token_claims(&self) -> CoreIdTokenClaims {
        CoreIdTokenClaims::new(
            self.issuer_url.clone(),
            self.audiences.clone(),
            Utc::now() + Duration::minutes(5),
            Utc::now(),
            StandardClaims::new(SubjectIdentifier::new(self.sub.clone())),
            EmptyAdditionalClaims {},
        )
    }

    /// Sign token claims with the AS private key
    pub fn sign_token(
        &self,
        claims: CoreIdTokenClaims,
        access_token: Option<&AccessToken>,
    ) -> Result<CoreIdToken, AuthError> {
        let id_token = CoreIdToken::new(
            claims,
            self.signing_key.as_ref(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            access_token,
            None,
        )
        .map_err(|err| AuthError::Any(err.to_string()))?;
        Ok(id_token)
    }

    /// Encode as JWT String
    pub fn encode_token(
        &self,
        claims: CoreIdTokenClaims,
        access_token: Option<&AccessToken>,
    ) -> Result<String, AuthError> {
        Ok(self.sign_token(claims, access_token)?.to_string())
    }

    /// Generate a valid access_token for this AS
    pub fn access_token(&self) -> Result<String, AuthError> {
        self.encode_token(self.token_claims(), None)
    }

    /// Generate a valid id_token for this AS
    pub fn id_token(
        &self,
        access_token: &AccessToken,
        client_id: Option<ClientId>,
        nonce: Option<Nonce>,
    ) -> Result<String, AuthError> {
        let claims = self.token_claims().set_nonce(nonce);
        let claims = if let Some(client_id) = client_id {
            claims.set_audiences(vec![Audience::new(client_id.into())])
        } else {
            claims
        };
        self.encode_token(claims, Some(access_token))
    }
}
