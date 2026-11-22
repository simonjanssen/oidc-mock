use anyhow::{Error, anyhow};
use openidconnect::{AccessToken, ClientId, Nonce, core::CoreIdTokenClaims, url::Url};
use std::net::SocketAddr;
use tokio::net::TcpListener;

use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    error::AuthError,
    server::{authorize, jwks, oidc_discovery, token},
    state::AuthServerState,
};

pub(crate) const PATH_OPENID_CONFIG: &str = "/.well-known/openid-configuration";
pub(crate) const PATH_JWKS: &str = "/jwks";
pub(crate) const PATH_TOKEN: &str = "/token";
pub(crate) const PATH_AUTHORIZE: &str = "/authorize";

pub struct AuthServerBuilder {
    aud: Option<String>,
    sub: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl AuthServerBuilder {
    pub fn new() -> Self {
        Self {
            aud: None,
            sub: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn aud(self, aud: String) -> Self {
        Self {
            aud: Some(aud),
            ..self
        }
    }

    pub fn subject(self, sub: String) -> Self {
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

    pub fn client(self, id: String, secret: String) -> Self {
        Self {
            client_id: Some(id),
            client_secret: Some(secret),
            ..self
        }
    }

    pub fn sabotage_at_hash(self) -> Self {
        todo!(
            "let the mock return a different access_token than the one it put into the id-tokens at_hash"
        )
    }

    pub fn sabotage_id_token(self) -> Self {
        todo!("let the mock return invalid id tokens: wrong iss, aud, bad signature, missing")
    }

    pub async fn build(self) -> Result<AuthServer, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let url = Url::parse(&format!("http://{addr}"))?;
        let aud = self.aud.ok_or(anyhow!("audience must be set"))?;
        let sub = self.sub.ok_or(anyhow!("sub must be set"))?;
        let client_id = self.client_id.ok_or(anyhow!("client_id must be set"))?;
        let client_secret = self
            .client_secret
            .ok_or(anyhow!("client_secret must be set"))?;
        let state = AuthServerState::builder()
            .url(url)
            .aud(aud)
            .sub(sub)
            .client_id(client_id)
            .client_secret(client_secret)
            .build()?;
        let router = Router::new()
            .route(PATH_OPENID_CONFIG, get(oidc_discovery))
            .route(PATH_JWKS, get(jwks))
            .route(PATH_AUTHORIZE, get(authorize))
            .route(PATH_TOKEN, post(token))
            .with_state(state.clone());

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(AuthServer { state })
    }
}

impl Default for AuthServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AuthServer {
    state: AuthServerState,
}

impl AuthServer {
    pub fn builder() -> AuthServerBuilder {
        AuthServerBuilder::new()
    }

    /// AS base url (pass it to your app)
    pub fn base_url(&self) -> &Url {
        self.state.issuer_url.url()
    }

    /// Generate valid token claims for this AS
    pub fn token_claims(&self) -> CoreIdTokenClaims {
        self.state.token_claims()
    }

    /// Encode as access_token
    pub fn encode_as_access_token(&self, claims: CoreIdTokenClaims) -> Result<String, AuthError> {
        self.state.encode_token(claims, None)
    }

    /// Encode as id_token
    pub fn encode_as_id_token(
        &self,
        claims: CoreIdTokenClaims,
        access_token: Option<&AccessToken>,
    ) -> Result<String, AuthError> {
        self.state.encode_token(claims, access_token)
    }

    /// Generate a valid access_token for this AS
    pub fn access_token(&self) -> Result<String, AuthError> {
        self.state.access_token()
    }

    /// Generate a valid id_token for this AS
    pub fn id_token(
        &self,
        access_token: &AccessToken,
        client_id: Option<ClientId>,
        nonce: Option<Nonce>,
    ) -> Result<String, AuthError> {
        self.state.id_token(access_token, client_id, nonce)
    }
}
