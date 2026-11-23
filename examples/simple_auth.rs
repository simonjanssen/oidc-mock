use anyhow::Error;
use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use http_body_util::BodyExt;
use oidc_mock::AuthServer;
use serde::Deserialize;
use tower::ServiceExt;
use url::Url;

mod common;

use common::app::{AppState, AuthenticatedPrincipal};

use crate::common::config::{TEST_AUDIENCE, TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_USER};

/// This could be your server implementation
async fn simple_axum_app(issuer_url: Url) -> axum::Router {
    // Protected server route
    async fn me(principal: AuthenticatedPrincipal) -> Json<AuthenticatedPrincipal> {
        Json(principal)
    }

    let state = AppState { issuer_url };

    axum::Router::new()
        .route("/user/me", get(me))
        .with_state(state)
}

/// This could be your cargo test
#[tokio::main]
async fn main() -> Result<(), Error> {
    // build the authorization server mock
    let auth_server = AuthServer::builder()
        .aud(TEST_AUDIENCE.to_string())
        .subject(TEST_USER.to_string())
        .client(TEST_CLIENT_ID.to_string(), TEST_CLIENT_SECRET.to_string())
        .build()
        .await?;
    let issuer_url = auth_server.base_url(); // in production that would be a real identity provider (Keycloak, Auth0, ...)

    // create your app and let it point to the upstream issuer url (same as in production)
    let app = simple_axum_app(issuer_url.to_owned()).await;

    // generate a valid access_token
    let access_token = auth_server.access_token()?;

    // execise your axum app -> calls auth server -> validates token
    let response = app
        .oneshot(
            Request::builder()
                .uri("/user/me")
                .header("Authorization", format!("Bearer {}", access_token))
                .body(Body::empty())?,
        )
        .await?;

    // verify it's response
    assert_eq!(response.status(), StatusCode::OK);

    #[derive(Deserialize)]
    struct User {
        sub: String,
    }
    let response_bytes = response.into_body().collect().await?.to_bytes();
    let user: User = serde_json::from_slice(&response_bytes).unwrap();
    assert_eq!(user.sub, "test-user");

    Ok(())
}
