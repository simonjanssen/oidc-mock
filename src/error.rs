use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openidconnect::core::CoreErrorResponseType;
use serde::Serialize;

/// Any error raised by the AS in its capacity as HTTP server when clients call it
#[derive(Debug)]
pub enum AuthServerError {
    Internal,
    BadAuthRequest(String),
    BadTokenRequest(String),
    InvalidGrant,
    InvalidClient,
    UnsupportedGrantType,
}

#[derive(Serialize)]
struct AuthServerErrorResponse {
    error: String,
}

impl IntoResponse for AuthServerError {
    fn into_response(self) -> Response {
        match self {
            AuthServerError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthServerErrorResponse {
                    error: "internal server error".to_string(),
                }),
            ),
            AuthServerError::BadAuthRequest(error) => (
                StatusCode::FORBIDDEN,
                Json(AuthServerErrorResponse { error }),
            ),
            AuthServerError::BadTokenRequest(error) => (
                StatusCode::FORBIDDEN,
                Json(AuthServerErrorResponse { error }),
            ),
            AuthServerError::InvalidGrant => (
                StatusCode::BAD_REQUEST,
                Json(AuthServerErrorResponse {
                    error: CoreErrorResponseType::InvalidGrant.to_string(),
                }),
            ),
            AuthServerError::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                Json(AuthServerErrorResponse {
                    error: CoreErrorResponseType::InvalidClient.to_string(),
                }),
            ),
            AuthServerError::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                Json(AuthServerErrorResponse {
                    error: CoreErrorResponseType::UnsupportedGrantType.to_string(),
                }),
            ),
        }
        .into_response()
    }
}

/// Any error raised by the AS in its capacity as type called inline
#[derive(Debug)]
pub enum AuthError {
    Any(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AuthError {}
