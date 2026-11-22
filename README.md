# oidc-mock

> Mock an upstream authorization server to `cargo test` your application's OIDC / OAuth 2.0 flows.

In the [OAuth 2.0 authorization framework](https://www.rfc-editor.org/rfc/rfc6749), this crate (added as a dev-dependency) acts as the **authorization server** (AS, also known as identity provider, IdP, or OpenID Provider, OP). The code under test acts as the **client** (OIDC: relying party) and/or **resource server** (a "backend" or "API").

This is _not_ a full-fledged authorization server to run standalone; it is meant to be embedded in your tests.

## Usage

```toml
[dev-dependencies]
oidc-mock = "0.1"
tokio = { version = "1", features = ["macros", "rt"] }
```

```rust,ignore
use oidc_mock::AuthServer;

#[tokio::test]
async fn protected_route_accepts_valid_token() -> anyhow::Result<()> {
    // 1. Start the mock AS (binds to a random local port)
    let auth_server = AuthServer::builder()
        .aud("my-api".to_string())
        .subject("alice".to_string())
        .client("my-client".to_string(), "my-secret".to_string())
        .build()
        .await?;

    // 2. Point your app at it as its issuer (it fetches discovery + JWKS from here)
    let app = my_app::build(auth_server.base_url().clone()).await?;

    // 3. Mint a valid token and call your protected endpoint
    let token = auth_server.access_token()?;
    // ... send a request with `Authorization: Bearer {token}`, assert 200

    Ok(())
}
```

`build()` spawns the server on the current tokio runtime, so call it from `#[tokio::test]`.


## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
