#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        Router,
        extract::Extension,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use ores_middleware::{
        AuthDecision, IntegrationError, MiddlewareOrderPolicy, MiddlewareOrderingRule,
        RequestMetadata, auth_provider_fn, validate_consumer_middleware_order,
    };
    use ores_middleware::frameworks::axum_composable::{AuthLayerState, authenticate};
    use tower::{ServiceBuilder, ServiceExt};

    #[derive(Clone)]
    struct ConsumerPinnedAuthSdkV7 {
        accepted_prefix: &'static str,
    }

    async fn identity(Extension(identity): Extension<AuthDecision>) -> String {
        format!(
            "{}:{}",
            identity.user_id.as_deref().unwrap_or("anonymous"),
            identity.tenant_id.as_deref().unwrap_or("none")
        )
    }

    fn provider() -> impl ores_middleware::StaticAuthVerifier {
        let sdk = ConsumerPinnedAuthSdkV7 { accepted_prefix: "sdk-v7:" };
        auth_provider_fn(move |request: RequestMetadata| {
            let sdk = sdk.clone();
            async move {
                let token = request.headers.get("authorization").cloned().ok_or_else(|| IntegrationError {
                    code: "missing_auth",
                    message: "authorization header is required".into(),
                })?;
                let subject = token.strip_prefix(sdk.accepted_prefix).map(ToOwned::to_owned).ok_or_else(|| IntegrationError {
                    code: "provider_rejected",
                    message: "consumer SDK v7 rejected token; private-key-id=42".into(),
                })?;
                Ok(AuthDecision {
                    user_id: Some(subject),
                    tenant_id: Some("tenant-consumer".into()),
                    claims: BTreeMap::new(),
                })
            }
        })
    }

    #[tokio::test]
    async fn consumer_owned_sdk_is_injected_without_ores_middleware_owning_its_version() {
        let state = AuthLayerState::from_provider(provider());
        let stack = ServiceBuilder::new().layer(middleware::from_fn_with_state(state, authenticate));
        let app = Router::new().route("/me", get(identity)).layer(stack);
        let response = app.oneshot(
            Request::builder().uri("/me").header("authorization", "sdk-v7:alice").body(axum::body::Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"alice:tenant-consumer");
    }

    #[tokio::test]
    async fn provider_failure_is_fail_closed_and_redacted() {
        let state = AuthLayerState::from_provider(provider());
        let app = Router::new().route("/me", get(identity)).layer(middleware::from_fn_with_state(state, authenticate));
        let response = app.oneshot(
            Request::builder().uri("/me").header("authorization", "bad-token").body(axum::body::Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("authentication_failed"));
        assert!(!body.contains("provider_rejected"));
        assert!(!body.contains("private-key-id=42"));
    }

    #[test]
    fn consumer_owns_middleware_order_policy() {
        let policy = MiddlewareOrderPolicy::new()
            .require("request-id")
            .require("company-auth-v7")
            .rule(MiddlewareOrderingRule::before(
                "request-id", "company-auth-v7", "request-id-before-auth",
                "this consumer wants correlation established before auth",
            ))
            .rule(MiddlewareOrderingRule::before(
                "company-auth-v7", "tenant-rate-limit", "auth-before-tenant-rate-limit",
                "this consumer derives its rate-limit key from authenticated identity",
            ));
        assert!(validate_consumer_middleware_order(
            &["request-id", "company-auth-v7", "tenant-rate-limit"], &policy
        ).is_empty());
        let issues = validate_consumer_middleware_order(
            &["request-id", "tenant-rate-limit", "company-auth-v7"], &policy
        );
        assert!(issues.iter().any(|issue| issue.code == "auth-before-tenant-rate-limit"));
    }
}
