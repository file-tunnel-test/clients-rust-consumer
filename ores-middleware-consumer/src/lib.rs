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
        AuthDecision, AuthStage, IntegrationError, MiddlewareOrderPolicy, MiddlewareOrderingRule,
        RequestContext, RequestMetadata, StageDecision, StageInput, auth_provider_fn,
        dyn_auth_provider, validate_consumer_middleware_order,
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

    fn provider() -> impl ores_middleware::StaticAuthVerifier + ores_middleware::AuthVerifier {
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

    fn tenant_provider() -> impl ores_middleware::StaticAuthVerifier {
        auth_provider_fn(|request: RequestMetadata| async move {
            let token = request.headers.get("authorization").cloned().ok_or_else(|| IntegrationError {
                code: "missing_auth",
                message: "authorization header is required".into(),
            })?;
            let (tenant, user) = token.split_once(':').ok_or_else(|| IntegrationError {
                code: "malformed_auth",
                message: "expected tenant:user".into(),
            })?;
            Ok(AuthDecision {
                user_id: Some(user.to_owned()),
                tenant_id: Some(tenant.to_owned()),
                claims: BTreeMap::new(),
            })
        })
    }

    fn stage_input(token: &str) -> StageInput {
        StageInput::new(
            RequestMetadata {
                method: "GET".into(),
                path: "/account".into(),
                headers: BTreeMap::from([("authorization".into(), token.into())]),
                remote_ip: Some("127.0.0.1".into()),
                content_length: None,
                transport_secure: true,
            },
            RequestContext {
                request_id: "external-test-1".into(),
                trace_id: "0123456789abcdef0123456789abcdef".into(),
                span_id: None,
                tenant_id: None,
                user_id: None,
                locale: None,
                started_at_unix_ms: 0,
                deadline_unix_ms: None,
                baggage: BTreeMap::new(),
            },
        )
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

    #[tokio::test]
    async fn consumer_can_choose_dynamic_dispatch_at_the_same_axum_boundary() {
        let dynamic_provider = dyn_auth_provider(provider());
        let state = AuthLayerState::from_provider(dynamic_provider);
        let app = Router::new().route("/me", get(identity)).layer(
            middleware::from_fn_with_state(state, authenticate),
        );
        let response = app.oneshot(
            Request::builder().uri("/me").header("authorization", "sdk-v7:runtime-user").body(axum::body::Body::empty()).unwrap(),
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"runtime-user:tenant-consumer");
    }

    #[tokio::test]
    async fn concurrent_requests_keep_consumer_tenant_identity_isolated() {
        let state = AuthLayerState::from_provider(tenant_provider());
        let app = Router::new().route("/me", get(identity)).layer(
            middleware::from_fn_with_state(state, authenticate),
        );

        let tenant_a = app.clone().oneshot(
            Request::builder().uri("/me").header("authorization", "tenant-a:alice").body(axum::body::Body::empty()).unwrap(),
        );
        let tenant_b = app.oneshot(
            Request::builder().uri("/me").header("authorization", "tenant-b:bob").body(axum::body::Body::empty()).unwrap(),
        );
        let (tenant_a, tenant_b) = tokio::join!(tenant_a, tenant_b);

        let tenant_a = tenant_a.unwrap();
        let tenant_b = tenant_b.unwrap();
        assert_eq!(tenant_a.status(), StatusCode::OK);
        assert_eq!(tenant_b.status(), StatusCode::OK);
        let tenant_a = axum::body::to_bytes(tenant_a.into_body(), usize::MAX).await.unwrap();
        let tenant_b = axum::body::to_bytes(tenant_b.into_body(), usize::MAX).await.unwrap();
        assert_eq!(tenant_a.as_ref(), b"alice:tenant-a");
        assert_eq!(tenant_b.as_ref(), b"bob:tenant-b");
    }

    #[tokio::test]
    async fn auth_stage_keeps_external_consumer_provider_concrete_and_updates_context() {
        let stage = AuthStage::from_provider("external-auth", provider());
        match stage.evaluate(stage_input("sdk-v7:stage-user")).await {
            StageDecision::Continue(input) => {
                assert_eq!(input.context.user_id.as_deref(), Some("stage-user"));
                assert_eq!(input.context.tenant_id.as_deref(), Some("tenant-consumer"));
                assert!(input.context.baggage.is_empty());
                assert!(input.attributes.is_empty());
            }
            _ => panic!("external auth stage should continue"),
        }
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
