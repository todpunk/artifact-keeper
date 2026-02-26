//! gRPC authentication interceptor.
//!
//! Validates JWT tokens from the `authorization` metadata field on all gRPC requests.
//! After validation, injects `x-user-id` and `x-is-admin` metadata keys so that
//! individual handlers can enforce authorization without re-decoding the token.

use jsonwebtoken::{decode, DecodingKey, Validation};
use tonic::metadata::MetadataValue;
use tonic::{Request, Status};

use crate::services::auth_service::Claims;

/// gRPC auth interceptor that validates JWT Bearer tokens.
#[derive(Clone)]
pub struct AuthInterceptor {
    decoding_key: DecodingKey,
}

impl AuthInterceptor {
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn intercept(&self, mut req: Request<()>) -> Result<Request<()>, Status> {
        // Extract the bearer token as an owned String so the immutable borrow on
        // `req` is released before we take `req.metadata_mut()` below.
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned())
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization token"))?;

        let token_data = decode::<Claims>(&token, &self.decoding_key, &Validation::default())
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        if token_data.claims.token_type != "access" {
            return Err(Status::unauthenticated("Invalid token type"));
        }

        // Inject user context into request metadata so handlers can enforce
        // authorization without re-decoding the JWT.
        let user_id = token_data.claims.sub.to_string();
        let metadata = req.metadata_mut();
        metadata.insert(
            "x-user-id",
            MetadataValue::try_from(user_id.as_str())
                .map_err(|_| Status::internal("Failed to encode user ID"))?,
        );
        metadata.insert(
            "x-is-admin",
            if token_data.claims.is_admin {
                MetadataValue::from_static("true")
            } else {
                MetadataValue::from_static("false")
            },
        );

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tonic::Request;
    use uuid::Uuid;

    fn make_token(secret: &str, is_admin: bool, token_type: &str) -> String {
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            iat: 0,
            exp: i64::MAX,
            token_type: token_type.to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn make_request(token: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    #[test]
    fn test_intercept_injects_user_id_and_is_admin_false() {
        let secret = "test-secret";
        let interceptor = AuthInterceptor::new(secret);
        let token = make_token(secret, false, "access");
        let req = make_request(&token);

        let result = interceptor.intercept(req).unwrap();

        let meta = result.metadata();
        assert!(
            meta.get("x-user-id").is_some(),
            "x-user-id should be injected"
        );
        let is_admin = meta.get("x-is-admin").unwrap().to_str().unwrap();
        assert_eq!(is_admin, "false");
    }

    #[test]
    fn test_intercept_injects_is_admin_true() {
        let secret = "test-secret";
        let interceptor = AuthInterceptor::new(secret);
        let token = make_token(secret, true, "access");
        let req = make_request(&token);

        let result = interceptor.intercept(req).unwrap();

        let is_admin = result
            .metadata()
            .get("x-is-admin")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(is_admin, "true");
    }

    #[test]
    fn test_intercept_rejects_missing_token() {
        let interceptor = AuthInterceptor::new("secret");
        let req = Request::new(());
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_intercept_rejects_refresh_token() {
        let secret = "test-secret";
        let interceptor = AuthInterceptor::new(secret);
        let token = make_token(secret, false, "refresh");
        let req = make_request(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_intercept_rejects_invalid_signature() {
        let token = make_token("correct-secret", false, "access");
        let interceptor = AuthInterceptor::new("wrong-secret");
        let req = make_request(&token);
        let err = interceptor.intercept(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
