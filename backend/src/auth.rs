use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use sqlx::query;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::AppState;

// Helper functions for OffsetDateTime serialization
fn serialize_time<S>(time: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = time.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&s)
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom)
}

pub const TOKEN_HEADER: &str = "X-Auth-Token";
pub const TOKEN_EXPIRY_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    #[serde(serialize_with = "serialize_time", deserialize_with = "deserialize_time")]
    pub created_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time", deserialize_with = "deserialize_time")]
    pub expires_at: OffsetDateTime,
    pub is_revoked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Error hashing password: {}", e))
}

// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| format!("Error parsing hash: {}", e))?;
    
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

// Generate a new auth token for a user
pub async fn generate_token(
    user_id: i64,
    state: &AppState,
) -> Result<AuthToken, (StatusCode, Json<ApiError>)> {
    let token = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::days(TOKEN_EXPIRY_DAYS);
    
    // Insert the token first
    let token_id = query!(
        r#"
        INSERT INTO auth_tokens (user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        "#,
        user_id,
        token,
        now,
        expires_at
    )
    .execute(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Failed to create auth token: {}", e),
            }),
        )
    })?
    .last_insert_rowid();

    // Then query for the created token
    let result = query!(
        r#"
        SELECT id, user_id, token, created_at, expires_at, is_revoked
        FROM auth_tokens
        WHERE id = ?
        "#,
        token_id
    )
    .fetch_one(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Failed to create auth token: {}", e),
            }),
        )
    })?;
    
    Ok(AuthToken {
        id: result.id,
        user_id: result.user_id,
        token: result.token,
        created_at: result.created_at,
        expires_at: result.expires_at,
        is_revoked: result.is_revoked == false,
    })
}

// Authenticate a user from a token in the request headers
pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

// Extractor for getting the authenticated user from a request
pub struct AuthUser(pub User);

// #[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from headers
        let token = extract_token_from_headers(&parts.headers)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiError {
                        error: "Missing authentication token".to_string(),
                    }),
                )
                    .into_response()
            })?;

        // Get app state
        let app_state = AppState::from_ref(state);

        // Verify the token in the database
        let user = query!(
            r#"
            SELECT u.id, u.username
            FROM users u
            JOIN auth_tokens t ON u.id = t.user_id
            WHERE t.token = ?
              AND t.is_revoked = 0
            "#,
            token
        )
        .fetch_optional(app_state.db_pool.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Database error: {}", e),
                }),
            )
                .into_response()
        })?;

        let user = user.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "Invalid or expired token".to_string(),
                }),
            )
                .into_response()
        })?;

        Ok(AuthUser(User {
            id: user.id,
            username: user.username,
        }))
    }
}