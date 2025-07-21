use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use common::{
    ApiError, AuthResponse, LoginRequest, SignupRequest, Conversation, ConversationsResponse,
};
use reqwest::Client;
use sqlx::{migrate::MigrateDatabase, query, sqlite::SqlitePoolOptions, Sqlite};
use std::{path::Path, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod auth;
mod appstate;
mod websocket;
use auth::{generate_token, hash_password, verify_password};
use appstate::AppState;

use crate::websocket::websocket_handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Ollama frontend server");
    let db_path = "database.db";
    let db_url = format!("sqlite://{}", db_path);

    // Check if the database file exists
    if !Path::new(db_path).exists() {
        // Create the database file
        Sqlite::create_database(&db_url).await?;
    }

    // Create a connection pool
    let db_pool = SqlitePoolOptions::new().connect(&db_url).await?;

    // Apply migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;

    // Your application logic here

    // Set up CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create shared client
    // let client = Arc::new(Client::new());
    let client = Client::new();
    let arced_db_pool = Arc::new(db_pool);
    // Build the router
    let app = Router::new()
        .route("/ws", get(websocket_handler))
        .route("/api/auth/signup", post(signup_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/logout", post(logout_handler))
        .route("/api/conversations", get(get_conversations_handler))
        .layer(cors)
        .with_state(AppState::new(client, arced_db_pool));

    // Start the server
    let listener = tokio::net::TcpListener::bind("localhost:3000")
        .await
        .unwrap();
    info!("Listening on http://localhost:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

// Authentication handlers
async fn signup_handler(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<ApiError>)> {
    // Validate username and password
    info!("Received signup request for username: {}", req.username);
    if req.username.trim().is_empty() || req.username.len() < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "Username must be at least 1 character".to_string(),
            }),
        ));
    }

    if req.password.len() < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "Password must be at least 1 character".to_string(),
            }),
        ));
    }

    // Check if username already exists
    let existing_user = query!("SELECT id FROM users WHERE username = ?", req.username)
        .fetch_optional(state.db_pool.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Database error: {}", e),
                }),
            )
        })?;

    if existing_user.is_some() {
        info!("Username already exists: {}", req.username);
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError {
                error: "Username already exists".to_string(),
            }),
        ));
    }

    // Hash the password
    let password_hash = hash_password(&req.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError { error: e }),
        )
    })?;

    // Create the user
    let user_id = query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        req.username,
        password_hash
    )
    .execute(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Failed to create user: {}", e),
            }),
        )
    })?
    .last_insert_rowid();

    // Verify the user was created
    let user_id = query!("SELECT id FROM users WHERE id = ?", user_id)
        .fetch_one(state.db_pool.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Failed to create user: {}", e),
                }),
            )
        })?
        .id;

    info!("User created successfully: {}", user_id);

    // Generate an auth token
    let token = generate_token(user_id, &state).await?;

    // Return the user and token
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: common::User {
                id: user_id,
                username: req.username,
            },
            token: token.token,
        }),
    ))
}

async fn login_handler(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<ApiError>)> {
    // Find the user
    let user = query!(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        req.username
    )
    .fetch_optional(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    let user = user.ok_or_else(|| {
        info!("Invalid login attempt for username: {}", req.username);
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "Invalid username or password".to_string(),
            }),
        )
    })?;

    // Verify the password
    let password_valid = verify_password(&req.password, &user.password_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError { error: e }),
        )
    })?;

    if !password_valid {
        info!("Invalid password for username: {}", req.username);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "Invalid username or password".to_string(),
            }),
        ));
    }
    // For some reason, sqlx says that user.id is optional, but it is not
    let user_id = user.id.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: "User ID not found".to_string(),
            }),
        )
    })?;

    // Generate an auth token
    let token = generate_token(user_id, &state).await?;
    info!("User logged in successfully: {}", user_id);
    // Return the user and token
    Ok((
        StatusCode::OK,
        Json(AuthResponse {
            user: common::User {
                id: user_id,
                username: user.username,
            },
            token: token.token,
        }),
    ))
}

async fn logout_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    // Retrieve token from header and mark it as revoked
    // Note: This is already validated by the AuthUser extractor
    let token = auth::extract_token_from_headers(&headers);
    if let Some(token) = token {
        // Revoke the token
        query!(
            "UPDATE auth_tokens SET is_revoked = 1 WHERE token = ?",
            token
        )
        .execute(state.db_pool.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Failed to revoke token: {}", e),
                }),
            )
        })?;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_conversations_handler(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<ConversationsResponse>, (StatusCode, Json<ApiError>)> {
    // Extract the token from headers
    let token = auth::extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "Missing authentication token".to_string(),
            }),
        )
    })?;

    // Verify the token and get user ID
    let user_id = query!(
        r#"
        SELECT u.id
        FROM users u
        JOIN auth_tokens t ON u.id = t.user_id
        WHERE t.token = ?
          AND t.is_revoked = 0
        "#,
        token
    )
    .fetch_optional(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Database error: {}", e),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "Invalid or expired token".to_string(),
            }),
        )
    })?;

    let user_id = user_id.id.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: "User ID not found".to_string(),
            }),
        )
    })?;

    // Get conversations for this user
    let conversations = query!(
        r#"
        SELECT id, user_id, created_at, updated_at,
               (SELECT content FROM messages WHERE conversation_id = conversations.id ORDER BY message_number LIMIT 1) as first_message
        FROM conversations 
        WHERE user_id = ? 
        ORDER BY updated_at DESC
        "#,
        user_id
    )
    .fetch_all(state.db_pool.as_ref())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("Failed to fetch conversations: {}", e),
            }),
        )
    })?;

    let conversations: Vec<Conversation> = conversations
        .into_iter()
        .map(|row| {
            // Generate title from first message or use default
            let title = row.first_message
                .map(|msg| {
                    let truncated = if msg.len() > 50 {
                        format!("{}...", &msg[..47])
                    } else {
                        msg
                    };
                    truncated
                })
                .unwrap_or_else(|| "New Conversation".to_string());

            Conversation {
                id: row.id,
                user_id: row.user_id,
                title: Some(title),
                created_at: row.created_at,
                updated_at: row.updated_at,
            }
        })
        .collect();

    Ok(Json(ConversationsResponse { conversations }))
}
