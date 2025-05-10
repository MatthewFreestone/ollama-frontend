use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    
    info!("Starting Ollama frontend server");

    // Set up CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create shared client
    let client = Arc::new(Client::new());

    // Build the router
    let app = Router::new()
        .route("/api/chat", post(proxy_ollama))
        .route("/ws", get(websocket_handler))
        .layer(cors)
        .with_state(AppState { client });

    // Start the server
    let listener = tokio::net::TcpListener::bind("localhost:3000").await.unwrap();
    info!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    client: Arc<Client>,
}

// Legacy endpoint for direct proxying
async fn proxy_ollama(
    State(state): State<AppState>, 
    axum::extract::Json(payload): axum::extract::Json<serde_json::Value>
) -> impl IntoResponse {
    let res = state.client
        .post("http://localhost:11434/api/chat")
        .json(&payload)
        .send()
        .await;

    match res {
        Ok(response) => {
            let stream = response.bytes_stream();
            axum::response::Response::new(
                axum::body::Body::from_stream(stream)
            )
        },
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// WebSocket handler
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: Option<bool>,
    options: Option<ChatOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatOptions {
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<u32>,
    num_predict: Option<u32>,
}

async fn handle_websocket(socket: WebSocket, state: AppState) {
    info!("WebSocket connection established");

    // Split the socket into sender and receiver
    let (sender, mut receiver) = socket.split();
    
    // Use an Arc<Mutex<_>> to share the sender between tasks
    let sender = Arc::new(Mutex::new(sender));

    // Process incoming messages
    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                info!("WebSocket error: {}", e);
                break;
            }
        };

        // Handle the message
        match msg {
            Message::Text(text) => {
                info!("Received message: {:?}", text);
                
                // Parse the request
                let chat_request: Result<ChatRequest, _> = serde_json::from_str(&text);
                match chat_request {
                    Ok(request) => {
                        // Set default model to phi4 if not specified
                        let model = if request.model.is_empty() { "phi4".to_string() } else { request.model };
                        
                        // Build the request
                        let ollama_request = ChatRequest {
                            model,
                            messages: request.messages,
                            stream: Some(true), // Always use streaming
                            options: request.options,
                        };

                        // Create a clone of the sender for the task
                        let sender_clone = Arc::clone(&sender);
                        let client = Arc::clone(&state.client);

                        // Spawn a task to make the request and handle the response
                        tokio::spawn(async move {
                            // Make the request to Ollama
                            let res = client
                                .post("http://localhost:11434/api/chat")
                                .json(&ollama_request)
                                .send()
                                .await;

                            match res {
                                Ok(response) => {
                                    // Create a separate task to stream the response
                                    let mut stream = response.bytes_stream();
                                    
                                    while let Some(chunk) = stream.next().await {
                                        match chunk {
                                            Ok(bytes) => {
                                                // Forward the response to the WebSocket client
                                                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                                                    let mut lock = sender_clone.lock().await;
                                                    if lock.send(Message::Text(text.into())).await.is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                info!("Error streaming response: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Send error message
                                    info!("Error sending request to Ollama: {}", e);
                                    let error_msg = serde_json::json!({
                                        "error": e.to_string()
                                    }).to_string();
                                    
                                    let mut lock = sender_clone.lock().await;
                                    let _ = lock.send(Message::Text(error_msg.into())).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // Send error message for invalid JSON
                        info!("Invalid JSON request: {}", e);
                        let error_msg = serde_json::json!({
                            "error": format!("Invalid request: {}", e)
                        }).to_string();
                        
                        let mut lock = sender.lock().await;
                        let _ = lock.send(Message::Text(error_msg.into())).await;
                    }
                }
            }
            Message::Close(_) => {
                info!("WebSocket connection closed by client");
                break;
            }
            _ => {}
        }
    }

    info!("WebSocket connection closed");
}