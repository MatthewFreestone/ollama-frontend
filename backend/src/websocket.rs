use axum::{extract::{ws::{Message, WebSocket}, State, WebSocketUpgrade}, response::IntoResponse};
use common::{
    ChatMessage, ChatType, ConvoId, OllamaChatRequest,
    OllamaResponse, WsChatRequest, WsResponse,
};
use jiff::Zoned;
use futures_util::{SinkExt, StreamExt};
use sqlx::{query, query_as};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::appstate::AppState;
use crate::auth::extract_token_from_headers;

// const CHAT_ENDPOINT: &str = "http://localhost:11434/";
const CHAT_ENDPOINT: &str = "http://localhost:11434/api/chat";

// WebSocket handler
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Extract the token from headers or query parameters
    let token = extract_token_from_headers(&headers);
    
    let user_id: Option<i64> = if let Some(token) = token {
        info!("WebSocket connection with token: {}", token);
        let foo = query!(
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
        .ok()
        .flatten();
        foo.and_then(|user| user.id)
    } else {
        info!("WebSocket connection without token");
        None
    };

    ws.on_upgrade(move |socket| handle_websocket_upgrade(socket, state, user_id))
}


async fn handle_websocket_upgrade(socket: WebSocket, state: AppState, user_id: Option<i64>) {
    if let Some(uid) = user_id {
        info!("Authenticated connection for user ID: {}", uid);
    } else {
        info!("Unauthenticated connection");
    }

    // Split the socket into sender and receiver
    let (sender, mut receiver) = socket.split();

    // Use an Arc<Mutex<_>> to share the sender between tasks
    let sender = Arc::new(Mutex::new(sender));
    let db_pool: Arc<sqlx::SqlitePool> = Arc::clone(&state.db_pool);
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
                let chat_request: Result<WsChatRequest, _> = serde_json::from_str(&text);
                match chat_request {
                    Ok(request) => {
                        // Set default model to phi4 if not specified
                        let model = if request.model.is_empty() {
                            "phi4".to_string()
                        } else {
                            request.model
                        };

                        let (messages, convo_id) = match request.chat_type {
                            ChatType::ContinueConvo(continue_convo) => {
                                info!(
                                    "Continuing conversation with ID: {}",
                                    continue_convo.conversation_id.0
                                );

                                // If user is authenticated, check if they own this conversation
                                if let Some(uid) = user_id {
                                    let conversation = query!(
                                        "SELECT user_id FROM conversations WHERE id = ?",
                                        continue_convo.conversation_id.0
                                    )
                                    .fetch_optional(db_pool.as_ref())
                                    .await;

                                    match conversation {
                                        Ok(Some(convo)) => {
                                            // Check if the authenticated user owns this conversation
                                            // user_id is a non-nullable field in the database
                                            // sqlx seems to return it as an Option<i64>
                                            if convo.user_id.unwrap() != uid {
                                                info!("Unauthorized access attempt to conversation {}", continue_convo.conversation_id.0);
                                                // Send error message for unauthorized access
                                                let error_msg = serde_json::json!({
                                                    "error": "You do not have permission to access this conversation"
                                                }).to_string();

                                                let mut lock = sender.lock().await;
                                                let _ = lock
                                                    .send(Message::Text(error_msg.into()))
                                                    .await;
                                                return;
                                            }
                                        }
                                        _ => {
                                            info!(
                                                "Conversation {} not found",
                                                continue_convo.conversation_id.0
                                            );
                                            let error_msg = serde_json::json!({
                                                "error": "Conversation not found"
                                            })
                                            .to_string();

                                            let mut lock = sender.lock().await;
                                            let _ =
                                                lock.send(Message::Text(error_msg.into())).await;
                                            return;
                                        }
                                    }
                                }

                                // Get previous messages
                                let mut previous_messages = query_as!(ChatMessage,
                                    "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY message_number",
                                    continue_convo.conversation_id.0
                                ).fetch_all(db_pool.as_ref()).await.unwrap();

                                if previous_messages.is_empty() {
                                    tracing::warn!(
                                        "No messages found for conversation ID: {}",
                                        continue_convo.conversation_id.0
                                    );
                                    return;
                                }

                                // Find the next message number for this conversation
                                let next_message_number = query!(
                                    "SELECT MAX(message_number) as max_num FROM messages WHERE conversation_id = ?",
                                    continue_convo.conversation_id.0
                                )
                                .fetch_one(db_pool.as_ref())
                                .await
                                .map(|record| record.max_num.unwrap_or(0) + 1)
                                .unwrap_or(0);

                                // Save the new user message
                                match query!(
                                    "INSERT INTO messages (conversation_id, role, content, message_number) VALUES (?, ?, ?, ?)",
                                    continue_convo.conversation_id.0,
                                    continue_convo.new_message.role,
                                    continue_convo.new_message.content,
                                    next_message_number
                                ).execute(db_pool.as_ref()).await {
                                    Ok(_) => info!("Successfully saved user message for continuation"),
                                    Err(e) => info!("Error saving user message for continuation: {}", e)
                                }

                                // Add the new message to the previous messages for the API request
                                previous_messages.push(continue_convo.new_message.clone());

                                (previous_messages, continue_convo.conversation_id)
                            }
                            ChatType::NewConvo(new_convo) => {
                                info!("Starting new conversation");
                                // Handle new conversation
                                let messages = new_convo;
                                let created_at = Zoned::now().timestamp().as_second();
                                // Create a new row in the conversations table
                                let new_conversation_id = {
                                    let uid_opt = user_id;
                                    query!("INSERT INTO conversations (user_id, created_at, updated_at) VALUES (?, ?, ?)", uid_opt, created_at, created_at)
                                        .execute(db_pool.as_ref())
                                        .await
                                        .unwrap()
                                        .last_insert_rowid()
                                };

                                // Now, insert the user message(s) into the messages table
                                let mut message_number: i64 = 0;
                                for message in messages.iter() {
                                    info!(
                                        "Saving message: role={}, content={}",
                                        message.role, message.content
                                    );
                                    match query!(
                                        "INSERT INTO messages (conversation_id, role, content, message_number) VALUES (?, ?, ?, ?)",
                                        new_conversation_id,
                                        message.role,
                                        message.content,
                                        message_number
                                    ).execute(db_pool.as_ref()).await {
                                        Ok(_) => message_number += 1,
                                        Err(e) => info!("Error saving message: {}", e)
                                    }
                                }

                                // Return the messages and conversation ID
                                (messages.clone(), ConvoId(new_conversation_id))
                            }
                        };

                        // Build the request
                        let ollama_request = OllamaChatRequest {
                            model,
                            messages,
                            stream: Some(true), // Always use streaming
                            options: request.options,
                        };

                        // Create a clone of the sender for the task
                        let sender_clone = Arc::clone(&sender);
                        let client = state.client.clone();

                        // Clone the database pool for the task

                        let task_db_pool = Arc::clone(&state.db_pool);
                        // Spawn a task to make the request and handle the response
                        tokio::spawn(async move {
                            // Make the request to Ollama
                            let res = client
                                .post(CHAT_ENDPOINT)
                                .json(&ollama_request)
                                .send()
                                .await;

                            match res {
                                Ok(response) => {
                                    // Create a separate task to stream the response
                                    let mut stream = response.bytes_stream();
                                    let mut complete_response: ChatMessage = ChatMessage {
                                        role: "bot".to_string(),
                                        content: String::new(),
                                    };
                                    let mut completed_safely: bool = false;
                                    while let Some(chunk) = stream.next().await {
                                        match chunk {
                                            Ok(bytes) => {
                                                // Forward the response to the WebSocket client
                                                if let Ok(text) = String::from_utf8(bytes.to_vec())
                                                {
                                                    let text_message =
                                                        Message::Text((&text).into());

                                                    // Try to parse the response using our typed struct
                                                    if let Ok(ollama_response) =
                                                        serde_json::from_str::<OllamaResponse>(
                                                            &text,
                                                        )
                                                    {
                                                        // Check if this is the done message
                                                        let is_done =
                                                            ollama_response.done.unwrap_or(false);
                                                        if is_done {
                                                            completed_safely = true;
                                                        }

                                                        // Extract content from the response
                                                        if let Some(content) =
                                                            &ollama_response.content
                                                        {
                                                            complete_response
                                                                .content
                                                                .push_str(content);
                                                        } else if let Some(message) =
                                                            &ollama_response.message
                                                        {
                                                            complete_response
                                                                .content
                                                                .push_str(&message.content);
                                                        }

                                                        // Wrap the response to include conversation ID
                                                        let wrapped_response = WsResponse {
                                                            response: ollama_response,
                                                            conversation_id: if is_done {
                                                                Some(convo_id.clone())
                                                            } else {
                                                                None
                                                            },
                                                            is_final: if is_done {
                                                                Some(true)
                                                            } else {
                                                                None
                                                            },
                                                        };

                                                        // Serialize the wrapped response
                                                        let wrapped_text = serde_json::to_string(
                                                            &wrapped_response,
                                                        )
                                                        .unwrap();
                                                        let message =
                                                            Message::Text(wrapped_text.into());

                                                        let mut lock = sender_clone.lock().await;
                                                        if lock.send(message).await.is_err() {
                                                            completed_safely = true;
                                                            break;
                                                        }

                                                        // Skip the original message send below
                                                        continue;
                                                    }

                                                    // If we couldn't parse it as an OllamaResponse, send the original message
                                                    let mut lock = sender_clone.lock().await;
                                                    if lock.send(text_message).await.is_err() {
                                                        completed_safely = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("Error streaming response: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    // Save the bot's response to the database
                                    // We count as completed either if we got a complete response or had a safe exit
                                    if completed_safely {
                                        // Save the bot's message to the database
                                        // First, find the next message number for this conversation
                                        let next_message_number = query!(
                                            "SELECT MAX(message_number) as max_num FROM messages WHERE conversation_id = ?",
                                            convo_id.0
                                        )
                                        .fetch_one(task_db_pool.as_ref())
                                        .await
                                        .map(|record| record.max_num.unwrap_or(0) + 1)
                                        .unwrap_or(0);

                                        // Save the bot's complete response
                                        match query!(
                                            "INSERT INTO messages (conversation_id, role, content, message_number) VALUES (?, ?, ?, ?)",
                                            convo_id.0,
                                            complete_response.role,
                                            complete_response.content,
                                            next_message_number
                                        )
                                        .execute(task_db_pool.as_ref())
                                        .await {
                                            Ok(_) => info!("Successfully saved bot message to database"),
                                            Err(e) => info!("Error saving bot message: {}", e)
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Send error message
                                    info!("Error sending request to Ollama: {}", e);

                                    // Create a proper OllamaResponse with error
                                    let ollama_error = OllamaResponse {
                                        model: ollama_request.model.clone(),
                                        created_at: None,
                                        message: None,
                                        done: Some(true),
                                        total_duration: None,
                                        load_duration: None,
                                        prompt_eval_count: None,
                                        prompt_eval_duration: None,
                                        eval_count: None,
                                        eval_duration: None,
                                        content: None,
                                        error: Some(e.to_string()),
                                    };

                                    // Wrap the error response to include conversation ID
                                    let wrapped_error = WsResponse {
                                        response: ollama_error,
                                        conversation_id: Some(convo_id),
                                        is_final: Some(true),
                                    };

                                    let error_msg = serde_json::to_string(&wrapped_error).unwrap();

                                    // Save the error as a system message in the database
                                    let next_message_number = query!(
                                        "SELECT MAX(message_number) as max_num FROM messages WHERE conversation_id = ?",
                                        convo_id.0
                                    )
                                    .fetch_one(task_db_pool.as_ref())
                                    .await
                                    .map(|record| record.max_num.unwrap_or(0) + 1)
                                    .unwrap_or(0);

                                    let error_content = format!("Error: {}", e);
                                    let _ = query!(
                                        "INSERT INTO messages (conversation_id, role, content, message_number) VALUES (?, ?, ?, ?)",
                                        convo_id.0,
                                        "system",
                                        error_content,
                                        next_message_number
                                    )
                                    .execute(task_db_pool.as_ref())
                                    .await;

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
                        })
                        .to_string();

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
