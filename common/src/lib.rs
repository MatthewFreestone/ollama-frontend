use jiff::Timestamp;
use serde::{Deserialize, Serialize};

// Request structs

#[derive(Debug, Serialize, Deserialize)]
pub struct WsChatRequest {
    pub model: String,
    pub chat_type: ChatType,
    pub options: Option<ChatOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ChatType {
    ContinueConvo(ContinueConvo),
    NewConvo(Vec<ChatMessage>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContinueConvo {
    pub new_message: ChatMessage,
    pub conversation_id: ConvoId,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ConvoId(pub i64);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatOptions {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub num_predict: Option<u32>,
}

// Ollama API response structs

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaResponse {
    pub model: String,
    pub created_at: Option<String>,
    pub message: Option<ChatMessage>,
    pub done: Option<bool>,
    pub total_duration: Option<u64>,
    pub load_duration: Option<u64>,
    pub prompt_eval_count: Option<u32>,
    pub prompt_eval_duration: Option<u64>,
    pub eval_count: Option<u32>,
    pub eval_duration: Option<u64>,

    // Fields for streaming responses
    pub content: Option<String>,

    // Fields for error responses
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub stream: Option<bool>,
    pub options: Option<ChatOptions>,
}

// Response wrapper to add conversation ID to all responses
#[derive(Debug, Serialize, Deserialize)]
pub struct WsResponse {
    // The original Ollama response
    #[serde(flatten)]
    pub response: OllamaResponse,

    // The conversation ID (only set once when streaming is complete)
    pub conversation_id: Option<ConvoId>,

    // Field to indicate if this is the final response in a stream
    pub is_final: Option<bool>,
}

pub const TOKEN_HEADER: &str = "X-Auth-Token";

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
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Conversation {
    pub id: i64,
    pub user_id: Option<i64>,
    pub title: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationsResponse {
    pub conversations: Vec<Conversation>,
}
