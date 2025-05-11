use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize, Clone)]
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