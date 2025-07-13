use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use wasm_bindgen_futures::spawn_local;

use common::{ContinueConvo, ConvoId};
use common::{ChatMessage, ChatType, WsChatRequest, LoginRequest, SignupRequest, AuthResponse, ApiError, TOKEN_HEADER, Conversation, ConversationsResponse};
use gloo_utils::format::JsValueSerdeExt;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Document, Element, HtmlButtonElement, HtmlSelectElement, HtmlTextAreaElement,
    HtmlInputElement, WebSocket, Request, RequestInit, Response, Headers,
};
use serde_json;
use web_sys::console;

use crate::state::{AppState, AuthState, ConversationState, UiState};
mod state;

// Helper for logging to console
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

// Define all possible actions as an enum
#[derive(Debug)]
enum AppMessage {
    // Auth messages
    Login { username: String, password: String },
    Signup { username: String, password: String },
    Logout,
    
    // Conversation messages
    LoadConversations,
    SelectConversation(i64),
    CreateNewConversation,
    
    // WebSocket messages
    ConnectWebSocket,
    DisconnectWebSocket,
    SendMessage(String),
    
    // UI update messages
    UpdateConversationList(Vec<Conversation>),
    UpdateAuthState(AuthState),
    ShowError(String),
    
    // Chat messages
    ClearChat,
}

// Main App struct with message channel
struct App {
    sender: mpsc::UnboundedSender<AppMessage>,
    ui: UiState,
}

impl App {
    fn new() -> Result<Self, JsValue> {
        let (sender, receiver) = mpsc::unbounded();
        let ui = UiState::new()?;
        
        // Start the message handler in background
        spawn_local(Self::message_handler(receiver, ui.clone()));
        
        Ok(Self { sender, ui })
    }
    
    async fn message_handler(
        mut receiver: mpsc::UnboundedReceiver<AppMessage>,
        ui: UiState,
    ) {
        let mut state = AppState::new(ui);
        log("Starting message handler...");
        while let Some(message) = receiver.next().await {
            log(&format!("Received message: {:?}", message));
            Self::handle_message(message, &mut state).await;
        }
        log("Message handler finished");
    }

    async fn handle_load_conversations_message(state: &mut AppState) {
        if let Some(token) = &state.auth.token {
            state.conversations.is_loading = true;
            state.update_conversation_ui();
            
            match Self::fetch_conversations(token).await {
                Ok(conversations) => {
                    state.conversations.conversations = conversations;
                    state.conversations.is_loading = false;
                    state.update_conversation_ui();
                }
                Err(error) => {
                    state.conversations.is_loading = false;
                    state.show_error(&error);
                }
            }
        }
    }

    async fn handle_message(message: AppMessage, state: &mut AppState) {
        log(&format!("Handling message: {:?}", message));
        
        match message {
            AppMessage::Login { username, password } => {
                state.auth.is_loading = true;
                state.update_auth_ui();
                
                match Self::perform_login(&username, &password).await {
                    Ok(auth_response) => {
                        state.auth = AuthState {
                            user_id: Some(auth_response.user.id),
                            username: Some(auth_response.user.username),
                            token: Some(auth_response.token),
                            is_loading: false,
                        };
                        state.update_auth_ui();
                        
                        // Clear input fields
                        state.ui.username_input.set_value("");
                        state.ui.password_input.set_value("");
                        
                        state.add_message("System", "Login successful!", "bot");
                        
                        // Trigger conversation loading
                        Self::handle_load_conversations_message(state).await;
                    }
                    Err(error) => {
                        state.auth.is_loading = false;
                        state.update_auth_ui();
                        state.show_error(&error);
                    }
                }
            }
            
            AppMessage::Signup { username, password } => {
                state.auth.is_loading = true;
                state.update_auth_ui();
                
                match Self::perform_signup(&username, &password).await {
                    Ok(auth_response) => {
                        state.auth = AuthState {
                            user_id: Some(auth_response.user.id),
                            username: Some(auth_response.user.username),
                            token: Some(auth_response.token),
                            is_loading: false,
                        };
                        state.update_auth_ui();
                        
                        // Clear input fields
                        state.ui.username_input.set_value("");
                        state.ui.password_input.set_value("");

                        state.add_message("System", "Signup successful!", "bot");

                        // Trigger conversation loading
                        Self::handle_load_conversations_message(state).await;
                    }
                    Err(error) => {
                        state.auth.is_loading = false;
                        state.update_auth_ui();
                        state.show_error(&error);
                    }
                }
            }
            
            AppMessage::LoadConversations => {
                Self::handle_load_conversations_message(state).await;
            }
            
            AppMessage::Logout => {
                if let Some(token) = &state.auth.token {
                    let _ = Self::perform_logout(token).await;
                }
                
                state.auth = AuthState::default();
                state.conversations = ConversationState::default();
                
                // Disconnect WebSocket if connected
                if state.websocket.connected {
                    Self::disconnect_websocket(state);
                }
                
                state.update_auth_ui();
                state.update_conversation_ui();
                state.add_message("System", "Logged out successfully", "bot");
            }
            
            AppMessage::SelectConversation(conversation_id) => {
                state.conversations.active_conversation_id = Some(conversation_id);
                state.update_conversation_ui();
                // TODO: Load messages for this conversation
            }
            
            AppMessage::CreateNewConversation => {
                state.clear_chat();
                state.add_message("System", "New conversation started", "bot");
            }
            
            AppMessage::ConnectWebSocket => {
                Self::connect_websocket(state).await;
            }
            
            AppMessage::DisconnectWebSocket => {
                state.disconnect_websocket();
            }
            
            AppMessage::SendMessage(message) => {
                Self::send_message(state, &message).await
            }
            
            AppMessage::ClearChat => {
                state.clear_chat();
            }
            
            AppMessage::ShowError(error) => {
                state.show_error(&error);
            }
            
            AppMessage::UpdateConversationList(_) => {
                state.update_conversation_ui();
            }
            
            AppMessage::UpdateAuthState(_) => {
                state.update_auth_ui();
            }
        }
    }

    

    // API Functions
    async fn perform_login(username: &str, password: &str) -> Result<AuthResponse, String> {
        let login_request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        
        let opts = RequestInit::new();
        opts.set_method("POST");
        
        let headers = Headers::new().map_err(|e| format!("Header error: {:?}", e))?;
        headers.set("Content-Type", "application/json").map_err(|e| format!("Header error: {:?}", e))?;
        opts.set_headers(&headers);
        
        let body = serde_json::to_string(&login_request)
            .map_err(|e| format!("Serialization error: {}", e))?;
        opts.set_body(&JsValue::from_str(&body));

        let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/login", &opts)
            .map_err(|e| format!("Request error: {:?}", e))?;
        
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
            .map_err(|e| format!("Fetch error: {:?}", e))?;
        let resp: Response = resp_value.dyn_into().unwrap();
        
        if resp.ok() {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let auth_response: AuthResponse = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Ok(auth_response)
        } else {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let error_response: ApiError = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Err(error_response.error)
        }
    }
    
    async fn perform_signup(username: &str, password: &str) -> Result<AuthResponse, String> {
        let signup_request = SignupRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        
        let opts = RequestInit::new();
        opts.set_method("POST");
        
        let headers = Headers::new().map_err(|e| format!("Header error: {:?}", e))?;
        headers.set("Content-Type", "application/json").map_err(|e| format!("Header error: {:?}", e))?;
        opts.set_headers(&headers);
        
        let body = serde_json::to_string(&signup_request)
            .map_err(|e| format!("Serialization error: {}", e))?;
        opts.set_body(&JsValue::from_str(&body));

        let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/signup", &opts)
            .map_err(|e| format!("Request error: {:?}", e))?;
        
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
            .map_err(|e| format!("Fetch error: {:?}", e))?;
        let resp: Response = resp_value.dyn_into().unwrap();
        
        if resp.ok() {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let auth_response: AuthResponse = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Ok(auth_response)
        } else {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let error_response: ApiError = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Err(error_response.error)
        }
    }
    
    async fn perform_logout(token: &str) -> Result<(), String> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        
        let headers = Headers::new().map_err(|e| format!("Header error: {:?}", e))?;
        headers.set(TOKEN_HEADER, token).map_err(|e| format!("Header error: {:?}", e))?;
        opts.set_headers(&headers);
        
        let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/logout", &opts)
            .map_err(|e| format!("Request error: {:?}", e))?;
        
        let window = web_sys::window().unwrap();
        let _ = JsFuture::from(window.fetch_with_request(&request)).await
            .map_err(|e| format!("Fetch error: {:?}", e))?;
        
        Ok(())
    }
    
    async fn fetch_conversations(token: &str) -> Result<Vec<Conversation>, String> {
        let opts = RequestInit::new();
        opts.set_method("GET");
        
        let headers = Headers::new().map_err(|e| format!("Header error: {:?}", e))?;
        headers.set(TOKEN_HEADER, token).map_err(|e| format!("Header error: {:?}", e))?;
        opts.set_headers(&headers);
        
        let request = Request::new_with_str_and_init("http://localhost:3000/api/conversations", &opts)
            .map_err(|e| format!("Request error: {:?}", e))?;
        
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await
            .map_err(|e| format!("Fetch error: {:?}", e))?;
        let resp: Response = resp_value.dyn_into().unwrap();
        
        if resp.ok() {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let conversations_response: ConversationsResponse = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Ok(conversations_response.conversations)
        } else {
            let json = JsFuture::from(resp.json().unwrap()).await
                .map_err(|e| format!("JSON error: {:?}", e))?;
            let error_response: ApiError = json.into_serde()
                .map_err(|e| format!("JSON parse error: {}", e))?;
            Err(error_response.error)
        }
    }

    // WebSocket Functions
    async fn connect_websocket(state: &mut AppState) {
        if state.websocket.connected {
            log("Already connected to WebSocket server");
            return;
        }

        log("Attempting to connect to WebSocket server...");
        
        // Build WebSocket URL with token if available
        let ws_url = if let Some(token) = &state.auth.token {
            log("Including authentication token in WebSocket URL");
            format!("ws://localhost:3000/ws?token={}", token)
        } else {
            "ws://localhost:3000/ws".to_string()
        };
        
        match WebSocket::new(&ws_url) {
            Ok(socket) => {
                log("WebSocket object created successfully");
                
                // TODO: Set up WebSocket event handlers here
                // For now, just mark as connected
                state.websocket.connected = true;
                state.websocket.socket = Some(socket);
                
                state.add_message("System", "Connected to WebSocket server", "bot");
                state.update_button_states();
                log("Connection state updated, UI refreshed");
            }
            Err(e) => {
                let error_msg = format!("Failed to create WebSocket: {:?}", e);
                state.show_error(&error_msg);
            }
        }
    }
    
    fn disconnect_websocket(state: &mut AppState) {
        log("Disconnect method called");
        if let Some(socket) = &state.websocket.socket {
            if state.websocket.connected {
                log("Sending close request to WebSocket");
                let _ = socket.close();
            }
        }
        
        state.disconnect_websocket();
    }
    
    async fn send_message(state: &mut AppState, _message: &str) {
        if !state.websocket.connected {
            state.show_error("Not connected to server");
            return;
        }

        let input_value = state.ui.input_message.value();
        let message_text = input_value.trim();
        if message_text.is_empty() {
            return;
        }

        let model = state.ui.model_select.value();

        // Add user message to chat
        state.add_message("You", message_text, "user");

        // Create the chat message
        let user_message = ChatMessage {
            role: "user".to_string(),
            content: message_text.to_string(),
        };

        // Create request payload based on whether we have a conversation ID
        let payload = if let Some(convo_id) = &state.current_convo_id {
            log(&format!("Continuing conversation with ID: {}", convo_id.0));
            WsChatRequest {
                model,
                chat_type: ChatType::ContinueConvo(ContinueConvo {
                    new_message: user_message,
                    conversation_id: *convo_id,
                }),
                options: None,
            }
        } else {
            log("Starting new conversation");
            WsChatRequest {
                model,
                chat_type: ChatType::NewConvo(vec![user_message]),
                options: None,
            }
        };

        // Send message to server
        if let Some(socket) = &state.websocket.socket {
            match serde_json::to_string(&payload) {
                Ok(json) => {
                    if let Err(e) = socket.send_with_str(&json) {
                        state.show_error(&format!("Failed to send message: {:?}", e));
                    } else {
                        // Clear input
                        state.ui.input_message.set_value("");
                    }
                }
                Err(e) => {
                    state.show_error(&format!("Failed to serialize message: {}", e));
                }
            }
        }
    }

    // Event Handler Setup
    fn setup_event_listeners(&self) -> Result<(), JsValue> {
        let sender = self.sender.clone();
        
        // Login button
        {
            let sender = sender.clone();
            let username_input = self.ui.username_input.clone();
            let password_input = self.ui.password_input.clone();
            
            let login_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let username = username_input.value();
                let password = password_input.value();
                
                if !username.trim().is_empty() && !password.trim().is_empty() {
                    let _ = sender.unbounded_send(AppMessage::Login { username, password });
                }
            }) as Box<dyn FnMut(_)>);
            
            self.ui.login_btn.set_onclick(Some(login_callback.as_ref().unchecked_ref()));
            login_callback.forget();
        }
        
        // Signup button
        {
            let sender = sender.clone();
            let username_input = self.ui.username_input.clone();
            let password_input = self.ui.password_input.clone();
            
            let signup_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let username = username_input.value();
                let password = password_input.value();
                
                if !username.trim().is_empty() && !password.trim().is_empty() {
                    let _ = sender.unbounded_send(AppMessage::Signup { username, password });
                }
            }) as Box<dyn FnMut(_)>);
            
            self.ui.signup_btn.set_onclick(Some(signup_callback.as_ref().unchecked_ref()));
            signup_callback.forget();
        }
        
        // Logout button
        {
            let sender = sender.clone();
            let logout_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let _ = sender.unbounded_send(AppMessage::Logout);
            }) as Box<dyn FnMut(_)>);
            
            self.ui.logout_btn.set_onclick(Some(logout_callback.as_ref().unchecked_ref()));
            logout_callback.forget();
        }
        
        // Send button
        {
            let sender = sender.clone();
            let input_message = self.ui.input_message.clone();
            
            let send_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let message = input_message.value();
                if !message.trim().is_empty() {
                    let _ = sender.unbounded_send(AppMessage::SendMessage(message));
                }
            }) as Box<dyn FnMut(_)>);
            
            self.ui.send_btn.set_onclick(Some(send_callback.as_ref().unchecked_ref()));
            send_callback.forget();
        }
        
        // Connect button
        {
            let sender = sender.clone();
            let connect_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                log("Connect method called"); 

                let _ = sender.unbounded_send(AppMessage::ConnectWebSocket);
            }) as Box<dyn FnMut(_)>);
            
            self.ui.connect_btn.set_onclick(Some(connect_callback.as_ref().unchecked_ref()));
            connect_callback.forget();
        }
        
        // Disconnect button
        {
            let sender = sender.clone();
            let disconnect_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let _ = sender.unbounded_send(AppMessage::DisconnectWebSocket);
            }) as Box<dyn FnMut(_)>);
            
            self.ui.disconnect_btn.set_onclick(Some(disconnect_callback.as_ref().unchecked_ref()));
            disconnect_callback.forget();
        }
        
        // Clear button
        {
            let sender = sender.clone();
            let clear_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let _ = sender.unbounded_send(AppMessage::ClearChat);
            }) as Box<dyn FnMut(_)>);
            
            self.ui.clear_btn.set_onclick(Some(clear_callback.as_ref().unchecked_ref()));
            clear_callback.forget();
        }
        
        // New conversation button
        {
            let sender = sender.clone();
            let new_conversation_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let _ = sender.unbounded_send(AppMessage::CreateNewConversation);
            }) as Box<dyn FnMut(_)>);
            
            self.ui.new_conversation_btn.set_onclick(Some(new_conversation_callback.as_ref().unchecked_ref()));
            new_conversation_callback.forget();
        }
        
        // Enter key handler for input
        {
            let sender = sender.clone();
            let keydown_callback = Closure::wrap(Box::new(move |e: web_sys::KeyboardEvent| {
                if e.key() == "Enter" && !e.shift_key() {
                    e.prevent_default();
                    if let Ok(target) = e.target().unwrap().dyn_into::<HtmlTextAreaElement>() {
                        let message = target.value();
                        if !message.trim().is_empty() {
                            let _ = sender.unbounded_send(AppMessage::SendMessage(message));
                        }
                    }
                }
            }) as Box<dyn FnMut(_)>);
            
            let _ = self.ui.input_message.add_event_listener_with_callback(
                "keydown",
                keydown_callback.as_ref().unchecked_ref(),
            );
            keydown_callback.forget();
        }
        log("Event listener setup complete");
        Ok(())
    }
}

// Main Function
pub fn main() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    log("WASM initialization started");
    
    let mut app = App::new()?;
    app.setup_event_listeners()?;
    
    // Send initial load message
    let _ = app.sender.unbounded_send(AppMessage::LoadConversations);
    
    log("WASM initialization complete");
    Ok(())
}