use common::{Conversation, ConvoId};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    console, Document, Element, HtmlButtonElement, HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, WebSocket
};

fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

// UI State (just DOM references, no business logic)
#[derive(Clone)]
pub struct UiState {
    pub document: Document,
    pub username_input: HtmlInputElement,
    pub password_input: HtmlInputElement,
    pub conversation_list: Element,
    pub messages_div: Element,
    pub login_form: Element,
    pub user_info: Element,
    pub username_display: Element,
    pub login_btn: HtmlButtonElement,
    pub signup_btn: HtmlButtonElement,
    pub logout_btn: HtmlButtonElement,
    pub send_btn: HtmlButtonElement,
    pub connect_btn: HtmlButtonElement,
    pub disconnect_btn: HtmlButtonElement,
    pub clear_btn: HtmlButtonElement,
    pub new_conversation_btn: HtmlButtonElement,
    pub input_message: HtmlTextAreaElement,
    pub model_select: HtmlSelectElement,
}

impl UiState {
    pub fn new() -> Result<Self, JsValue> {
        let window = web_sys::window().expect("No global window exists");
        let document = window.document().expect("No document exists");

        // Get DOM elements
        let messages_div = document.get_element_by_id("messages").expect("No messages div");
        let input_message = document
            .get_element_by_id("input-message")
            .expect("No input message")
            .dyn_into::<HtmlTextAreaElement>()?;
        let model_select = document
            .get_element_by_id("model-select")
            .expect("No model select")
            .dyn_into::<HtmlSelectElement>()?;
        let send_btn = document
            .get_element_by_id("send-btn")
            .expect("No send button")
            .dyn_into::<HtmlButtonElement>()?;
        let connect_btn = document
            .get_element_by_id("connect-btn")
            .expect("No connect button")
            .dyn_into::<HtmlButtonElement>()?;
        let disconnect_btn = document
            .get_element_by_id("disconnect-btn")
            .expect("No disconnect button")
            .dyn_into::<HtmlButtonElement>()?;
        let clear_btn = document
            .get_element_by_id("clear-btn")
            .expect("No clear button")
            .dyn_into::<HtmlButtonElement>()?;
        let username_input = document
            .get_element_by_id("username-input")
            .expect("No username input")
            .dyn_into::<HtmlInputElement>()?;
        let password_input = document
            .get_element_by_id("password-input")
            .expect("No password input")
            .dyn_into::<HtmlInputElement>()?;
        let login_btn = document
            .get_element_by_id("login-btn")
            .expect("No login button")
            .dyn_into::<HtmlButtonElement>()?;
        let signup_btn = document
            .get_element_by_id("signup-btn")
            .expect("No signup button")
            .dyn_into::<HtmlButtonElement>()?;
        let logout_btn = document
            .get_element_by_id("logout-btn")
            .expect("No logout button")
            .dyn_into::<HtmlButtonElement>()?;
        let login_form = document
            .get_element_by_id("login-form")
            .expect("No login form");
        let user_info = document
            .get_element_by_id("user-info")
            .expect("No user info");
        let username_display = document
            .get_element_by_id("username-display")
            .expect("No username display");
        let conversation_list = document
            .get_element_by_id("conversation-list")
            .expect("No conversation list");
        let new_conversation_btn = document
            .get_element_by_id("new-conversation-btn")
            .expect("No new conversation button")
            .dyn_into::<HtmlButtonElement>()?;

        Ok(Self {
            document,
            username_input,
            password_input,
            conversation_list,
            messages_div,
            login_form,
            user_info,
            username_display,
            login_btn,
            signup_btn,
            logout_btn,
            send_btn,
            connect_btn,
            disconnect_btn,
            clear_btn,
            new_conversation_btn,
            input_message,
            model_select,
        })
    }

    
}


// Separate state structs
#[derive(Debug, Clone)]
pub struct AuthState {
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub is_loading: bool,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            user_id: None,
            username: None,
            token: None,
            is_loading: false,
        }
    }
}

#[derive(Debug)]
pub struct ConversationState {
    pub conversations: Vec<Conversation>,
    pub active_conversation_id: Option<i64>,
    pub is_loading: bool,
}

impl Default for ConversationState {
    fn default() -> Self {
        Self {
            conversations: Vec::new(),
            active_conversation_id: None,
            is_loading: false,
        }
    }
}

#[derive(Debug)]
pub struct WebSocketState {
    pub connected: bool,
    pub socket: Option<WebSocket>,
}

impl Default for WebSocketState {
    fn default() -> Self {
        Self {
            connected: false,
            socket: None,
        }
    }
}


// Main app state container  
pub struct AppState {
    pub auth: AuthState,
    pub conversations: ConversationState,
    pub websocket: WebSocketState,
    pub ui: UiState,
    pub current_convo_id: Option<ConvoId>,
    pub current_bot_message: Option<Element>,
}


impl AppState {
    
    pub fn new(ui: UiState) -> AppState {
        AppState {
            auth: AuthState::default(),
            conversations: ConversationState::default(),
            websocket: WebSocketState::default(),
            ui,
            current_convo_id: None,
            current_bot_message: None,
        }
    }


    
    pub fn clear_chat(&mut self) {
        self.ui.messages_div.set_inner_html("");
        self.current_bot_message = None;
        self.current_convo_id = None;
        log("Chat and conversation ID cleared");
    }

    pub fn show_error(&mut self, error: &str) {
        Self::add_message(self, "Error", error, "error");
        log(&format!("Error: {}", error));
    }

    pub fn update_conversation_ui(&self) {
        // Clear and repopulate conversation list
        self.ui.conversation_list.set_inner_html("");
        
        if self.conversations.conversations.is_empty() {
            let empty_message = self.ui.document.create_element("div").unwrap();
            empty_message.set_class_name("conversation-empty");
            empty_message.set_text_content(Some("No conversations yet"));
            let _ = self.ui.conversation_list.append_child(&empty_message);
            return;
        }
        
        for conversation in &self.conversations.conversations {
            let item = self.ui.document.create_element("div").unwrap();
            item.set_class_name("conversation-item");
            
            if Some(conversation.id) == self.conversations.active_conversation_id {
                item.class_list().add_1("active").unwrap();
            }
            
            let title = conversation.title.as_deref().unwrap_or("Untitled Conversation");
            item.set_text_content(Some(title));
            item.set_attribute("data-conversation-id", &conversation.id.to_string()).unwrap();
            
            let _ = self.ui.conversation_list.append_child(&item);
        }
    }
    
    pub fn update_button_states(&self) {
        self.ui.send_btn.set_disabled(!self.websocket.connected);
        self.ui.connect_btn.set_disabled(self.websocket.connected);
        self.ui.disconnect_btn.set_disabled(!self.websocket.connected);
    }
        // UI Update Functions
    pub fn update_auth_ui(&self) {
        if let Some(username) = &self.auth.username {
            // Show logged in state
            let _ = self.ui.login_form.set_attribute("style", "display: none;");
            let _ = self.ui.user_info.set_attribute("style", "display: block;");
            self.ui.username_display.set_text_content(Some(&format!("Logged in as: {}", username)));
        } else {
            // Show login form
            let _ = self.ui.login_form.set_attribute("style", "display: block;");
            let _ = self.ui.user_info.set_attribute("style", "display: none;");
        }
        
        // Update loading states
        self.ui.login_btn.set_disabled(self.auth.is_loading);
        self.ui.signup_btn.set_disabled(self.auth.is_loading);
    }

    pub fn disconnect_websocket(&mut self)
    {
        self.websocket.connected = false;
        self.websocket.socket = None;
        
        Self::add_message(self, "System", "Disconnected from WebSocket server", "bot");
        Self::update_button_states(self);
    }

    
    // Helper Functions
    pub fn add_message(&mut self, sender: &str, text: &str, class_name: &str) {
        // If it's a bot message, we might be streaming tokens
        if sender == "Bot" && class_name == "bot" {
            if let Some(bot_msg) = &self.current_bot_message {
                // If we already have a bot message, update it instead of creating a new one
                let current_text = bot_msg.text_content().unwrap_or_default();
                // Replace the entire content with updated text
                bot_msg.set_text_content(Some(&(current_text + text)));
            } else {
                // First bot message in a stream, create a new message div
                let message_div = self.ui.document.create_element("div").unwrap();
                message_div.set_class_name(&format!("message {}", class_name));
                message_div.set_text_content(Some(&format!("Bot: {}", text)));

                let _ = self.ui.messages_div.append_child(&message_div);

                // Save reference to the new bot message
                self.current_bot_message = Some(message_div);
            }
        } else {
            // For user messages or other message types, always create a new message
            let message_div = self.ui.document.create_element("div").unwrap();
            message_div.set_class_name(&format!("message {}", class_name));
            message_div.set_text_content(Some(&format!("{}: {}", sender, text)));

            let _ = self.ui.messages_div.append_child(&message_div);

            // If this is a user message, clear the current bot message reference
            // so the next bot response will start fresh
            if sender == "You" && class_name == "user" {
                self.current_bot_message = None;
            }
        }

        // Always scroll to bottom after adding or updating a message
        let _ = js_sys::eval(&format!(
            "document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight"
        ));
    }
}