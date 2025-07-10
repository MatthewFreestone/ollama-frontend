use std::cell::RefCell;
use std::rc::Rc;

use common::{ContinueConvo, ConvoId};
use common::{ChatMessage, ChatType, WsChatRequest, WsResponse, LoginRequest, SignupRequest, AuthResponse, ApiError, TOKEN_HEADER};
use gloo_utils::format::JsValueSerdeExt;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Document, Element, HtmlButtonElement, HtmlSelectElement, HtmlTextAreaElement, HtmlInputElement,
    MessageEvent, WebSocket, Request, RequestInit, Response, Headers,
};
use serde_json;

use web_sys::console;

// Helper for logging to console
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

// WebSocket state
struct WebSocketState {
    socket: Option<WebSocket>,
    connected: bool,
}

// Authentication state
struct AuthState {
    user_id: Option<i64>,
    username: Option<String>,
    token: Option<String>,
}

// Global state
struct AppState {
    ws_state: WebSocketState,
    auth_state: AuthState,
    document: Document,
    messages_div: Element,
    input_message: HtmlTextAreaElement,
    model_select: HtmlSelectElement,
    send_btn: HtmlButtonElement,
    connect_btn: HtmlButtonElement,
    disconnect_btn: HtmlButtonElement,
    clear_btn: HtmlButtonElement,
    username_input: HtmlInputElement,
    password_input: HtmlInputElement,
    login_btn: HtmlButtonElement,
    signup_btn: HtmlButtonElement,
    logout_btn: HtmlButtonElement,
    login_form: Element,
    user_info: Element,
    username_display: Element,
    current_convo_id: Option<ConvoId>, // Track current conversation ID
    current_bot_message: Option<Element>, // Track current bot message for appending tokens
}

impl AppState {
    fn new() -> Result<Self, JsValue> {
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

        Ok(Self {
            ws_state: WebSocketState {
                socket: None,
                connected: false,
            },
            auth_state: AuthState {
                user_id: None,
                username: None,
                token: None,
            },
            document,
            messages_div,
            input_message,
            model_select,
            send_btn,
            connect_btn,
            disconnect_btn,
            clear_btn,
            username_input,
            password_input,
            login_btn,
            signup_btn,
            logout_btn,
            login_form,
            user_info,
            username_display,
            current_convo_id: None,
            current_bot_message: None,
        })
    }

    // Update button states based on connection status and authentication
    fn update_buttons(&self) {
        log(&format!("Updating button states, connected: {}", self.ws_state.connected));
        self.send_btn.set_disabled(!self.ws_state.connected);
        self.connect_btn.set_disabled(self.ws_state.connected);
        self.disconnect_btn.set_disabled(!self.ws_state.connected);
        log("Button states updated");
    }

    // Update UI based on authentication state
    fn update_auth_ui(&self) {
        if self.auth_state.token.is_some() {
            // User is logged in
            let _ = self.login_form.set_attribute("style", "display: none;");
            let _ = self.user_info.set_attribute("style", "display: block;");
            if let Some(username) = &self.auth_state.username {
                self.username_display.set_text_content(Some(&format!("Logged in as: {}", username)));
            }
        } else {
            // User is not logged in
            let _ = self.login_form.set_attribute("style", "display: block;");
            let _ = self.user_info.set_attribute("style", "display: none;");
        }
    }

    // Add a message to the chat
    fn add_message(&mut self, sender: &str, text: &str, class_name: &str) {
        // If it's a bot message, we might be streaming tokens
        if sender == "Bot" && class_name == "bot" {
            if let Some(bot_msg) = &self.current_bot_message {
                // If we already have a bot message, update it instead of creating a new one
                let current_text = bot_msg.text_content().unwrap_or_default();
                // Replace the entire content with updated text
                bot_msg.set_text_content(Some(&(current_text + text)));

                // No need to append a new element since we're updating an existing one
            } else {
                // First bot message in a stream, create a new message div
                let message_div = self.document.create_element("div").unwrap();
                message_div.set_class_name(&format!("message {}", class_name));
                message_div.set_text_content(Some(&format!("Bot: {}", text)));

                self.messages_div.append_child(&message_div).unwrap();

                // Save reference to the new bot message
                self.current_bot_message = Some(message_div);
            }
        } else {
            // For user messages or other message types, always create a new message
            let message_div = self.document.create_element("div").unwrap();
            message_div.set_class_name(&format!("message {}", class_name));
            message_div.set_text_content(Some(&format!("{}: {}", sender, text)));

            self.messages_div.append_child(&message_div).unwrap();

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

    // Clear all messages
    fn clear_chat(&mut self) {
        self.messages_div.set_inner_html("");
        self.current_bot_message = None; // Reset the bot message reference
        self.current_convo_id = None; // Reset the conversation ID
        log("Chat and conversation ID cleared");
    }

    // Connect to WebSocket server
    fn connect(app_state: Rc<RefCell<Self>>) -> Result<(), JsValue> {
        log("Connect method called");
        {
            let theapp = app_state.borrow();
            if theapp.ws_state.connected {
                log("Already connected to WebSocket server");
                return Ok(());
            }
        }

        log("Attempting to connect to WebSocket server...");
        
        // Build WebSocket URL with token if available
        let ws_url = {
            let app = app_state.borrow();
            if let Some(token) = &app.auth_state.token {
                log("Including authentication token in WebSocket URL");
                format!("ws://localhost:3000/ws?token={}", token)
            } else {
                "ws://localhost:3000/ws".to_string()
            }
        };
        
        let socket = WebSocket::new(&ws_url)?;
        log("WebSocket object created successfully");

        // Set up onopen callback
        {
            let app_state_clone = Rc::clone(&app_state);
            let onopen_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
                log("WebSocket onopen event triggered");
                match app_state_clone.try_borrow_mut() {
                    Ok(mut app_state) => {
                        log("Successfully borrowed mutable app state");
                        app_state.ws_state.connected = true;
                        // Add a system message indicating connection
                        app_state.add_message("System", "Connected to WebSocket server", "bot");
                        app_state.update_buttons();
                        log("Connection state updated, UI refreshed");
                    }
                    Err(e) => {
                        log(&format!("ERROR: Could not borrow mutable app state: {:?}", e));
                    }
                }
            });
            log("Setting onopen callback");
            socket.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
            onopen_callback.forget();
            log("onopen callback set and forgotten");
        }

        // Set up onmessage callback
        {
            let app_state_clone = Rc::clone(&app_state);
            let onmessage_callback: Closure<dyn FnMut(MessageEvent) + 'static> = Closure::new(move |e: MessageEvent| {
                log("WebSocket onmessage event triggered");
                match app_state_clone.try_borrow_mut() {
                    Ok(mut app_state) => {
                        log("Successfully borrowed app state for message handling");
                        if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                            let txt_str = String::from(txt);
                            log(&format!("Received message: {}", &txt_str));

                            match serde_json::from_str::<WsResponse>(&txt_str) {
                                Ok(ws_response) => {
                                    log("Successfully parsed WebSocket response");

                                    // Extract the Ollama response
                                    let response = &ws_response.response;

                                    // Store conversation ID if it's included
                                    if let Some(convo_id) = ws_response.conversation_id {
                                        log(&format!("Received conversation ID: {}", convo_id.0));
                                        app_state.current_convo_id = Some(convo_id);
                                    }

                                    // Check if this is the done message indicating the stream is complete
                                    let is_final = ws_response.is_final.unwrap_or(false) ||
                                                   response.done.unwrap_or(false);

                                    if is_final {
                                        log("Stream complete (final message received)");
                                        // Just leave the message as is, we're finished with this response
                                        return;
                                    }

                                    if let Some(error) = &response.error {
                                        log(&format!("Error message: {}", error));
                                        app_state.add_message("Error", error, "error");
                                    } else if let Some(message) = &response.message {
                                        log("Found message field in response");
                                        log(&format!("Adding bot message: {}", message.content));
                                        app_state.add_message("Bot", &message.content, "bot");
                                    } else if let Some(content) = &response.content {
                                        // Extract accumulated content
                                        log(&format!("Streaming token: {}", content));

                                        // For streaming tokens, we need to accumulate them
                                        // Get the current message text if we have an active bot message
                                        let current_text = match &app_state.current_bot_message {
                                            Some(element) => {
                                                // Extract just the content part without the "Bot: " prefix
                                                element.text_content()
                                                    .unwrap_or_default()
                                                    .trim_start_matches("Bot: ")
                                                    .to_string()
                                            },
                                            None => String::new()
                                        };

                                        // Append the new token to the accumulated text
                                        // Note: Ollama doesn't send complete words in chunks,
                                        // so we need to append individual tokens and display
                                        app_state.add_message("Bot", &(current_text.to_string() + content), "bot");
                                    } else {
                                        // Unknown format, just display as is
                                        log("Unknown response format, displaying raw JSON");
                                        app_state.add_message("Bot", &txt_str, "bot");
                                    }
                                },
                                Err(e) => {
                                    log(&format!("Failed to parse JSON: {}", e));
                                    app_state.add_message("Bot", &txt_str, "bot");
                                }
                            }
                        } else {
                            log("ERROR: Could not convert message data to string");
                        }
                    }
                    Err(e) => {
                        log(&format!("ERROR: Could not borrow mutable app state for message handling: {:?}", e));
                    }
                }
            });
            log("Setting onmessage callback");
            socket.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
            onmessage_callback.forget();
            log("onmessage callback set and forgotten");
        }

        // Set up onclose callback
        {
            let app_state_clone = Rc::clone(&app_state);
            let onclose_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
                log("WebSocket onclose event triggered");
                match app_state_clone.try_borrow_mut() {
                    Ok(mut app_state) => {
                        log("Successfully borrowed mutable app state for close handling");
                        app_state.ws_state.connected = false;
                        app_state.add_message("System", "Disconnected from WebSocket server", "bot");
                        app_state.update_buttons();
                        log("Connection state updated to disconnected");
                    }
                    Err(e) => {
                        log(&format!("ERROR: Could not borrow mutable app state for close handling: {:?}", e));
                    }
                }
            });
            log("Setting onclose callback");
            socket.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
            onclose_callback.forget();
            log("onclose callback set and forgotten");
        }

        // Set up onerror callback
        {
            let app_state_clone = Rc::clone(&app_state);
            let onerror_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |e: JsValue| {
                log("WebSocket onerror event triggered");
                log(&format!("Error details: {:?}", e));
                match app_state_clone.try_borrow_mut() {
                    Ok(mut app_state) => {
                        log("Successfully borrowed app state for error handling");
                        app_state.add_message("Error", "WebSocket error occurred", "error");
                    }
                    Err(e) => {
                        log(&format!("ERROR: Could not borrow app state for error handling: {:?}", e));
                    }
                }
            });
            log("Setting onerror callback");
            socket.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
            onerror_callback.forget();
            log("onerror callback set and forgotten");
        }
        let mut theapp = app_state.borrow_mut();
        theapp.ws_state.socket = Some(socket);
        theapp.update_buttons();
        log("WebSocket connection setup complete, socket stored in state");

        Ok(())
    }

    // Login method
    async fn login(&mut self, username: &str, password: &str) -> Result<(), JsValue> {
        log("Attempting to login...");
        
        let login_request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        
        let opts = RequestInit::new();
        opts.set_method("POST");
        // opts.mode(web_sys::RequestMode::Cors);
        
        let headers = Headers::new()?;
        headers.set("Content-Type", "application/json")?;
        opts.set_headers(&headers);
        
        let body = serde_json::to_string(&login_request)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        opts.set_body(&JsValue::from_str(&body));

        let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/login", &opts)?;
        
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        
        if resp.ok() {
            let json = JsFuture::from(resp.json()?).await?;
            let auth_response: AuthResponse = json.into_serde()
                .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
            
            // Update auth state
            self.auth_state.user_id = Some(auth_response.user.id);
            self.auth_state.username = Some(auth_response.user.username);
            self.auth_state.token = Some(auth_response.token);
            
            // Clear input fields
            self.username_input.set_value("");
            self.password_input.set_value("");
            
            // Update UI
            self.update_auth_ui();
            
            self.add_message("System", "Login successful!", "bot");
            log("Login successful");
        } else {
            let json = JsFuture::from(resp.json()?).await?;
            let error_response: ApiError = json.into_serde()
                .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
            
            self.add_message("Error", &format!("Login failed: {}", error_response.error), "error");
            log(&format!("Login failed: {}", error_response.error));
        }
        
        Ok(())
    }
    
    // Signup method
    async fn signup(&mut self, username: &str, password: &str) -> Result<(), JsValue> {
        log("Attempting to signup...");
        
        let signup_request = SignupRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        
        let opts = RequestInit::new();
        opts.set_method("POST");
        
        let headers = Headers::new()?;
        headers.set("Content-Type", "application/json")?;
        opts.set_headers(&headers);
        
        let body = serde_json::to_string(&signup_request)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        opts.set_body(&JsValue::from_str(&body));
        
        let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/signup", &opts)?;
        
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        
        if resp.ok() {
            let json = JsFuture::from(resp.json()?).await?;
            let auth_response: AuthResponse = json.into_serde()
                .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
            
            // Update auth state
            self.auth_state.user_id = Some(auth_response.user.id);
            self.auth_state.username = Some(auth_response.user.username);
            self.auth_state.token = Some(auth_response.token);
            
            // Clear input fields
            self.username_input.set_value("");
            self.password_input.set_value("");
            
            // Update UI
            self.update_auth_ui();
            
            self.add_message("System", "Signup successful!", "bot");
            log("Signup successful");
        } else {
            let json = JsFuture::from(resp.json()?).await?;
            let error_response: ApiError = json.into_serde()
                .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
            
            self.add_message("Error", &format!("Signup failed: {}", error_response.error), "error");
            log(&format!("Signup failed: {}", error_response.error));
        }
        
        Ok(())
    }
    
    // Logout method
    async fn logout(&mut self) -> Result<(), JsValue> {
        log("Attempting to logout...");
        
        if let Some(token) = &self.auth_state.token {
            let opts: RequestInit = RequestInit::new();
            opts.set_method("POST");
            // opts.mode(web_sys::RequestMode::Cors);
            
            let headers = Headers::new()?;
            headers.set(TOKEN_HEADER, token)?;
            opts.set_headers(&headers);
            
            let request = Request::new_with_str_and_init("http://localhost:3000/api/auth/logout", &opts)?;
            
            let window = web_sys::window().unwrap();
            let _ = JsFuture::from(window.fetch_with_request(&request)).await?;
        }
        
        // Clear auth state
        self.auth_state.user_id = None;
        self.auth_state.username = None;
        self.auth_state.token = None;
        
        // Update UI
        self.update_auth_ui();
        
        // Disconnect WebSocket if connected
        if self.ws_state.connected {
            self.disconnect();
        }
        
        self.add_message("System", "Logged out successfully", "bot");
        log("Logout successful");
        
        Ok(())
    }

    // Disconnect from WebSocket server
    fn disconnect(&mut self) {
        log("Disconnect method called");
        if let Some(socket) = &self.ws_state.socket {
            if self.ws_state.connected {
                log("Sending close request to WebSocket");
                let _ = socket.close();
            } else {
                log("Socket exists but not connected, no need to close");
            }
        } else {
            log("No socket exists to disconnect");
        }
    }

    // Send message to server
    fn send_message(&mut self) -> Result<(), JsValue> {
        if !self.ws_state.connected {
            self.add_message("Error", "Not connected to server", "error");
            return Ok(());
        }

        let input_value = self.input_message.value();
        let message = input_value.trim();
        if message.is_empty() {
            return Ok(());
        }

        let model = self.model_select.value();

        // Add user message to chat
        self.add_message("You", &message, "user");

        // Create the chat message
        let user_message = ChatMessage {
            role: "user".to_string(),
            content: message.to_string(),
        };

        // Create request payload based on whether we have a conversation ID
        let payload = if let Some(convo_id) = &self.current_convo_id {
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
        if let Some(socket) = &self.ws_state.socket {
            let json = serde_json::to_string(&payload).unwrap();
            socket.send_with_str(&json)?;
            
            // Clear input
            self.input_message.set_value("");
        }
        
        Ok(())
    }

    // This method was the source of our bug
    // Do not use weak references - the Rc is created and immediately dropped
    // We'll use direct Rc clones in the event handlers instead
}

// Need to implement Clone for AppState to use in callbacks
impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            ws_state: WebSocketState {
                socket: None, // Can't clone WebSocket
                connected: self.ws_state.connected,
            },
            auth_state: AuthState {
                user_id: self.auth_state.user_id,
                username: self.auth_state.username.clone(),
                token: self.auth_state.token.clone(),
            },
            document: self.document.clone(),
            messages_div: self.messages_div.clone(),
            input_message: self.input_message.clone(),
            model_select: self.model_select.clone(),
            send_btn: self.send_btn.clone(),
            connect_btn: self.connect_btn.clone(),
            disconnect_btn: self.disconnect_btn.clone(),
            clear_btn: self.clear_btn.clone(),
            username_input: self.username_input.clone(),
            password_input: self.password_input.clone(),
            login_btn: self.login_btn.clone(),
            signup_btn: self.signup_btn.clone(),
            logout_btn: self.logout_btn.clone(),
            login_form: self.login_form.clone(),
            user_info: self.user_info.clone(),
            username_display: self.username_display.clone(),
            current_convo_id: self.current_convo_id,
            current_bot_message: self.current_bot_message.clone(),
        }
    }
}

pub fn main() -> Result<(), JsValue> {
    // Initialize panic hook for better error messages
    console_error_panic_hook::set_once();
    log("WASM initialization started");

    log("Creating app state");
    let app_state = Rc::new(std::cell::RefCell::new(AppState::new()?));
    log("App state created successfully");
    
    // Set up event listeners
    log("Setting up event listeners");
    {
        let app_state_clone = Rc::clone(&app_state);
        let send_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Send button clicked");
            if let Ok(mut app_state) = app_state_clone.try_borrow_mut() {
                log("Borrowed app state for send button action");
                let result = app_state.send_message();
                if let Err(e) = result {
                    log(&format!("Error sending message: {:?}", e));
                }
            } else {
                log("ERROR: Could not borrow app state for send button");
            }
        });

        log("Attaching send button click handler");
        app_state.borrow().send_btn.set_onclick(Some(send_callback.as_ref().unchecked_ref()));
        send_callback.forget();
        log("Send button handler attached");
    }
    
    {
        let app_state_clone = Rc::clone(&app_state);
        let clear_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Clear button clicked");
            if let Ok(mut app_state) = app_state_clone.try_borrow_mut() {
                log("Borrowed app state for clear button action");
                app_state.clear_chat();
                log("Chat cleared");
            } else {
                log("ERROR: Could not borrow app state for clear button");
            }
        });

        log("Attaching clear button click handler");
        app_state.borrow().clear_btn.set_onclick(Some(clear_callback.as_ref().unchecked_ref()));
        clear_callback.forget();
        log("Clear button handler attached");
    }

    {
        let app_state_clone = Rc::clone(&app_state);
        let connect_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Connect button clicked");
            let result = AppState::connect(Rc::clone(&app_state_clone));
            if let Err(e) = result {
                log(&format!("Error connecting to WebSocket: {:?}", e));
            } else {
                log("Connect method completed successfully");
            }
        });

        log("Attaching connect button click handler");
        app_state.borrow().connect_btn.set_onclick(Some(connect_callback.as_ref().unchecked_ref()));
        connect_callback.forget();
        log("Connect button handler attached");
    }
    
    {
        let app_state_clone = Rc::clone(&app_state);
        let disconnect_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Disconnect button clicked");
            if let Ok(mut app_state) = app_state_clone.try_borrow_mut() {
                log("Borrowed mutable app state for disconnect button action");
                app_state.disconnect();
                log("Disconnect method completed");
            } else {
                log("ERROR: Could not borrow mutable app state for disconnect button");
            }
        });

        log("Attaching disconnect button click handler");
        app_state.borrow().disconnect_btn.set_onclick(Some(disconnect_callback.as_ref().unchecked_ref()));
        disconnect_callback.forget();
        log("Disconnect button handler attached");
    }

    // Set up Enter key handler for input
    log("Setting up keyboard event handler");
    {
        let app_state_clone = Rc::clone(&app_state);
        let keydown_callback: Closure<dyn FnMut(web_sys::KeyboardEvent) + 'static> = Closure::new(move |e: web_sys::KeyboardEvent| {
            if e.key() == "Enter" && !e.shift_key() {
                log("Enter key pressed without shift");
                e.prevent_default();
                if let Ok(mut app_state) = app_state_clone.try_borrow_mut() {
                    log("Borrowed app state for enter key action");
                    let result = app_state.send_message();
                    if let Err(e) = result {
                        log(&format!("Error sending message via Enter key: {:?}", e));
                    }
                } else {
                    log("ERROR: Could not borrow app state for enter key");
                }
            }
        });

        let input = app_state.borrow().input_message.clone();
        log("Adding keydown event listener to input field");
        let result = input.add_event_listener_with_callback(
            "keydown",
            keydown_callback.as_ref().unchecked_ref(),
        );
        if let Err(e) = result {
            log(&format!("ERROR: Failed to add keydown event listener: {:?}", e));
        } else {
            log("Keydown event listener added successfully");
        }
        keydown_callback.forget();
        log("Keydown callback forgotten");
    }

    // Set up login button event listener
    {
        let app_state_clone = Rc::clone(&app_state);
        let login_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Login button clicked");
            let username = app_state_clone.borrow().username_input.value();
            let password = app_state_clone.borrow().password_input.value();
            
            if username.trim().is_empty() || password.trim().is_empty() {
                log("Username or password is empty");
                return;
            }
            
            let app_state_clone_inner = Rc::clone(&app_state_clone);
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(mut app_state) = app_state_clone_inner.try_borrow_mut() {
                    let _ = app_state.login(&username, &password).await;
                }
            });
        });
        
        app_state.borrow().login_btn.set_onclick(Some(login_callback.as_ref().unchecked_ref()));
        login_callback.forget();
    }
    
    // Set up signup button event listener
    {
        let app_state_clone = Rc::clone(&app_state);
        let signup_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Signup button clicked");
            let username = app_state_clone.borrow().username_input.value();
            let password = app_state_clone.borrow().password_input.value();
            
            if username.trim().is_empty() || password.trim().is_empty() {
                log("Username or password is empty");
                return;
            }
            
            let app_state_clone_inner = Rc::clone(&app_state_clone);
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(mut app_state) = app_state_clone_inner.try_borrow_mut() {
                    let _ = app_state.signup(&username, &password).await;
                }
            });
        });
        
        app_state.borrow().signup_btn.set_onclick(Some(signup_callback.as_ref().unchecked_ref()));
        signup_callback.forget();
    }
    
    // Set up logout button event listener
    {
        let app_state_clone = Rc::clone(&app_state);
        let logout_callback: Closure<dyn FnMut(JsValue) + 'static> = Closure::new(move |_| {
            log("Logout button clicked");
            let app_state_clone_inner = Rc::clone(&app_state_clone);
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(mut app_state) = app_state_clone_inner.try_borrow_mut() {
                    let _ = app_state.logout().await;
                }
            });
        });
        
        app_state.borrow().logout_btn.set_onclick(Some(logout_callback.as_ref().unchecked_ref()));
        logout_callback.forget();
    }

    // Update initial button states and auth UI
    log("Updating initial button states and auth UI");
    app_state.borrow().update_buttons();
    app_state.borrow().update_auth_ui();
    log("WASM initialization complete");

    Ok(())
}