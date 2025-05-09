use axum::{
    routing::post,
    extract::Json,
    response::IntoResponse,
    Router,
};
use serde_json::Value;
use reqwest::Client;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/api/chat", post(proxy_ollama));
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn proxy_ollama(Json(payload): Json<Value>) -> impl IntoResponse {
    let client = Client::new();
    let res = client
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
