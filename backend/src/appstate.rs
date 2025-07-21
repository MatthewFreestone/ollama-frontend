use std::sync::Arc;
use reqwest::Client;


#[derive(Clone)]
pub struct AppState {
    pub client: Client,
    pub db_pool: Arc<sqlx::SqlitePool>,
}

impl AppState {
    pub fn new(client: Client, db_pool: Arc<sqlx::SqlitePool>) -> Self {
        Self { client, db_pool }
    }
}
