use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize)]
pub struct ScanRequest {
    pub api_url: String,
    // pub token: Option<String>, //optional
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct ScanResult {
    pub id: i64,
    pub api_url: String,
    pub vulnerability: String,
    pub severity: String,
    pub details: String,
}