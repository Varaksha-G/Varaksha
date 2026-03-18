use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TxRequest {
    pub vpa: String,
    pub amount: f32,
    pub merchant_category: String,
    pub transaction_type: String,
    pub device_type: String,
    pub hour_of_day: i32,
    pub day_of_week: i32,
    pub transactions_last_1h: i32,
    pub transactions_last_24h: i32,
    pub amount_zscore: f32,
    pub gps_delta_km: f32,
    pub is_new_device: bool,
    pub is_new_merchant: bool,
    pub balance_drain_ratio: f32,
    pub account_age_days: i32,
    pub previous_failed_attempts: i32,
    pub transfer_cashout_flag: i32,
    #[serde(default)]
    pub consent_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TxResponse {
    pub vpa_hash: String,
    pub verdict: Verdict,
    pub risk_score: f32,
    pub trace_id: String,
    pub latency_us: u64,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Allow,
    Flag,
    Block,
}

#[derive(Debug, Deserialize)]
pub struct CacheUpdateRequest {
    pub vpa_hash: String,
    pub risk_score: f32,
    pub reason: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CacheUpdateResponse {
    pub ok: bool,
    pub vpa_hash: String,
    pub trace_id: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CacheEntryView {
    pub key: String,
    pub risk_score: f32,
    pub reason: String,
    pub updated_at: u64,
}
