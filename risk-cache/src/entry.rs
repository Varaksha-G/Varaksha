#[derive(Debug, Clone)]
pub struct RiskEntry {
    pub risk_score: f32,
    pub reason: String,
    pub updated_at: u64,
}