use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RiskEntry {
    pub risk_score: f32,
    pub reason: String,
    pub expires_at: Instant,
}
/*
struct datatype is defined for the type of final risks that enter the system 
it has 3 components - 1. risk score which is 32 bits long, 
                      2. reason which is basically a string telling us why it is a potential risk 
                      3. and pub expires_at which says that the risk entry must expire as soon as possible without leaving any persistent data with us. 
                      */