//! DPDP Act 2023 §12 — Data Principal Rights
//!
//! Four endpoints that give Data Principals statutory control over their data
//! held in the Varaksha risk-scoring gateway:
//!
//! | Endpoint                | §12 right           | Description                       |
//! |-------------------------|---------------------|-----------------------------------|
//! | POST /v1/dpr/access     | §12(a) — Access     | All data held for this VPA        |
//! | POST /v1/dpr/correction | §12(b) — Correction | Disputed score → 90-day grievance |
//! | POST /v1/dpr/erasure    | §12(b) — Erasure    | Delete all records for this VPA   |
//! | POST /v1/dpr/nomination | §12(d) — Nomination | Register nominee for incapacity   |
//!
//! All endpoints authenticate via an AA consent artefact token (DPDP §4(1)/§7(g)).
//! Set `DPDP_CONSENT_DEV_BYPASS=true` in local development to skip the AA call.
//!
//! Grievance resolution deadline: 90 days — DPDP Rules 2025 §13.

use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{consent, hash_vpa, AppState};

// ── Shared time helper ────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NomineeRecord {
    pub nominee_name:    String,
    pub nominee_contact: String,
    pub nominated_at:    u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrievanceStatus {
    Pending,
    Resolved,
}

#[derive(Debug, Clone)]
pub struct GrievanceRecord {
    pub grievance_id:  String,
    pub vpa_hash:      String,
    pub stated_reason: String,
    pub filed_at:      u64,
    pub deadline:      u64,
    pub status:        GrievanceStatus,
}

// ── §12(a) — Access ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AccessRequest {
    pub vpa:           String,
    pub consent_token: Option<String>,
}

/// Return all data Varaksha holds for a VPA — risk score, rate window, any
/// open grievances, and any registered nominee.
#[post("/v1/dpr/access")]
pub async fn dpr_access(
    data: web::Data<Arc<AppState>>,
    body: web::Json<AccessRequest>,
) -> impl Responder {
    let trace_id = Uuid::new_v4().to_string();

    if let Err(e) = data
        .consent_manager
        .verify(body.consent_token.as_ref(), &trace_id)
        .await
    {
        return dpr_consent_error(e, &trace_id);
    }

    let vpa_hash = hash_vpa(&body.vpa);
    let (risk_score, reason) = data.cache.get(&vpa_hash);

    let rate_info = data.rate_limiter.get(&vpa_hash).map(|e| {
        serde_json::json!({
            "requests_in_window": e.0,
            "window_age_secs":    e.1.elapsed().as_secs(),
        })
    });

    let nominee = data.nominations.get(&vpa_hash).map(|n| {
        serde_json::json!({
            "nominee_name":    n.nominee_name.clone(),
            "nominee_contact": n.nominee_contact.clone(),
            "nominated_at":    n.nominated_at,
        })
    });

    let open_grievances: Vec<_> = data
        .grievances
        .iter()
        .filter(|entry| entry.value().vpa_hash == vpa_hash)
        .map(|entry| {
            let g = entry.value();
            serde_json::json!({
                "grievance_id":  g.grievance_id.clone(),
                "stated_reason": g.stated_reason.clone(),
                "filed_at":      g.filed_at,
                "deadline":      g.deadline,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "trace_id":        trace_id,
        "vpa_hash":        vpa_hash,
        "data_held": {
            "risk_score":  risk_score,
            "reason":      reason,
        },
        "rate_window":     rate_info,
        "nominee":         nominee,
        "open_grievances": open_grievances,
        "legal_basis":     "DPDP Act 2023 §12(a) — right of access",
        "data_fiduciary":  "Varaksha Risk Gateway v0.2.0",
        "retrieved_at":    unix_now(),
    }))
}

// ── §12(b) — Correction ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CorrectionRequest {
    pub vpa:           String,
    pub consent_token: Option<String>,
    /// The Data Principal's explanation of why the risk classification is wrong.
    pub stated_reason: String,
}

/// File a grievance disputing the risk classification for a VPA.
/// Risk scores are recomputed by the ML pipeline; a human reviewer will
/// reassess within the 90-day deadline mandated by DPDP Rules 2025 §13.
#[post("/v1/dpr/correction")]
pub async fn dpr_correction(
    data: web::Data<Arc<AppState>>,
    body: web::Json<CorrectionRequest>,
) -> impl Responder {
    let trace_id     = Uuid::new_v4().to_string();
    let grievance_id = Uuid::new_v4().to_string();

    if let Err(e) = data
        .consent_manager
        .verify(body.consent_token.as_ref(), &trace_id)
        .await
    {
        return dpr_consent_error(e, &trace_id);
    }

    let vpa_hash = hash_vpa(&body.vpa);
    let deadline  = unix_now() + 90 * 86_400; // DPDP Rules 2025 §13

    let record = GrievanceRecord {
        grievance_id:  grievance_id.clone(),
        vpa_hash:      vpa_hash.clone(),
        stated_reason: body.stated_reason.clone(),
        filed_at:      unix_now(),
        deadline,
        status:        GrievanceStatus::Pending,
    };

    data.grievances.insert(grievance_id.clone(), record);

    log::info!(
        "[{}] DPR §12(b) correction filed — hash={} grievance_id={}",
        trace_id, vpa_hash, grievance_id
    );

    HttpResponse::Accepted().json(serde_json::json!({
        "trace_id":            trace_id,
        "grievance_id":        grievance_id,
        "vpa_hash":            vpa_hash,
        "status":              "PENDING",
        "resolution_deadline": deadline,
        "note": "Risk scores are recalculated by the ML pipeline. A reviewer will \
                 reassess the classification within the 90-day deadline mandated \
                 by DPDP Rules 2025 §13.",
        "legal_basis": "DPDP Act 2023 §12(b) — right of correction",
    }))
}

// ── §12(b) — Erasure ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ErasureRequest {
    pub vpa:           String,
    pub consent_token: Option<String>,
}

/// Permanently delete all Varaksha records for a VPA: risk cache entry,
/// rate-limiter window, and any registered nominee.
#[post("/v1/dpr/erasure")]
pub async fn dpr_erasure(
    data: web::Data<Arc<AppState>>,
    body: web::Json<ErasureRequest>,
) -> impl Responder {
    let trace_id = Uuid::new_v4().to_string();

    if let Err(e) = data
        .consent_manager
        .verify(body.consent_token.as_ref(), &trace_id)
        .await
    {
        return dpr_consent_error(e, &trace_id);
    }

    let vpa_hash    = hash_vpa(&body.vpa);
    let had_cache   = data.cache.remove(&vpa_hash);
    let had_rate    = data.rate_limiter.remove(&vpa_hash).is_some();
    let had_nominee = data.nominations.remove(&vpa_hash).is_some();

    log::info!(
        "[{}] DPR §12(b) erasure — hash={} cache={} rate={} nomination={}",
        trace_id, vpa_hash, had_cache, had_rate, had_nominee
    );

    HttpResponse::Ok().json(serde_json::json!({
        "trace_id":  trace_id,
        "vpa_hash":  vpa_hash,
        "erased": {
            "risk_cache":  had_cache,
            "rate_window": had_rate,
            "nomination":  had_nominee,
        },
        "erased_at":   unix_now(),
        "legal_basis": "DPDP Act 2023 §12(b) — right of erasure",
    }))
}

// ── §12(d) — Nomination ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NominationRequest {
    pub vpa:             String,
    pub consent_token:   Option<String>,
    pub nominee_name:    String,
    /// Phone or email of the nominee — stored in-memory only, never logged.
    pub nominee_contact: String,
}

/// Register a nominee who may exercise §12(a)–(c) rights on the Data
/// Principal's behalf in the event of their death or incapacity.
#[post("/v1/dpr/nomination")]
pub async fn dpr_nomination(
    data: web::Data<Arc<AppState>>,
    body: web::Json<NominationRequest>,
) -> impl Responder {
    let trace_id      = Uuid::new_v4().to_string();
    let nomination_id = Uuid::new_v4().to_string();

    if let Err(e) = data
        .consent_manager
        .verify(body.consent_token.as_ref(), &trace_id)
        .await
    {
        return dpr_consent_error(e, &trace_id);
    }

    let vpa_hash = hash_vpa(&body.vpa);

    let record = NomineeRecord {
        nominee_name:    body.nominee_name.clone(),
        nominee_contact: body.nominee_contact.clone(),
        nominated_at:    unix_now(),
    };

    data.nominations.insert(vpa_hash.clone(), record);

    // nominee_contact is intentionally NOT logged to avoid PII in log files
    log::info!(
        "[{}] DPR §12(d) nomination recorded — hash={}",
        trace_id, vpa_hash
    );

    HttpResponse::Ok().json(serde_json::json!({
        "trace_id":      trace_id,
        "nomination_id": nomination_id,
        "vpa_hash":      vpa_hash,
        "nominee_name":  body.nominee_name,
        "nominated_at":  unix_now(),
        "legal_basis":   "DPDP Act 2023 §12(d) — right to nominate",
        "note": "The nominee may exercise §12(a)–(c) rights on your behalf \
                 in the event of your death or incapacity.",
    }))
}

// ── Shared error helper ───────────────────────────────────────────────────────

pub fn dpr_consent_error(e: consent::ConsentError, trace_id: &str) -> HttpResponse {
    match e {
        consent::ConsentError::TokenMissing => {
            HttpResponse::UnprocessableEntity().json(serde_json::json!({
                "error":    "CONSENT_REQUIRED",
                "detail":   "Provide your AA consent_token to exercise DPDP §12 rights.",
                "trace_id": trace_id,
            }))
        }
        consent::ConsentError::NotActive(status) => {
            HttpResponse::Forbidden().json(serde_json::json!({
                "error":    "CONSENT_NOT_ACTIVE",
                "detail":   format!("Consent artefact is not active (status={status})."),
                "trace_id": trace_id,
            }))
        }
        err => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error":    "CONSENT_CHECK_FAILED",
            "detail":   format!("{err}"),
            "trace_id": trace_id,
        })),
    }
}
