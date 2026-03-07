// gateway/src/main.rs
// ─────────────────────────────────────────────────────────────────────────────
// Varaksha V2 — Layer 2: Real-Time Consortium Risk Cache Gateway
// Built with Actix-Web 4 + DashMap
//
// Endpoints:
//   GET  /health                       → liveness probe
//   POST /v1/tx                        → real-time transaction risk check
//   POST /v1/webhook/update_cache      → async cache update from graph layer
//
// TODO [teammate — IMPLEMENTATION CHECKLIST]:
//   [ ] Fill in `check_tx` handler (src/main.rs, marked below)
//   [ ] Fill in `update_cache` handler (src/main.rs, marked below)
//   [ ] Fill in RiskCache::get()   (src/cache.rs)
//   [ ] Fill in RiskCache::upsert() (src/cache.rs)
//   [ ] Verify HMAC-SHA256 on update_cache requests (see models.rs comments)
//   [ ] Test: `cargo run` then `curl -X POST http://localhost:8082/v1/tx ...`
//
// Latency target: POST /v1/tx must return in < 5 ms (P99).
// ─────────────────────────────────────────────────────────────────────────────

mod cache;
mod models;

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use cache::RiskCache;
use models::{CacheUpdateRequest, CacheUpdateResponse, TxRequest, TxResponse, Verdict};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

// ── Shared application state ─────────────────────────────────────────────────

struct AppState {
    cache: RiskCache,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// SHA-256 hash a VPA string and return the lowercase hex digest.
/// This is the ONLY place raw VPAs should appear in the Rust process.
fn hash_vpa(vpa: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vpa.as_bytes());
    hex::encode(hasher.finalize())
}

/// Map a numeric risk score to a Verdict.
fn score_to_verdict(score: f32) -> Verdict {
    if score >= 0.75 {
        Verdict::Block
    } else if score >= 0.40 {
        Verdict::Flag
    } else {
        Verdict::Allow
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /health  — liveness probe (always returns 200).
#[get("/health")]
async fn health(data: web::Data<Arc<AppState>>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "cache_entries": data.cache.len(),
        "version": "2.0.0"
    }))
}

/// POST /v1/tx  — real-time transaction risk check.
///
/// TODO [teammate]:
///   1. Parse the JSON body into TxRequest (already done below via `tx`).
///   2. Call `hash_vpa(&tx.vpa)` to get the vpa_hash.
///   3. Call `data.cache.get(&vpa_hash)` to retrieve (risk_score, reason).
///   4. Call `score_to_verdict(risk_score)` to get the Verdict.
///   5. Record `latency_us` using the `started` Instant below.
///   6. Return a `TxResponse` as JSON with HTTP 200.
///
///   Extra credit: if verdict == Block, log the trace_id + vpa_hash + reason
///   at WARN level so it appears in any SIEM log aggregator.
#[post("/v1/tx")]
async fn check_tx(
    data: web::Data<Arc<AppState>>,
    body: web::Json<TxRequest>,
) -> impl Responder {
    let started   = Instant::now();
    let trace_id  = Uuid::new_v4().to_string();
    let tx        = body.into_inner();

    // TODO [teammate]: implement steps 2-6 described above.
    // The stub below compiles but always returns ALLOW with score 0.0.

    let vpa_hash  = hash_vpa(&tx.vpa);
    let (risk_score, _reason) = data.cache.get(&vpa_hash); // TODO: use _reason in logging
    let verdict   = score_to_verdict(risk_score);
    let latency   = started.elapsed().as_micros() as u64;

    HttpResponse::Ok().json(TxResponse {
        vpa_hash,
        verdict,
        risk_score,
        trace_id,
        latency_us: latency,
    })
}

/// POST /v1/webhook/update_cache  — receive a risk score update from Python.
///
/// TODO [teammate]:
///   1. Extract the `x-varaksha-sig` header from `req`.
///   2. Recompute HMAC-SHA256 over the raw request body using the shared
///      secret in env var $VARAKSHA_WEBHOOK_SECRET.
///   3. Compare digests in constant time (use `hmac::Mac::verify_slice`).
///      If mismatch → return HTTP 401.
///   4. Parse body into CacheUpdateRequest.
///   5. Call `data.cache.upsert(...)`.
///   6. Return CacheUpdateResponse with ok=true.
#[post("/v1/webhook/update_cache")]
async fn update_cache(
    req:  HttpRequest,
    data: web::Data<Arc<AppState>>,
    body: web::Json<CacheUpdateRequest>,
) -> impl Responder {
    let trace_id = Uuid::new_v4().to_string();
    let update   = body.into_inner();

    // TODO [teammate]: step 1-3 (HMAC verification).
    // Skipping for now — MUST be implemented before production use.
    let _sig_header = req.headers().get("x-varaksha-sig");

    // TODO [teammate]: step 5 (call upsert).
    // data.cache.upsert(
    //     update.vpa_hash.clone(),
    //     update.risk_score,
    //     update.reason.clone(),
    //     update.ttl_seconds,
    // );

    log::info!(
        "[{}] cache update stub: hash={} score={:.3} reason={}",
        trace_id, update.vpa_hash, update.risk_score, update.reason
    );

    HttpResponse::Ok().json(CacheUpdateResponse {
        ok: true,
        vpa_hash: update.vpa_hash,
        trace_id,
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let state = Arc::new(AppState {
        cache: RiskCache::new(),
    });

    let port = std::env::var("GATEWAY_PORT")
        .unwrap_or_else(|_| "8082".to_string())
        .parse::<u16>()
        .expect("GATEWAY_PORT must be a valid port number");

    log::info!("Varaksha V2 Gateway starting on port {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Arc::clone(&state)))
            .service(health)
            .service(check_tx)
            .service(update_cache)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
