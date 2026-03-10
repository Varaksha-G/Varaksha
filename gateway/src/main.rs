mod models;

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

use models::{CacheUpdateRequest, CacheUpdateResponse, TxRequest, TxResponse, Verdict};

use risk_cache::RiskCache;

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use uuid::Uuid;

use std::sync::Arc;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

struct AppState {
    cache: RiskCache,
}

fn hash_vpa(vpa: &str) -> String {

    let mut hasher = Sha256::new();

    hasher.update(vpa.as_bytes());

    hex::encode(hasher.finalize())
}

fn score_to_verdict(score: f32) -> Verdict {

    if score >= 0.75 {
        Verdict::Block
    } else if score >= 0.40 {
        Verdict::Flag
    } else {
        Verdict::Allow
    }
}

#[get("/health")]
async fn health(data: web::Data<Arc<AppState>>) -> impl Responder {

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "cache_entries": data.cache.len(),
        "version": "2.0.0"
    }))
}

#[post("/v1/tx")]
async fn check_tx(
    data: web::Data<Arc<AppState>>,
    body: web::Json<TxRequest>,
) -> impl Responder {

    let started = Instant::now();

    let trace_id = Uuid::new_v4().to_string();

    let tx = body.into_inner();

    let vpa_hash = hash_vpa(&tx.vpa);

    let (risk_score, reason) = data.cache.get(&vpa_hash);

    let verdict = score_to_verdict(risk_score);

    let latency = started.elapsed().as_micros() as u64;

    if verdict == Verdict::Block {

        log::warn!(
            "[{}] BLOCKED tx hash={} score={:.3} reason={}",
            trace_id,
            vpa_hash,
            risk_score,
            reason
        );
    }

    HttpResponse::Ok().json(TxResponse {
        vpa_hash,
        verdict,
        risk_score,
        trace_id,
        latency_us: latency,
    })
}

#[post("/v1/webhook/update_cache")]
async fn update_cache(
    req: HttpRequest,
    data: web::Data<Arc<AppState>>,
    body: web::Json<CacheUpdateRequest>,
) -> impl Responder {

    let trace_id = Uuid::new_v4().to_string();

    let update = body.into_inner();

    let sig_header = match req.headers().get("x-varaksha-sig") {
        Some(v) => v,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let secret = std::env::var("VARAKSHA_WEBHOOK_SECRET")
        .expect("VARAKSHA_WEBHOOK_SECRET must be set");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    let payload = format!(
        "{}:{}:{}:{}",
        update.vpa_hash,
        update.risk_score,
        update.reason,
        update.ttl_seconds
    );

    mac.update(payload.as_bytes());

    let sig_bytes = hex::decode(sig_header.to_str().unwrap()).unwrap();

    if mac.verify_slice(&sig_bytes).is_err() {

        log::warn!("invalid webhook signature");

        return HttpResponse::Unauthorized().finish();
    }

    data.cache.upsert(
        update.vpa_hash.clone(),
        update.risk_score,
        update.reason.clone(),
        update.ttl_seconds,
    );

    log::info!(
        "[{}] cache update hash={} score={:.3} reason={}",
        trace_id,
        update.vpa_hash,
        update.risk_score,
        update.reason
    );

    HttpResponse::Ok().json(CacheUpdateResponse {
        ok: true,
        vpa_hash: update.vpa_hash,
        trace_id,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    env_logger::init();

    let state = Arc::new(AppState {
        cache: RiskCache::new(),
    });

    let port = std::env::var("GATEWAY_PORT")
        .unwrap_or_else(|_| "8082".to_string())
        .parse::<u16>()
        .unwrap();

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