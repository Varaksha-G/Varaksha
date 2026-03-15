mod models;

use actix_cors::Cors;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use async_stream::stream;
use hmac::{Hmac, Mac};
use models::{CacheEntryView, CacheUpdateRequest, CacheUpdateResponse, TxRequest, TxResponse, Verdict};
use rand::Rng;
use reqwest::Client;
use risk_cache::RiskCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use dashmap::DashMap;

type HmacSha256 = Hmac<Sha256>;

struct AppState {
    cache: RiskCache,
    rate_limiter: DashMap<String, (u32, Instant)>,
    http_client: Client,
    sidecar_url: String,
}

#[derive(Debug, Serialize)]
struct StreamEvent {
    time: String,
    sender: String,
    receiver: String,
    amount: f32,
    category: String,
    risk: f32,
    verdict: String,
}

#[derive(Debug, Serialize)]
struct SidecarRequest {
    merchant_category: i32,
    transaction_type: i32,
    device_type: i32,
    amount: f32,
    hour_of_day: i32,
    day_of_week: i32,
    transactions_last_1h: i32,
    transactions_last_24h: i32,
    amount_zscore: f32,
    gps_delta_km: f32,
    is_new_device: i32,
    is_new_merchant: i32,
    balance_drain_ratio: f32,
    account_age_days: i32,
    previous_failed_attempts: i32,
    transfer_cashout_flag: i32,
}

#[derive(Debug, Deserialize)]
struct SidecarResponse {
    risk_score: f32,
    reason: String,
}

fn merchant_code(v: &str) -> i32 {
    match v.to_ascii_uppercase().as_str() {
        "ECOM" => 0,
        "FOOD" => 1,
        "GAMBLING" => 2,
        "P2P" => 3,
        "TRAVEL" => 4,
        "UTILITY" => 5,
        _ => 0,
    }
}

fn tx_type_code(v: &str) -> i32 {
    match v.to_ascii_uppercase().as_str() {
        "CREDIT" => 0,
        "DEBIT" => 1,
        _ => 1,
    }
}

fn device_code(v: &str) -> i32 {
    match v.to_ascii_uppercase().as_str() {
        "ANDROID" => 0,
        "IOS" => 1,
        "WEB" => 2,
        _ => 2,
    }
}

fn normalise_vpa(vpa: &str) -> String {
    if let Some(at) = vpa.find('@') {
        let handle = &vpa[..at];
        let bank = &vpa[at + 1..];
        if handle.len() >= 10 && handle.chars().all(|c| c.is_ascii_digit()) {
            return format!("{}****{}@{}", &handle[..2], &handle[handle.len() - 2..], bank);
        }
        if handle.len() == 8
            && handle[..2].chars().all(|c| c.is_ascii_digit())
            && &handle[2..6] == "****"
            && handle[6..].chars().all(|c| c.is_ascii_digit())
        {
            return vpa.to_string();
        }
    }
    vpa.to_string()
}

fn hash_vpa(vpa: &str) -> String {
    let canonical = normalise_vpa(vpa);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
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

fn verdict_text(v: &Verdict) -> String {
    match v {
        Verdict::Allow => "ALLOW".to_string(),
        Verdict::Flag => "FLAG".to_string(),
        Verdict::Block => "BLOCK".to_string(),
    }
}

fn build_sidecar_payload(tx: &TxRequest) -> SidecarRequest {
    SidecarRequest {
        merchant_category: merchant_code(&tx.merchant_category),
        transaction_type: tx_type_code(&tx.transaction_type),
        device_type: device_code(&tx.device_type),
        amount: tx.amount,
        hour_of_day: tx.hour_of_day,
        day_of_week: tx.day_of_week,
        transactions_last_1h: tx.transactions_last_1h,
        transactions_last_24h: tx.transactions_last_24h,
        amount_zscore: tx.amount_zscore,
        gps_delta_km: tx.gps_delta_km,
        is_new_device: if tx.is_new_device { 1 } else { 0 },
        is_new_merchant: if tx.is_new_merchant { 1 } else { 0 },
        balance_drain_ratio: tx.balance_drain_ratio,
        account_age_days: tx.account_age_days,
        previous_failed_attempts: tx.previous_failed_attempts,
        transfer_cashout_flag: tx.transfer_cashout_flag,
    }
}

async fn score_via_sidecar(state: &AppState, tx: &TxRequest) -> Result<(f32, String), String> {
    let payload = build_sidecar_payload(tx);

    let resp = state
        .http_client
        .post(&state.sidecar_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("sidecar request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("sidecar http status {}", resp.status()));
    }

    let parsed: SidecarResponse = resp
        .json()
        .await
        .map_err(|e| format!("sidecar parse failed: {e}"))?;

    Ok((parsed.risk_score, parsed.reason))
}

#[get("/health")]
async fn health(data: web::Data<Arc<AppState>>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "cache_entries": data.cache.len(),
        "version": "2.1.0"
    }))
}

#[post("/v1/tx")]
async fn check_tx(data: web::Data<Arc<AppState>>, body: web::Json<TxRequest>) -> impl Responder {
    let started = Instant::now();
    let trace_id = Uuid::new_v4().to_string();
    let tx = body.into_inner();
    let vpa_hash = hash_vpa(&tx.vpa);

    {
        const CAP: u32 = 100;
        const WINDOW: Duration = Duration::from_secs(86_400);
        let mut entry = data
            .rate_limiter
            .entry(vpa_hash.clone())
            .or_insert((0u32, Instant::now()));

        if entry.1.elapsed() >= WINDOW {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
            if entry.0 > CAP {
                drop(entry);
                return HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": "RATE_LIMIT_EXCEEDED",
                    "detail": "NPCI OC-215/2025-26: daily scoring request cap for this VPA exceeded.",
                    "trace_id": trace_id,
                }));
            }
        }
    }

    let (mut risk_score, mut reason) = data.cache.get(&vpa_hash);

    if reason == "cold" {
        match score_via_sidecar(data.get_ref().as_ref(), &tx).await {
            Ok((s, r)) => {
                risk_score = s;
                reason = r.clone();
                data.cache.upsert(vpa_hash.clone(), s, r, 300);
            }
            Err(e) => {
                return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                    "error": "SIDECAR_UNAVAILABLE",
                    "detail": e,
                    "trace_id": trace_id,
                }));
            }
        }
    }

    let verdict = score_to_verdict(risk_score);
    let latency = started.elapsed().as_micros() as u64;

    log::info!(
        "[{}] tx hash={} score={:.3} verdict={} reason={}",
        trace_id,
        vpa_hash,
        risk_score,
        verdict_text(&verdict),
        reason
    );

    HttpResponse::Ok().json(TxResponse {
        vpa_hash,
        verdict,
        risk_score,
        trace_id,
        latency_us: latency,
    })
}

#[get("/v1/cache")]
async fn list_cache(data: web::Data<Arc<AppState>>) -> impl Responder {
    let entries: Vec<CacheEntryView> = data
        .cache
        .snapshot(100)
        .into_iter()
        .map(|(key, val)| CacheEntryView {
            key,
            risk_score: val.risk_score,
            reason: val.reason,
            updated_at: val.updated_at,
        })
        .collect();

    HttpResponse::Ok().json(entries)
}

#[get("/v1/stream")]
async fn stream_tx(data: web::Data<Arc<AppState>>) -> impl Responder {
    let state = Arc::clone(data.get_ref());

    let event_stream = stream! {
        let senders = [
            "ravi.kumar@axisbank",
            "priya.sharma@okicici",
            "suresh.patel@ybl",
            "anita.rao@axisbank",
            "mohan.verma@okhdfc",
            "kavitha.n@paytm",
        ];
        let receivers = [
            "kirana.store@okhdfc",
            "dmart.retail@ybl",
            "fuel.pump@okaxis",
            "zomato.pay@okicici",
            "auto.rickshaw@paytm",
            "loan.repay@axisbank",
        ];
        let cats = ["FOOD", "UTILITY", "TRAVEL", "P2P", "ECOM", "GAMBLING"];

        loop {
            let mut rng = rand::thread_rng();
            let tx = TxRequest {
                vpa: senders[rng.gen_range(0..senders.len())].to_string(),
                amount: [120.0, 499.0, 1100.0, 4750.0, 8900.0, 35000.0, 65000.0][rng.gen_range(0..7)],
                merchant_category: cats[rng.gen_range(0..cats.len())].to_string(),
                transaction_type: "DEBIT".to_string(),
                device_type: ["ANDROID", "IOS", "WEB"][rng.gen_range(0..3)].to_string(),
                hour_of_day: rng.gen_range(0..24),
                day_of_week: rng.gen_range(0..7),
                transactions_last_1h: rng.gen_range(0..15),
                transactions_last_24h: rng.gen_range(0..65),
                amount_zscore: rng.gen_range(-1.0..4.5),
                gps_delta_km: rng.gen_range(0.0..900.0),
                is_new_device: rng.gen_bool(0.25),
                is_new_merchant: rng.gen_bool(0.2),
                balance_drain_ratio: rng.gen_range(0.0..1.0),
                account_age_days: rng.gen_range(0..3650),
                previous_failed_attempts: rng.gen_range(0..13),
                transfer_cashout_flag: if rng.gen_bool(0.12) { 1 } else { 0 },
                consent_token: None,
            };

            let now = chrono::Local::now().format("%H:%M:%S").to_string();
            let receiver_vpa = receivers[rng.gen_range(0..receivers.len())].to_string();
            let sender_hash = hash_vpa(&tx.vpa);
            let receiver_hash = hash_vpa(&receiver_vpa);
            let sender = format!("tx_{}", &sender_hash[..12]);
            let receiver = format!("rx_{}", &receiver_hash[..12]);
            let amount = tx.amount;
            let category = tx.merchant_category.clone();

            let vpa_hash = sender_hash;
            let (risk_score, reason) = match score_via_sidecar(state.as_ref(), &tx).await {
                Ok(v) => v,
                Err(_) => (0.0, "sidecar unavailable".to_string()),
            };
            state.cache.upsert(vpa_hash, risk_score, reason, 300);
            let verdict = verdict_text(&score_to_verdict(risk_score));

            let evt = StreamEvent {
                time: now,
                sender,
                receiver,
                amount,
                category,
                risk: risk_score,
                verdict,
            };

            let payload = serde_json::to_string(&evt).unwrap_or_else(|_| "{}".to_string());
            yield Ok::<_, actix_web::Error>(web::Bytes::from(format!("data: {}\n\n", payload)));

            sleep(Duration::from_millis(1500)).await;
        }
    };

    HttpResponse::Ok()
        .append_header(("Content-Type", "text/event-stream"))
        .append_header(("Cache-Control", "no-cache"))
        .append_header(("Connection", "keep-alive"))
        .streaming(event_stream)
}

#[post("/v1/webhook/update_cache")]
async fn update_cache(req: actix_web::HttpRequest, data: web::Data<Arc<AppState>>, body: web::Json<CacheUpdateRequest>) -> impl Responder {
    let trace_id = Uuid::new_v4().to_string();
    let update = body.into_inner();

    let sig_header = match req.headers().get("x-varaksha-sig") {
        Some(v) => v,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let secret = std::env::var("VARAKSHA_WEBHOOK_SECRET")
        .unwrap_or_else(|_| "dev-secret-change-me".to_string());

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

    let sig_bytes = match hex::decode(sig_header.to_str().unwrap_or("")) {
        Ok(v) => v,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    if mac.verify_slice(&sig_bytes).is_err() {
        return HttpResponse::Unauthorized().finish();
    }

    data.cache.upsert(
        update.vpa_hash.clone(),
        update.risk_score,
        update.reason.clone(),
        update.ttl_seconds,
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
        rate_limiter: DashMap::new(),
        http_client: Client::new(),
        sidecar_url: std::env::var("SIDECAR_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8001/score".to_string()),
    });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "7860".to_string())
        .parse()
        .unwrap_or(7860);
    let bind_addr = format!("0.0.0.0:{}", port);

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(Arc::clone(&state)))
            .service(health)
            .service(check_tx)
            .service(list_cache)
            .service(stream_tx)
            .service(update_cache)
    })
    .bind(bind_addr)?
    .run()
    .await
}
