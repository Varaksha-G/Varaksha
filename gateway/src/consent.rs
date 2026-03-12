//! DPDP Act 2023 §4(1) — Consent Manager client
//!
//! Implements the Sahamati / ReBIT Account Aggregator (AA) consent verification
//! API as specified in the ReBIT AA API v2.0 spec:
//!   https://api.rebit.org.in/
//!
//! # AA Ecosystem overview
//!
//! The Account Aggregator framework (RBI circular RBI/2016-17/8 DNBR.PD(FSD)
//! CC.No.058/03.10.119/2016-17) defines a Consent Manager (CM) role.
//! Registered AAs include Finvu, OneMoney, CAMS Finserv, NADL.  All expose
//! the same ReBIT-standardised REST API so this client works with any of them.
//!
//! # Configuration (environment variables)
//!
//! | Variable                     | Required  | Description                                      |
//! |------------------------------|-----------|--------------------------------------------------|
//! | `CONSENT_MANAGER_BASE_URL`   | Yes       | Base URL of your AA, e.g. `https://api.finvu.in` |
//! | `CONSENT_MANAGER_API_KEY`    | Yes       | API key / client-credential issued by the AA     |
//! | `CONSENT_MANAGER_FI_ID`      | Yes       | Your FI (Financial Information User) entity ID   |
//! | `DPDP_CONSENT_DEV_BYPASS`    | No        | Set to `"true"` in local dev to skip CM call     |
//!
//! # DPDP_CONSENT_DEV_BYPASS
//!
//! When `DPDP_CONSENT_DEV_BYPASS=true` the client logs a loud WARNING and
//! returns `Ok(())` without contacting the AA.  This lets local development
//! proceed without live CM credentials but makes it impossible to accidentally
//! run this mode in production (the env var is never set on the production host).
//!
//! # Consent purpose
//!
//! Every call passes `purpose_code = "101"` — the ReBIT standardised code for
//! "Fraud Risk Management" under Category D (Other) in the AA Technical
//! Specifications v2.0.  If your AA uses a non-standard code, override with the
//! `CONSENT_PURPOSE_CODE` env var.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── AA API request/response types ─────────────────────────────────────────────

/// Body for `POST /v2/Consent/fetch` — ReBIT AA API v2.0 §4.3
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsentFetchRequest {
    /// Consent Artefact Handle issued to the Data Principal by the AA.
    consent_handle: String,
    /// Your FI (Financial Information User) entity ID registered with Sahamati.
    fi_id: String,
    /// The purpose code for which consent is being verified.
    purpose_code: String,
}

/// Top-level response from `POST /v2/Consent/fetch`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsentFetchResponse {
    consent_status: ConsentStatus,
    consent_id: String,
    /// Epoch milliseconds at which the consent expires.
    expiry_time: Option<u64>,
}

/// Status field within a consent fetch response.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ConsentStatus {
    Active,
    Revoked,
    Paused,
    Expired,
    Pending,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by consent verification.
#[derive(Debug)]
pub enum ConsentError {
    /// Required environment variable is not set.
    MissingConfig(&'static str),
    /// `consent_token` field was absent or empty in the request.
    TokenMissing,
    /// The AA returned a non-ACTIVE status for this consent artefact.
    NotActive(String),     // carries the actual status string for logging
    /// HTTP/network error while contacting the AA.
    Transport(reqwest::Error),
    /// The AA returned an unexpected HTTP status code.
    BadStatus(u16, String), // (status_code, response_body)
}

impl std::fmt::Display for ConsentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsentError::MissingConfig(v) => write!(f, "Missing env var: {v}"),
            ConsentError::TokenMissing      => write!(f, "consent_token is absent or empty"),
            ConsentError::NotActive(s)      => write!(f, "Consent not ACTIVE: status={s}"),
            ConsentError::Transport(e)      => write!(f, "CM transport error: {e}"),
            ConsentError::BadStatus(c, b)   => write!(f, "CM HTTP {c}: {b}"),
        }
    }
}

impl From<reqwest::Error> for ConsentError {
    fn from(e: reqwest::Error) -> Self {
        ConsentError::Transport(e)
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Consent Manager client — instantiated once at startup and shared via
/// `Arc<AppState>`.
pub struct ConsentManagerClient {
    http:         Client,
    base_url:     String,
    api_key:      String,
    fi_id:        String,
    purpose_code: String,
    dev_bypass:   bool,
}

impl ConsentManagerClient {
    /// Build from environment variables.  Returns `Err` if any required var
    /// is absent AND `DPDP_CONSENT_DEV_BYPASS` is not set to `"true"`.
    pub fn from_env() -> Result<Self, ConsentError> {
        let dev_bypass = std::env::var("DPDP_CONSENT_DEV_BYPASS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if dev_bypass {
            log::warn!(
                "⚠  DPDP_CONSENT_DEV_BYPASS=true — consent validation is DISABLED. \
                 NEVER use this setting in production."
            );
            // Return a client with placeholder values; verify() will short-circuit.
            return Ok(Self {
                http:         Client::new(),
                base_url:     String::new(),
                api_key:      String::new(),
                fi_id:        String::new(),
                purpose_code: String::new(),
                dev_bypass:   true,
            });
        }

        let base_url = std::env::var("CONSENT_MANAGER_BASE_URL")
            .map_err(|_| ConsentError::MissingConfig("CONSENT_MANAGER_BASE_URL"))?;
        let api_key = std::env::var("CONSENT_MANAGER_API_KEY")
            .map_err(|_| ConsentError::MissingConfig("CONSENT_MANAGER_API_KEY"))?;
        let fi_id = std::env::var("CONSENT_MANAGER_FI_ID")
            .map_err(|_| ConsentError::MissingConfig("CONSENT_MANAGER_FI_ID"))?;
        let purpose_code = std::env::var("CONSENT_PURPOSE_CODE")
            .unwrap_or_else(|_| "101".to_string()); // ReBIT code 101 = Fraud Risk Management

        let http = Client::builder()
            .timeout(Duration::from_secs(3)) // tight budget — consent check must not stall payments
            .use_rustls_tls()
            .build()
            .expect("reqwest client build should not fail");

        Ok(Self { http, base_url, api_key, fi_id, purpose_code, dev_bypass })
    }

    /// Verify that a consent artefact is ACTIVE and covers the required purpose.
    ///
    /// # Parameters
    /// - `token`     — the `consent_token` from the `TxRequest`
    /// - `trace_id`  — used for structured log entries only (not sent to AA)
    ///
    /// # Returns
    /// - `Ok(consent_id)` — the CM-internal consent ID; caller MUST log this
    ///   alongside `trace_id` to satisfy the §12(a) access-rights audit trail.
    /// - `Err(ConsentError)` — caller must translate to an HTTP error response.
    ///
    /// # DPDP obligations satisfied
    /// - §4(1): processing only happens after consent is confirmed ACTIVE
    /// - §6(3): purpose is verified at the CM (must match "fraud-risk-check" /
    ///   purpose code 101)
    /// - §12(a): `consent_id` is returned so callers can log it against the
    ///   transaction trace_id for the audit trail
    pub async fn verify(
        &self,
        token: Option<&String>,
        trace_id: &str,
    ) -> Result<String, ConsentError> {
        // ── Dev bypass ────────────────────────────────────────────────────────
        if self.dev_bypass {
            log::warn!(
                "[{trace_id}] DPDP consent check BYPASSED (dev mode). \
                 Token presented: {}",
                token.map(|t| t.as_str()).unwrap_or("<none>")
            );
            return Ok("DEV-BYPASS".to_string());
        }

        // ── Token presence check ──────────────────────────────────────────────
        let consent_handle = match token {
            Some(t) if !t.trim().is_empty() => t.as_str(),
            _ => return Err(ConsentError::TokenMissing),
        };

        log::debug!(
            "[{trace_id}] verifying consent handle={} purpose={}",
            consent_handle,
            self.purpose_code
        );

        // ── Call AA: POST /v2/Consent/fetch ───────────────────────────────────
        let url = format!("{}/v2/Consent/fetch", self.base_url);

        let body = ConsentFetchRequest {
            consent_handle: consent_handle.to_string(),
            fi_id:           self.fi_id.clone(),
            purpose_code:    self.purpose_code.clone(),
        };

        let resp = self.http
            .post(&url)
            .header("x-jws-signature", &self.api_key) // AA client-credential header
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();

        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            log::warn!(
                "[{trace_id}] CM returned HTTP {status} for handle={consent_handle}: {body_text}"
            );
            return Err(ConsentError::BadStatus(status.as_u16(), body_text));
        }

        // ── Parse response ────────────────────────────────────────────────────
        let payload: ConsentFetchResponse = resp.json().await?;

        log::debug!(
            "[{trace_id}] CM response consent_id={} status={:?}",
            payload.consent_id,
            payload.consent_status
        );

        // ── Status check ──────────────────────────────────────────────────────
        if payload.consent_status != ConsentStatus::Active {
            let status_str = format!("{:?}", payload.consent_status);
            log::warn!(
                "[{trace_id}] Consent not ACTIVE: id={} handle={} status={status_str}",
                payload.consent_id,
                consent_handle
            );
            return Err(ConsentError::NotActive(status_str));
        }

        // ── Expiry sanity check ───────────────────────────────────────────────
        // Belt-and-suspenders: the AA should not return ACTIVE for an expired
        // artefact, but we check locally too to guard against clock skew on the
        // AA side.
        if let Some(expiry_ms) = payload.expiry_time {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if expiry_ms < now_ms {
                log::warn!(
                    "[{trace_id}] Consent expired locally: id={} expiry_epoch_ms={expiry_ms}",
                    payload.consent_id
                );
                return Err(ConsentError::NotActive("EXPIRED_LOCAL_CHECK".to_string()));
            }
        }

        log::info!(
            "[{trace_id}] Consent VERIFIED: id={} handle={} purpose={}",
            payload.consent_id,
            consent_handle,
            self.purpose_code
        );

        Ok(payload.consent_id)
    }
}
