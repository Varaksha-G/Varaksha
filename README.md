# Varaksha — Privacy-Preserving Collaborative UPI Fraud Intelligence Network

> **Hackathon:** Secure AI Software and Systems Hackathon (BITSGOA)
> **Problem:** Problem 1 — NPCI's UPI Fraud Detection · **Blue Team Challenge**
> **Team:** Varaksha G — *Security Engineer × ML Engineer*

---

## Problem Statement

> *The following is reproduced from the official hackathon problem statement document.*

**Problem 1 — NPCI's UPI Fraud Detection (Blue Team Challenge)**

Develop an AI/ML solution to identify fraudulent transactions in the Unified Payments Interface (UPI) system and implement defensive measures to protect legitimate transactions.

### Official Key Objectives

| # | Objective | Varaksha Implementation |
|---|---|---|
| 1 | Implement **anomaly detection** techniques to identify unusual transaction patterns | `IsolationForest` trained on 111 K rows — 16 behavioural features including hour-of-day sin/cos, amount log-transform, device-seen flag |
| 2 | Explore **ensemble methods or deep learning** to improve prediction accuracy | `RandomForest` (300 trees) fused with `IsolationForest` scores → composite risk 0–1; ROC-AUC **0.9546** |
| 3 | Address **imbalanced datasets** using techniques like SMOTE | `imblearn.SMOTE` applied to training split only; held-out test set preserves natural 42 % fraud ratio |
| 4 | Develop a **user-friendly dashboard** for visualising transaction risks and fraud alerts | Full interactive Next.js 15 web UI — live transaction feed, Security Arena, Cache Visualizer, Legal Report, and 8-language audio alert |
| 5 | Create **real-time monitoring** systems for immediate threat detection | Rust Actix-Web gateway with lock-free `DashMap` consortium cache — P99 < 5 ms verdict; async graph analysis off the hot path |

---

## What We Built & Why

UPI processes over **14 billion transactions a month**. A fraudulent ₹99,999 transfer can drain a victim's account in under 3 seconds — well before any human intervention is possible.

Varaksha G is a two-person team: one specialising in systems security, one in machine learning. Working across disciplines made clear that UPI fraud is not a single problem — it is two compounding failures:

1. **The ML side** — models trained in isolation on unbalanced data, with no shared memory of what peer institutions have already flagged.
2. **The security side** — latency-critical payment paths that cannot absorb a Python process in the synchronous loop, and alert systems that silently fail the majority of India's non-English-speaking population.

Varaksha addresses both: a privacy-preserving, multilingual fraud intelligence network where a **Rust gateway** handles the sub-10 ms verdict path, a **machine-learning ensemble** provides the risk signal, and a **graph + alert layer** delivers human-readable evidence in 8 Indian languages.

---

## Architecture

```
External UPI Client
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  Layer 2 — Rust Gateway  (port 8082)                  │
│  • DashMap consortium risk cache                      │
│  • SHA-256 VPA hashing (no PII stored)                │
│  • Verdicts: ALLOW / FLAG / BLOCK  (<5 ms P99)        │
└───────────────────┬───────────────────────────────────┘
                    │ async webhook (off critical path)
        ┌───────────┴───────────┐
        ▼                       ▼
┌──────────────┐      ┌──────────────────────────┐
│  Layer 1     │      │  Layer 3                 │
│  ML Engine   │      │  Graph Agent (NetworkX)  │
│  RF-300 + IF │      │  Fan-out / Fan-in / Cycle│
│  16 features │      │  → pushes risk to cache  │
└──────────────┘      └──────────────────────────┘
                                │
                                ▼
                    ┌──────────────────────────┐
                    │  Layer 4                 │
                    │  Accessible Alert Agent  │
                    │  LLM + Multilingual NMT  │
                    │  + edge-tts (8 languages)│
                    └──────────────────────────┘
                                │
                                ▼
                    ┌──────────────────────────┐
                    │  Layer 5 — Dashboard     │
                    │  Next.js 15 /live        │
                    │  (production web UI)     │
                    └──────────────────────────┘
```

### Why Rust for the gateway?

Placing a GIL-bound Python process inside a payment's synchronous path introduces serious tail-latency risk under burst load. Rust's `actix-web` + `DashMap` delivers lock-free concurrent reads, compile-time memory safety, and P99 < 5 ms with no JVM-style warm-up — properties that matter when a fraudulent transfer completes in under 3 seconds.

### Why a consortium cache?

A single bank sees a vanishingly small slice of a mule's activity. The `risk-cache` crate (a separate Rust workspace member) exposes a `DashMap`-backed `RiskCache` to the gateway — a VPA flagged by Bank A is immediately visible to Banks B and C on the next transaction, without either side ever exchanging raw account data (SHA-256 hashing ensures no PII crosses the network boundary).

---

## Hackathon Track Compliance

All five official Blue Team objectives from the problem statement are addressed:

| Requirement | Implementation |
|---|---|
| Anomaly Detection | IsolationForest (`services/local_engine/train_ensemble.py`) |
| Ensemble Methods | RandomForest (300 estimators) fused with IsolationForest scores |
| SMOTE for imbalanced data | `imblearn.over_sampling.SMOTE` on training split only — test set always reflects real distribution |
| User-friendly Dashboard | Next.js 15 web UI — live transaction feed, Security Arena, Cache Visualizer, Legal Report |
| Real-Time Monitoring | Rust DashMap cache — sub-5 ms lookups, async graph updates off the hot path |
| Accessibility | Pre-generated Neural TTS (edge-tts, 8 Indian languages) — works offline, no API key |
| Privacy | SHA-256 VPA hashing — raw PII never stored or transmitted |

---

## Quick Start

### 1. Install Python dependencies
```powershell
pip install -r requirements.txt
```

### 2. Train the ML models (Layer 1)
```powershell
python services/local_engine/train_ensemble.py
```
Auto-discovers all datasets under `data/datasets/` and merges them.
Pre-trained ONNX models (`varaksha_rf_model.onnx`, `isolation_forest.onnx`, `scaler.onnx`) are committed and ready to use without retraining.

### 3. Build and run the Rust gateway (Layer 2)
```powershell
cd gateway
cargo build --release
cargo run --release
# Gateway listens on http://localhost:8082
```

### 4. Run the graph agent (Layer 3)
```powershell
python services/graph/graph_agent.py --dry-run
```

### 5. Test the accessible alert agent (Layer 4)
```powershell
python services/agents/agent03_accessible_alert.py
```

### 6. Launch the dashboard (Layer 5)
```powershell
# Next.js web UI (dev server)
cd frontend && npm install && npm run dev
# → http://localhost:3000
```

---

## Training Results

Trained on 111,499 real rows across 7 datasets (March 2026):

| Metric | Value |
|---|---|
| RandomForest Accuracy | **85.24%** |
| ROC-AUC | **0.9546** |
| Fraud Precision | 0.7709 |
| Fraud Recall | 0.9229 |
| Fraud F1 | **0.8401** |

| Dataset | Rows | Fraud % |
|---|---|---|
| PaySim (stratified) | 50,000 | 16.4% |
| UPI Transactions | 647 | 24.0% |
| Customer_DF + cust_transaction_details | 168 | 36.3% |
| CDR Realtime Fraud | 24,543 | 50.2% |
| Supervised Behavior (API anomaly) | 1,699 | varies |
| Remaining Behavior Extended | 34,423 | varies |
| ToN-IoT network intrusion | 19 | varies |
| **Total** | **111,499** | **42.0% (pre-SMOTE)** |

---

## Project Structure

```
varaksha/
├── frontend/                       ← Next.js 15 web UI (Cloudflare Pages)
│   ├── app/
│   │   ├── page.tsx                # Landing / overview
│   │   ├── flow/page.tsx           # How-it-works interactive flow
│   │   ├── timeline/page.tsx       # Build timeline + future roadmap
│   │   └── live/page.tsx           # Live transaction demo (Module A–E)
│   └── next.config.ts              # output: "export" for Cloudflare Pages
│
├── gateway/                        ← Layer 2: Rust Actix-Web gateway
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # HTTP server, endpoint handlers
│       └── models.rs               # Request/response structs
│
├── risk-cache/                     ← Rust workspace crate: DashMap consortium cache
│   ├── Cargo.toml                  #   dashmap = "5" dependency
│   └── src/
│       ├── lib.rs
│       ├── cache.rs                # RiskCache — DashMap<String, RiskEntry>
│       ├── entry.rs                # RiskEntry struct (score, timestamp)
│       ├── cleaner.rs              # Background TTL expiry task
│       └── metrics.rs              # Cache hit/miss counters
│
├── services/
│   ├── local_engine/
│   │   ├── train_ensemble.py       ← Layer 1: RF-300 + IsolationForest + SMOTE
│   │   └── infer.py                ← ONNX scoring (16 features)
│   ├── graph/
│   │   └── graph_agent.py          ← Layer 3: NetworkX mule-network detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  ← Layer 4: LLM + NMT + pre-gen TTS MP3s
│   └── demo/
│       └── app.py                  ← Layer 5: demo support script
│
├── data/
│   ├── models/                     ← ONNX artefacts (committed)
│   │   ├── varaksha_rf_model.onnx  #   RF-300 (6.2 MB)
│   │   ├── isolation_forest.onnx   #   IsolationForest (1.3 MB)
│   │   ├── scaler.onnx             #   StandardScaler
│   │   └── feature_meta.json       #   Feature schema — 16 features
│   └── datasets/
│       └── README.md               ← Dataset download guide
│
└── requirements.txt
```

---

## Key Design Decisions

**Privacy first** — VPAs are SHA-256 hashed before entering any Rust process. Raw PII never touches the consortium cache. This was non-negotiable from the security side of the team: you cannot build a shared-risk network if participants have to hand over raw account identifiers.

**Latency discipline** — Graph analytics are expensive; keeping them synchronous would add 50–200 ms to every payment. We push all heavy computation (ML inference, graph traversal) to an async webhook path. The Rust DashMap lookup — the only thing in the hot path — completes in under 5 ms at P99.

**Accessible by default** — 37% of India's population does not read English fluently. An alert system that fires an English SMS and calls it done is not a safety net; it's security theatre. All eight pre-generated Neural TTS MP3s (en/hi/ta/te/bn/mr/gu/kn) use Microsoft's edge-tts Neural voices and are served as static assets — zero API key, zero latency, works offline and on every browser.

**SMOTE boundary** — Oversampling is applied to the training split *only*. The held-out test set always reflects the real-world class distribution so reported metrics are honest.

---

## Datasets

See [data/datasets/README.md](data/datasets/README.md) for individual download instructions.
All files go under `data/datasets/`. The trainer auto-discovers and merges everything it finds.

| # | File | Rows | Fraud % | Source |
|---|---|---|---|---|
| 1 | `PS_20174392719_1491204439457_log.csv` | 50,000 *(stratified)* | 16.4 % | [Kaggle — PaySim Online Payments Fraud Detection](https://www.kaggle.com/datasets/rupakroy/online-payments-fraud-detection-dataset) |
| 2 | `Untitled spreadsheet - upi_transactions.csv` | 647 | 24.0 % | Self-generated synthetic UPI transactions (matches problem statement's 660-row dataset spec) |
| 3 | `customer_df.csv` + `cust_transaction_details.csv` | 168 | 36.3 % | Kaggle credit-fraud behaviour datasets |
| 4 | `cdr_realtime_fraud.csv` | 24,543 | 50.2 % | Kaggle telecom CDR realtime fraud dataset |
| 5 | `supervised_dataset.csv` | 1,699 | varies | API behavioural anomaly dataset |
| 6 | `remaining_behavior_ext.csv` | 34,423 | varies | Extended behavioural classification dataset |
| 7 | `ton-iot.csv` | 19 | varies | [ToN-IoT — IoT/IIoT network intrusion](https://research.unsw.edu.au/projects/toniot-datasets) |
| — | *(fallback)* | synthetic | — | NumPy-generated if no CSVs are present — offline / CI mode |
| **Total** | | **111,499** | **42.0 % pre-SMOTE** | |

> **SMOTE note:** Oversampling is applied to the training split *only*. The held-out test set always reflects the real class distribution so reported metrics are honest.

---

## Team

**Varaksha G** — Secure AI Software and Systems Hackathon, BITSGOA

A security engineer and an ML engineer who share the view that robust fraud detection requires both disciplines to operate at the same layer of the stack — not sequentially, but together.

---

## Legal & Regulatory Compliance

Varaksha is built against the full 2026 regulatory stack for UPI fraud detection in India.

### Laws and Frameworks

| Law / Guideline | Scope | Key requirement for Varaksha |
|---|---|---|
| **DPDP Act 2023 §4(1), §6** | Data privacy | Lawful basis required before processing any personal data (VPA, device ID) |
| **DPDP Act 2023 §7(g)** | Data privacy | *Primary* legal basis: "legitimate use" for ensuring safety and security / detecting fraud — no explicit consent required in a banking context |
| **DPDP Rules 2025 Rule 3–4** | Data privacy | Notice in Data Principal's language before first collection; Consent Artefact via AA framework |
| **IT Act 2000 §66C, §66D** | Anti-fraud | Identity theft and impersonation are criminal offences; fraud detection systems prevent them |
| **IT Act 2000 §43A** | Data security | Reasonable security practices for sensitive personal data |
| **RBI Master Directions — Digital Payment Security Controls** | Payment security | PSPs must implement risk-based transaction monitoring |
| **RBI 2026 2FA mandate (effective April 1, 2026)** | Authentication | All UPI transactions must use a dynamic second factor; Varaksha provides the risk-scoring layer that triggers enhanced verification |
| **NPCI OC-215/2025-26** | API rate limits | Maximum 50 balance checks/day per VPA; 3 status checks/transaction; exponential back-off required |

---

### Implementation Status

| Obligation | Reference | Status |
|---|---|---|
| Legitimate Use for Security (primary legal basis) | DPDP §7(g) | ✅ Documented as primary basis in `gateway/src/main.rs` — no consent required for fraud detection in a banking context |
| Consent gate (secondary belt-and-braces) | DPDP §4(1), §6 | ✅ `ConsentManagerClient` (`gateway/src/consent.rs`) calls AA `POST /v2/Consent/fetch` (ReBIT v2.0). HTTP 422 on missing token, 403 on inactive consent. `consent_id` logged against `trace_id` |
| Notice to Data Principal | DPDP §5, Rules 2025 Rule 3 | ⚠️ Footer placeholder on frontend — production needs a dedicated privacy notice page |
| Purpose limitation — fraud scoring only | DPDP §6(3), §7(e) | ✅ No secondary use of any hash or score |
| Data minimisation — no raw PII stored | DPDP §6(3) | ✅ Only `{vpa_hash, risk_score, reason}` persists; raw VPA is hashed at ingress |
| TTL / retention enforcement | DPDP §6(3), §9(6) | ✅ Background eviction in `risk-cache/src/cleaner.rs` (60 s sweep); `get()` validates `expires_at` on every read |
| Data Principal rights (access, erasure, grievance) | DPDP §§12–13 | ⚠️ Grievance contact in footer; no self-service rights portal yet |
| Webhook channel integrity | DPDP / IT Act §43A | ✅ HMAC-SHA256 signature on every graph→gateway webhook |
| Identity theft / SIM-swap / impersonation detection | IT Act §66C, §66D | ✅ ML features `is_new_device` + `previous_failed_attempts` target SIM-swap; graph mule detector catches fan-in (account takeover); L4 alert agent cites §66D |
| Per-VPA daily request cap | NPCI OC-215/2025-26 | ✅ `check_tx` enforces 100 scoring requests per VPA per 24 h via `DashMap` rate limiter — HTTP 429 on breach |
| Risk-based transaction monitoring | RBI Master Directions; RBI 2026 2FA | ✅ Varaksha IS the risk-based monitoring layer — composite ML score (RF 70 % + IsoForest 30 %) + graph mule detection flags high-risk patterns for enhanced verification |
| Significant Data Fiduciary registration | DPDP §10 | N/A — demo scale; register if > 10 M principals |

---

### Personal Data Surface Audit

| Surface | Personal data? | Handling |
|---|---|---|
| `POST /v1/tx` — raw VPA | **Yes** — phone-number VPAs are §2(t) personal data | SHA-256 hashed at ingress; hash only is stored |
| `POST /v1/tx` — `device_id` | **Yes** | Must be pre-hashed by PSP before transmission; raw fingerprint never crosses the wire |
| DashMap cache `{vpa_hash, …}` | No — pseudonymous digest | TTL-evicted, in-memory only |
| Frontend `/live` | No — all logic is client-side JS; nothing leaves the browser | Clean |
| ML training data | No — synthetic / public datasets only | Clean |
| Graph agent output | Pre-hashed `vpa_hash` only | Clean |
| Alert agent input | `vpa_hash` only | Clean |
| Google Fonts CDN | IP address touches Google CDN | Disclose as data processor in production privacy notice |

---

### Production Checklist (before deploying with real transaction data)

1. **Activate consent env vars** — set `CONSENT_MANAGER_BASE_URL`, `CONSENT_MANAGER_API_KEY`, `CONSENT_MANAGER_FI_ID` on the gateway host (see `gateway/src/consent.rs`). Remove `DPDP_CONSENT_DEV_BYPASS`.
2. **Privacy notice page** — add a dedicated `/privacy` route with: processing purpose, legal basis (§7(g)), Data Fiduciary identity, Data Principal rights, 90-day grievance contact.
3. **Data Principal rights portal** — implement `GET /v1/rights/access`, `DELETE /v1/rights/erasure` endpoints (§§12–13).
4. **Self-host Google Fonts** — eliminate the third-party CDN hop or disclose Google as data processor.
5. **Significant Data Fiduciary** — if processing > 10 M principals, register per §10 and appoint a DPO.


