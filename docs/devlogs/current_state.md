# Varaksha V2 — Current State Snapshot

> **Last updated:** March 12, 2026  
> **Branch:** `test` · **Latest commit:** `2e806e6`  
> **Live deploy:** `8dfb8b4b.varaksha.pages.dev`  
>
> This document is a point-in-time spec sheet + architecture reference.
> It must be kept in sync with the repo whenever a Phase entry is added to `DEVLOG.md`.
> For the full decision history, see [`DEVLOG.md`](./DEVLOG.md).

---

## Table of Contents

- [Varaksha V2 — Current State Snapshot](#varaksha-v2--current-state-snapshot)
  - [Table of Contents](#table-of-contents)
  - [Model Metrics](#model-metrics)
  - [Architecture Overview](#architecture-overview)
  - [Layer-by-Layer Spec](#layer-by-layer-spec)
    - [L1 — ML Scoring Engine (`services/local_engine/`)](#l1--ml-scoring-engine-serviceslocal_engine)
    - [L2 — Rust Privacy Gateway (`gateway/`)](#l2--rust-privacy-gateway-gateway)
    - [L3 — Graph Mule Detector (`services/graph/`)](#l3--graph-mule-detector-servicesgraph)
    - [L4 — Multilingual Alert Agent (`services/agents/`)](#l4--multilingual-alert-agent-servicesagents)
    - [L5 — Next.js /live Dashboard (`frontend/app/live/`)](#l5--nextjs-live-dashboard-frontendapplive)
  - [Frontend (`frontend/`)](#frontend-frontend)
  - [Datasets](#datasets)
  - [Model Artefacts](#model-artefacts)
  - [Dependencies](#dependencies)
    - [Python runtime (`requirements.txt`)](#python-runtime-requirementstxt)
    - [Python training only (`requirements-train.txt`)](#python-training-only-requirements-traintxt)
    - [Rust (`gateway/Cargo.toml`)](#rust-gatewaycargotoml)
    - [Frontend (`frontend/package.json`)](#frontend-frontendpackagejson)
  - [Directory Map](#directory-map)
  - [Run Commands](#run-commands)
  - [DPDP Act 2023 Compliance](#dpdp-act-2023-compliance)
    - [Personal data surfaces and their status](#personal-data-surfaces-and-their-status)
    - [Key DPDP obligations and implementation status](#key-dpdp-obligations-and-implementation-status)
    - [Production consent flow (required before real-data deployment)](#production-consent-flow-required-before-real-data-deployment)

---

## Model Metrics

Trained March 12, 2026. Source: `services/local_engine/train_ensemble.py`.  
All four target-leakage bugs fixed before this run (see DEVLOG Phase 10).

| Metric             | Value        |
|--------------------|-------------|
| RF Accuracy        | **85.24%**  |
| RF ROC-AUC         | **0.9546**  |
| Fraud Precision    | 0.7709      |
| Fraud Recall       | **0.9229**  |
| Fraud F1           | **0.8401**  |
| Training rows      | 111,499     |
| After SMOTE        | 51,735 / 51,735 (legit / fraud) |
| Features           | 16          |
| Algo               | RandomForest (300 trees) + IsolationForest (composite score) |
| Export format      | ONNX (runtime: `onnxruntime`) |

---

## Architecture Overview

```
UPI Client
    │
    ▼
┌─────────────────────────────────────┐
│  L2 — Rust Privacy Gateway          │  ← sole entry point for raw VPAs
│  Actix-Web 4 · port 8082            │
│  SHA-256 hash at ingress            │
│  DashMap risk cache (in-process)    │
│  score_to_verdict() thresholds:     │
│    < 0.40 → ALLOW                   │
│    0.40–0.74 → FLAG                 │
│    ≥ 0.75 → BLOCK                   │
└───────────┬─────────────────────────┘
            │ cache miss / async update
            ▼
┌─────────────────────────────────────┐
│  L1 — ML Scoring Engine             │  ← background, off payment path
│  Random Forest (ONNX, 300 trees)    │
│  + IsolationForest (ONNX)           │
│  16 features · NumPy only at infer  │
└───────────┬─────────────────────────┘
            │
            ▼
┌─────────────────────────────────────┐
│  L3 — Graph Mule Detector           │  ← async, off payment path
│  NetworkX directed graph            │
│  4 BIS Hertha typologies            │
│  Pushes scores via HMAC-SHA256      │
│  signed webhook to L2 cache        │
└───────────┬─────────────────────────┘
            │ FLAG or BLOCK verdict
            ▼
┌─────────────────────────────────────┐
│  L4 — Multilingual Alert Agent      │
│  edge-tts · 8 Indian languages      │
│  Cites BNS §318(4) + IT Act §66D   │
│  Emits MP3 audio alert              │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  L5 — Next.js /live Dashboard     │
│  Real-time feed · SecurityArena   │
│  CacheVisualizer · LegalReport    │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  Frontend — Next.js 15              │  ← public-facing, static edge deploy
│  Cloudflare Pages (global CDN)      │
│  4 routes: / · /flow · /live · /timeline │
└─────────────────────────────────────┘
```

**Interface contracts between layers:**

| From → To | Protocol | Auth |
|---|---|---|
| UPI Client → L2 | HTTP POST `/v1/tx` | None (internal network) |
| L3 → L2 cache | HTTP POST `/v1/webhook/update_cache` | HMAC-SHA256 signature |
| L2 → L1 | Direct Python import (same process) | — |
| L4 → L5 | Python function call / `AlertResult` dataclass | — |

---

## Layer-by-Layer Spec

### L1 — ML Scoring Engine (`services/local_engine/`)

| Item | Detail |
|---|---|
| **Files** | `train_ensemble.py`, `infer.py` |
| **Train command** | `python services/local_engine/train_ensemble.py` |
| **Algorithm** | RandomForest (300 estimators, `class_weight="balanced"`) + IsolationForest |
| **Features (16)** | `merchant_category`, `transaction_type`, `device_type` *(label-encoded)* · `amount`, `hour_of_day`, `day_of_week`, `transactions_last_1h`, `transactions_last_24h`, `amount_zscore`, `gps_delta_km`, `is_new_device`, `is_new_merchant`, `balance_drain_ratio`, `account_age_days`, `previous_failed_attempts`, `transfer_cashout_flag` |
| **Categorical maps** | `merchant_category`: ECOM=0, FOOD=1, GAMBLING=2, P2P=3, TRAVEL=4, UTILITY=5 · `transaction_type`: CREDIT=0, DEBIT=1 · `device_type`: ANDROID=0, IOS=1, WEB=2 |
| **SMOTE** | Applied to training split only (never test) |
| **Output format** | `data/models/varaksha_rf_model.onnx`, `isolation_forest.onnx`, `scaler.onnx` |
| **Runtime imports** | `onnxruntime`, `numpy` only — no sklearn/pandas at inference |
| **Composite score** | `rf_prob * 0.7 + iso_score_normalised * 0.3` |

**Known clean loaders (post Phase 10 audit):**

| Loader | Source file | Rows | Notes |
|---|---|---|---|
| `_load_paysim` | `PS_20174392719_1491204439457_log.csv` | 50,000 | Stratified sample |
| `_load_upi` | `Untitled spreadsheet - upi_transactions.csv` | 647 | |
| `_load_customer_df` | `customer_df.csv` + `cust_transaction_details.csv` | 168 | |
| `_load_cdr_fraud` | CDR Realtime Fraud dataset | 24,543 | `merchant_category = "UTILITY"` (fixed) |
| `_load_supervised_behavior` | `supervised_dataset.csv` | 1,699 | `is_new_device = 0.0` (fixed) |
| `_load_behavior_extended` | `remaining_behavior_ext.csv` | 34,423 | `is_new_device = 0.0` (fixed) |
| `_load_ton_iot` | `ton-iot.csv` | 19 | `is_new_device = 0.0` (fixed) |

---

### L2 — Rust Privacy Gateway (`gateway/`)

| Item | Detail |
|---|---|
| **Crate** | `varaksha-gateway` v0.2.0 |
| **Framework** | Actix-Web 4 |
| **Port** | 8082 |
| **Key dependencies** | `sha2 0.10`, `hmac 0.12`, `dashmap` (via `risk-cache` local crate), `uuid 1`, `tokio 1` |
| **Endpoints** | `POST /v1/tx` — transaction scoring · `POST /v1/webhook/update_cache` — async graph signals · `GET /health` |
| **PII handling** | Raw VPAs are SHA-256 hashed at `POST /v1/tx` ingress; only the hex digest persists in memory |
| **VPA normalisation** | Phone-number VPAs (`10+ digits`) masked to `XX****XX@bank` before hashing for consortium cache consistency |
| **Verdict thresholds** | ALLOW `< 0.40` · FLAG `0.40–0.74` · BLOCK `≥ 0.75` |
| **Webhook auth** | HMAC-SHA256; secret from env var `VARAKSHA_WEBHOOK_SECRET` (dev default: `dev-secret-change-me`) |
| **Status** | Builds and runs. Hash + verdict logic implemented. DashMap cache operational. |

---

### L3 — Graph Mule Detector (`services/graph/`)

| Item | Detail |
|---|---|
| **File** | `graph_agent.py` |
| **Library** | NetworkX 3.x (directed graph) |
| **Typologies** | Fan-out (1→many), Fan-in (many→1), Cycle (A→B→C→A), Scatter (high out/in ratio) |
| **Taxonomy** | BIS Project Hertha |
| **Score aggregation** | `max()` across all detected pattern scores (prevents FP on high-volume merchants) |
| **Output** | HTTP POST to `http://localhost:8082/v1/webhook/update_cache` with HMAC-SHA256 signature |
| **Execution** | Fully async, off the payment critical path |
| **Run command** | `python services/graph/graph_agent.py` |

---

### L4 — Multilingual Alert Agent (`services/agents/`)

| Item | Detail |
|---|---|
| **File** | `agent03_accessible_alert.py` |
| **TTS** | `edge-tts` (Microsoft Neural TTS, no API key) |
| **Languages** | English, Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati, Kannada (8 of 22 scheduled) |
| **Audio output** | `data/audio_alerts/*.mp3` |
| **Alert content** | Transaction ID, blocked amount, risk score, legal citations |
| **Laws cited** | BNS §318(4) · IT Act 2000 §66D · PMLA §3 |
| **LLM** | Mock (swap `_call_llm()` for GPT-4o-mini / Groq at production time) |
| **NMT** | Template engine (swap `_translate_warning()` for IndicTrans2 / ULCA at production time) |
| **Run command** | `python services/agents/agent03_accessible_alert.py` |

---

### L5 — Next.js /live Dashboard (`frontend/app/live/`)

| Item | Detail |
|---|---|
| **Files** | `page.tsx`, `SecurityArena.tsx`, `CacheVisualizer.tsx`, `LegalReport.tsx` |
| **Purpose** | Production dashboard — real-time transaction feed, threat classification, cache state, legal citations |
| **Features** | Live ALLOW/FLAG/BLOCK feed · SecurityArena threat panel · CacheVisualizer DashMap state · LegalReport per-transaction citations |
| **Deploy** | Cloudflare Pages (global CDN) |

---

## Frontend (`frontend/`)

| Item | Detail |
|---|---|
| **Framework** | Next.js 15.2 · React 19 |
| **Styling** | Tailwind CSS 3.4 · custom tokens: `cream`, `ink`, `saffron`, `allow`, `block`, `flag` |
| **Animation** | framer-motion 12 |
| **Icons** | lucide-react 0.577 |
| **Fonts** | Playfair Display (serif headings) · Barlow (sans body) · Courier Prime (monospace) |
| **Build mode** | Static export (`output: "export"` in `next.config.ts`) |
| **Hosting** | Cloudflare Pages (global edge, zero cold starts) |
| **Deploy command** | `npx wrangler pages deploy frontend/out --project-name varaksha --branch test --commit-dirty=true` |

**Routes:**

| Route | File | Purpose |
|---|---|---|
| `/` | `app/page.tsx` | Landing — live metric cards, mission statement, 5-layer architecture callout |
| `/flow` | `app/flow/page.tsx` | Animated step-by-step transaction walkthrough |
| `/live` | `app/live/page.tsx` | Synthetic real-time transaction feed + Security Arena + Cache Visualizer |
| `/timeline` | `app/timeline/page.tsx` | Build timeline — 12 milestones, storyboard, future scope |

**Key components in `/live`:**

| Component | Function |
|---|---|
| `SecurityArena.tsx` | Real-time threat classification panel |
| `CacheVisualizer.tsx` | DashMap risk cache state visualiser |
| `LegalReport.tsx` | Per-transaction legal citation overlay |

**Colour tokens:**

| Token | Hex | Role |
|---|---|---|
| `cream` | `#F0F4F8` | Page background |
| `ink` | `#0F1E2E` | Primary text / dark surfaces |
| `saffron` | `#2563EB` | UI accent — buttons, kickers |
| `allow` | `#0D7A5F` | ALLOW verdict |
| `block` | `#C0392B` | BLOCK verdict |
| `flag` | `#D97706` | FLAG verdict (amber) |

---

## Datasets

All stored in `data/datasets/`:

| File | Rows used | Source |
|---|---|---|
| `PS_20174392719_1491204439457_log.csv` | 50,000 (stratified) | PaySim synthetic mobile money |
| `Untitled spreadsheet - upi_transactions.csv` | 647 | UPI transaction records |
| `customer_df.csv` + `cust_transaction_details.csv` | 168 | Customer behaviour |
| CDR Realtime Fraud | 24,543 | Telecom CDR fraud dataset |
| `supervised_dataset.csv` | 1,699 | API behaviour anomaly |
| `remaining_behavior_ext.csv` | 34,423 | Bot / attack / outlier behaviour |
| `ton-iot.csv` | 19 | IoT network intrusion (ToN-IoT) |
| **Merged total** | **111,499** | 42.0% fraud pre-SMOTE |

Also includes `prompt_injections.json` and `jailbreakbench-main/` for the prompt guard model.

---

## Model Artefacts

All in `data/models/`:

| File | Purpose | Format |
|---|---|---|
| `varaksha_rf_model.onnx` | Random Forest fraud classifier (300 trees, 16 features) | ONNX |
| `isolation_forest.onnx` | Anomaly / outlier detector | ONNX |
| `scaler.onnx` | StandardScaler for numerical features | ONNX |
| `feature_meta.json` | Feature names + order contract between training and inference | JSON |
| `random_forest.pkl` | RF sklearn artefact (local training reference) | Pickle |
| `isolation_forest.pkl` | IsoForest sklearn artefact | Pickle |
| `scaler.pkl` | Scaler sklearn artefact | Pickle |
| `prompt_guard.pkl` | Prompt injection guard model | Pickle |

Runtime inference uses **only the `.onnx` files** — `.pkl` files are local sidecars.

---

## Dependencies

### Python runtime (`requirements.txt`)

```
onnxruntime>=1.18.0
numpy>=1.26.0
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
networkx>=3.3
requests>=2.32.0
edge-tts>=6.1.10
googletrans==4.0.0rc1
pytest>=8.0.0
```

### Python training only (`requirements-train.txt`)

```
scikit-learn>=1.4.0
imbalanced-learn>=0.12.0
xgboost>=2.0.0 (used for data augmentation experiments, not in serving stack)
lightgbm>=4.3.0
joblib>=1.3.0
pandas>=2.1.0
skl2onnx>=1.16.0
onnxmltools>=1.12.0
onnx>=1.16.0
```

### Rust (`gateway/Cargo.toml`)

```
actix-web = "4"
sha2 = "0.10"
hmac = "0.12"
hex = "0.4"
tokio = "1" (full features)
serde / serde_json = "1"
uuid = "1" (v4)
log = "0.4" + env_logger = "0.11"
risk-cache = { path = "../risk-cache" } (local DashMap wrapper)
```

### Frontend (`frontend/package.json`)

```
next ^15.2.0
react ^19.0.0
react-dom ^19.0.0
framer-motion ^12.0.0
lucide-react ^0.577.0
tailwindcss ^3.4.17
```

---

## Directory Map

```
Varaksha/
├── README.md
├── requirements.txt          ← server runtime deps
├── requirements-train.txt    ← local training deps
│
├── data/
│   ├── datasets/             ← 7 source datasets + jailbreakbench
│   ├── models/               ← ONNX artefacts + feature_meta.json
│   └── audio_alerts/         ← generated MP3 files (agent03 output)
│
├── docs/
│   └── devlogs/
│       ├── DEVLOG.md         ← full decision log (add entry for every major change)
│       └── current_state.md  ← this file (keep in sync with repo)
│
├── gateway/                  ← L2: Rust Actix-Web 4 privacy gateway
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs           ← HTTP handlers, VPA hashing, verdict logic
│       └── models.rs         ← TxRequest / TxResponse / Verdict structs
│
├── services/                 ← Python backend layers
│   ├── local_engine/
│   │   ├── train_ensemble.py ← training pipeline (7 loaders, SMOTE, ONNX export)
│   │   └── infer.py          ← VarakshaScoringEngine — ONNX inference only
│   ├── graph/
│   │   └── graph_agent.py    ← L3: NetworkX graph + BIS typology detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  ← L4: edge-tts multilingual alerts
│   └── demo/
│       └── app.py            ← deprecated local demo (superseded by Next.js /live)
│
└── frontend/                 ← Next.js 15 static web UI
    ├── app/
    │   ├── layout.tsx        ← root layout, nav, fonts
    │   ├── globals.css       ← dot-grid texture, surface-card utility
    │   ├── page.tsx          ← / landing page
    │   ├── flow/page.tsx     ← /flow animated walkthrough
    │   ├── live/             ← /live real-time feed
    │   │   ├── page.tsx
    │   │   ├── SecurityArena.tsx
    │   │   ├── CacheVisualizer.tsx
    │   │   └── LegalReport.tsx
    │   └── timeline/
    │       └── page.tsx      ← /timeline build history
    ├── tailwind.config.ts    ← colour + font tokens
    └── package.json
```

---

## Run Commands

```bash
# ── Training (local only) ──────────────────────────────────────────────────
pip install -r requirements-train.txt
python services/local_engine/train_ensemble.py
# → writes data/models/*.onnx + data/models/*.pkl

# ── Python runtime install ─────────────────────────────────────────────────
pip install -r requirements.txt

# ── Rust gateway ──────────────────────────────────────────────────────────
cd gateway && cargo run
# → listens on http://localhost:8082

# ── Graph agent ───────────────────────────────────────────────────────────
python services/graph/graph_agent.py

# ── Alert agent (smoke test) ──────────────────────────────────────────────
python services/agents/agent03_accessible_alert.py

# ── Frontend (dev) ────────────────────────────────────────────────────────
cd frontend && npm install && npm run dev
# → http://localhost:3000

# ── Frontend (build + deploy to Cloudflare Pages) ─────────────────────────
cd frontend && npm run build
npx wrangler pages deploy frontend/out --project-name varaksha --branch test --commit-dirty=true
```

---

## DPDP Act 2023 Compliance

Relevant law: **Digital Personal Data Protection Act, 2023** + **DPDP Rules, 2025**.

### Personal data surfaces and their status

| Surface | Personal data? | Current handling | Gap / Action |
|---|---|---|---|
| `POST /v1/tx` — `vpa` field | **YES** — phone-number VPAs are §2(t) personal data | SHA-256 hashed at ingress before any storage | Consent gate **LIVE**: `ConsentManagerClient` calls AA `POST /v2/Consent/fetch` (ReBIT AA v2.0). Set `CONSENT_MANAGER_BASE_URL`, `CONSENT_MANAGER_API_KEY`, `CONSENT_MANAGER_FI_ID`. Use `DPDP_CONSENT_DEV_BYPASS=true` locally. |
| `POST /v1/tx` — `device_id` | **YES** — device fingerprint is personal data | Documented as "must be pre-hashed client-side" | Enforcement is contractual (PSP obligation); add validation in production |
| DashMap cache `{vpa_hash, …}` | No — SHA-256 digest is pseudonymous | TTL-evicted in-memory only | Clean |
| Frontend sandbox (`/live`) | No — `deriveSandboxResult()` is pure browser-side JS | No network call made; nothing leaves the browser | Clean |
| Google Fonts CDN | IP address hits Google CDN on page load | Third-party processor | Disclose in privacy notice for production deployments |
| ML training data | No — synthetic / public datasets only | N/A | Clean |
| Graph agent | Pushes only pre-hashed `vpa_hash` | N/A | Clean |
| Alert agent | Receives only `vpa_hash` | N/A | Clean |

### Key DPDP obligations and implementation status

| Obligation | Act reference | Status |
|---|---|---|
| Lawful purpose + consent before processing VPA | §4(1), §6 | ✅ `ConsentManagerClient` (`gateway/src/consent.rs`) calls AA `POST /v2/Consent/fetch`; 422 on missing token, 403 on inactive consent, 503 on transport error. `consent_id` logged against `trace_id` for §12(a) audit trail. |
| **Legitimate Use for Security** (primary lawful basis, no consent required) | §7(g) | ✅ Processing is for detecting and preventing unlawful activity (fraud). Documented as dual legal basis alongside §4(1) in `gateway/src/main.rs`. |
| Notice to Data Principal (language, purpose, rights) | §5, Rules 2025 Rule 3 | ⚠️ Footer notice on frontend; production must add dedicated privacy notice page |
| Purpose limitation — fraud-risk scoring only | §6(3), §7(e) | ✅ No secondary use of hash or score |
| Data minimisation — no raw PII in cache | §6(3) | ✅ Only `{vpa_hash, risk_score, reason}` stored |
| TTL / retention policy | §6(3), §9(6) | ✅ Background eviction implemented in `risk-cache/src/cleaner.rs` (tokio task, 60 s sweep). `cache.rs::get()` also validates `expires_at` on every read. |
| Data Principal rights (access, correction, erasure, nomination, grievance) | §§12–13 | ⚠️ Grievance contact placeholder added to frontend footer; no rights portal yet |
| Significant Data Fiduciary registration (>10 M principals, or govt notification) | §10 | N/A for current demo scale |
| Webhook HMAC-SHA256 signature on graph→gateway | DPDP security obligations, also IT Act §43A | ✅ Implemented |
| Identity theft / impersonation / SIM-swap detection | IT Act 2000 §66C, §66D | ✅ L4 alert agent cites §66D; ML features `is_new_device`, `previous_failed_attempts` target SIM-swap patterns; graph agent detects fan-in (account takeover) typology |
| Per-VPA daily request cap (UPI rail protection) | NPCI OC-215/2025-26 | ✅ `check_tx` enforces 100 scoring requests per VPA per 24 h window via `DashMap` rate limiter; HTTP 429 on breach. Architecture is physically incapable of VPA flooding. |
| Risk-based transaction monitoring | RBI Master Directions on Digital Payment Security Controls; RBI 2026 2FA draft | ✅ Varaksha IS the risk-based monitoring layer mandated for PSPs. Composite ML score (RF 70% + IsoForest 30%) + graph mule detection fulfils "unusual/high-risk pattern" identification. |

### Production consent flow (required before real-data deployment)

```
User (Data Principal)
  │
  ├─ 1. PSP shows DPDP Notice (§5 / Rules 2025 Rule 3)
  │      Language = user's chosen language or English
  │      Purpose  = "Detecting and preventing UPI payment fraud"
  │      Fiduciary = [Bank / PSP name]
  │
  ├─ 2. User grants consent (free, specific, informed, unconditional, unambiguous)
  │      Consent Manager issues Consent Artefact ID  →  token = "ca_xxxx"
  │
  └─ 3. PSP calls  POST /v1/tx  with body:
             { "vpa": "...", "device_id": "<pre-hashed>",
               "consent_token": "ca_xxxx", ... }

Gateway (Data Fiduciary processor)
  ├─ Validates consent_token via Consent Manager SDK
  ├─ Hashes VPA (personal data never stored beyond this point)
  └─ Returns { vpa_hash, verdict, risk_score, trace_id }
         with consent artefact ID logged against trace_id for §12(a) access rights
```
