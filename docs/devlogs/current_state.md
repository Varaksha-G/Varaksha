# Varaksha V2 — Current State Snapshot

> **Last updated:** March 12, 2026  
> **Branch:** `test` · **Latest commit:** `cb9ef30`  
> **Live deploy:** `8dfb8b4b.varaksha.pages.dev`  
>
> This document is a point-in-time spec sheet + architecture reference.
> It must be kept in sync with the repo whenever a Phase entry is added to `DEVLOG.md`.
> For the full decision history, see [`DEVLOG.md`](./DEVLOG.md).

---

## Table of Contents

- [Model Metrics](#model-metrics)
- [Architecture Overview](#architecture-overview)
- [Layer-by-Layer Spec](#layer-by-layer-spec)
  - [L1 — ML Scoring Engine](#l1--ml-scoring-engine-serviceslocalengine)
  - [L2 — Rust Privacy Gateway](#l2--rust-privacy-gateway-gateway)
  - [L3 — Graph Mule Detector](#l3--graph-mule-detector-servicesgraph)
  - [L4 — Multilingual Alert Agent](#l4--multilingual-alert-agent-servicesagents)
  - [L5 — Streamlit Demo Dashboard](#l5--streamlit-demo-dashboard-servicesdemo)
- [Frontend](#frontend-frontend)
- [Datasets](#datasets)
- [Model Artefacts](#model-artefacts)
- [Dependencies](#dependencies)
- [Directory Map](#directory-map)
- [Run Commands](#run-commands)

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
│  L5 — Streamlit Demo Dashboard      │  ← analyst / judge demo only
│  Live verdict feed · Plotly graph   │
│  Hindi alert panel · audit log      │
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
| L5 → L1 | Direct Python import | — |
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

### L5 — Streamlit Demo Dashboard (`services/demo/`)

| Item | Detail |
|---|---|
| **File** | `app.py` |
| **Purpose** | Analyst / judge demo — not production |
| **Features** | ALLOW/FLAG/BLOCK live verdict feed · Plotly Scattergl force-directed graph · Hindi alert panel · 50-event audit log |
| **Data** | Synthetic VPAs from seeded RNG — no real PII processed |
| **Run command** | `streamlit run services/demo/app.py` |

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
│       └── app.py            ← L5: Streamlit analyst dashboard
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

# ── Streamlit demo ────────────────────────────────────────────────────────
streamlit run services/demo/app.py
# → http://localhost:8501

# ── Frontend (dev) ────────────────────────────────────────────────────────
cd frontend && npm install && npm run dev
# → http://localhost:3000

# ── Frontend (build + deploy to Cloudflare Pages) ─────────────────────────
cd frontend && npm run build
npx wrangler pages deploy frontend/out --project-name varaksha --branch test --commit-dirty=true
```
