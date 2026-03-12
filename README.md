# Varaksha — Privacy-Preserving Collaborative UPI Fraud Intelligence Network

> **Hackathon:** BITSGOA Secure AI Software and Systems Hackathon
> **Team:** Varaksha G — *Security Engineer × ML Engineer*

---

## What We Built & Why

UPI processes over **14 billion transactions a month**. A fraudulent ₹99,999 transfer can drain a victim's account in under 3 seconds — well before any human intervention is possible.

We're two people: one with a background in systems security and one in machine learning. We kept disagreeing on where the real problem was — until we realised we were both right. The fraud pipeline breaks at *two* different points:

1. **The ML side** — models trained in isolation, on unbalanced synthetic data, with no memory of what the consortium has already flagged.
2. **The security side** — latency-critical payment paths that can't afford a Python process in the hot loop, and alert systems that silently fail non-English speakers.

Varaksha is our answer to both: a privacy-preserving, multilingual fraud intelligence network where a **Rust gateway** handles the sub-10 ms verdict path, a **machine-learning ensemble** provides the actual risk signal, and a **graph + alert layer** closes the loop with human-readable evidence — in 8 Indian languages.

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
                    │  Streamlit (local demo)  │
                    │  Next.js 15 (web UI)     │
                    └──────────────────────────┘
```

### Why Rust for the gateway?

The security engineer's insistence. Python is fine for training, inference, and graph analytics — but placing a GIL-bound process inside a payment's synchronous path is asking for tail-latency disasters under burst load. Rust's `actix-web` + `DashMap` gives us lock-free concurrent reads, compile-time memory safety, and P99 < 5 ms with no warm-up.

### Why a consortium cache?

A single bank sees a vanishingly small slice of a mule's activity. The `DashMap` risk cache acts as a shared memory across institutions — a VPA flagged by Bank A is immediately visible to Banks B and C on the next transaction, without either side ever exchanging raw account data (SHA-256 hashing ensures no PII crosses the network boundary).

---

## Hackathon Track Compliance

| Requirement | Implementation |
|---|---|
| Anomaly Detection | IsolationForest (`services/local_engine/train_ensemble.py`) |
| Ensemble Methods | RandomForest (300 estimators) fused with IsolationForest scores |
| SMOTE for imbalanced data | `imblearn.over_sampling.SMOTE` on training split only — test set always reflects real distribution |
| User-friendly Dashboard | Streamlit (`services/demo/app.py`) + full interactive Next.js web UI |
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
# Streamlit (local introspection)
streamlit run services/demo/app.py

# Next.js web UI (dev server)
cd frontend && npm install && npm run dev
# → http://localhost:3000
```

---

## Training Results

Trained on 111,499 real rows across 7 datasets (March 2026):

| Metric | Value |
|---|---|
| RandomForest Accuracy | **96.52%** |
| ROC-AUC | **0.9952** |
| Fraud Precision | 0.9745 |
| Fraud Recall | 0.9419 |
| Fraud F1 | **0.9579** |

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
│       ├── cache.rs                # DashMap risk cache
│       └── models.rs               # Request/response structs
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
│       └── app.py                  ← Layer 5: Streamlit dashboard
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

See [data/datasets/README.md](data/datasets/README.md) for download instructions.

| Dataset | Source |
|---|---|
| PaySim (`PS_20174392719_*.csv`) | [Kaggle — López-Rojas 2016](https://www.kaggle.com/datasets/rupakroy/online-payments-fraud-detection-dataset) |
| UPI Transactions | Self-generated synthetic |
| Customer_DF + cust_transaction_details | Kaggle credit-fraud datasets |
| CDR Realtime Fraud | Kaggle telecom fraud dataset |
| Supervised Behavior | API behavior anomaly dataset |
| Remaining Behavior Extended | Extended behavior classification dataset |
| ToN-IoT | IoT network intrusion dataset |

If no datasets are present, `train_ensemble.py` falls back to NumPy synthetic generation (hackathon offline mode).

---

## Team

**Varaksha G** — BITSGOA Secure AI Software and Systems Hackathon

> *"We spent the first day arguing about whether the threat model was a data science problem or a systems security problem. Turns out it was both."*


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
                    │ async webhook
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
                    │  Streamlit (local demo)  │
                    │  Next.js 15 (web UI)     │
                    └──────────────────────────┘
```

---

## Hackathon "Bible" Compliance

| Requirement | Implementation |
|---|---|
| Anomaly Detection | IsolationForest (`services/local_engine/train_ensemble.py`) |
| Ensemble Methods | RandomForest (300 estimators, RF-only; XGBoost/LightGBM dropped for 512 MB memory budget) |
| SMOTE for imbalanced data | `imblearn.over_sampling.SMOTE` applied to training split only |
| User-friendly Dashboard | Streamlit (`services/demo/app.py`) with Plotly graph |
| Real-Time Monitoring | Rust DashMap cache (`gateway/`) — sub-5 ms lookups |

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
The script auto-discovers all datasets under `data/datasets/` and merges them.
Pre-trained ONNX models (`varaksha_rf_model.onnx`, `isolation_forest.onnx`, `scaler.onnx`) are checked in and ready to use without retraining.

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

### 5. Test the accessible alert (Layer 4)
```powershell
python services/agents/agent03_accessible_alert.py
```

### 6. Launch the dashboard (Layer 5)
```powershell
# Streamlit (local introspection)
streamlit run services/demo/app.py

# Next.js web UI (dev server)
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

---

## Training Results

Model trained on 111,499 real rows from 7 datasets (March 2026 retrain):

| Metric | Value |
|---|---|
| RandomForest Accuracy | **96.52%** |
| ROC-AUC | **0.9952** |
| Fraud Precision | 0.9745 |
| Fraud Recall | 0.9419 |
| Fraud F1 | **0.9579** |

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
│   │   ├── page.tsx                # Landing page
│   │   ├── flow/page.tsx           # How-it-works flow
│   │   └── live/page.tsx           # Live transaction demo
│   └── next.config.ts              # output: "export" for Cloudflare Pages
│
├── gateway/                        ← Layer 2: Rust Actix-Web gateway
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # HTTP server, endpoint handlers
│       ├── cache.rs                # DashMap risk cache
│       └── models.rs               # Request/response structs
│
├── services/
│   ├── local_engine/
│   │   ├── train_ensemble.py       ← Layer 1: RF-only (300 trees) + IF + SMOTE
│   │   └── infer.py                ← ONNX scoring engine (16 features)
│   ├── graph/
│   │   └── graph_agent.py          ← Layer 3: NetworkX mule detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  ← Layer 4: LLM + NMT + TTS
│   └── demo/
│       └── app.py                  ← Layer 5: Streamlit dashboard
│
├── data/
│   ├── models/                     ← ONNX model artefacts (committed)
│   │   ├── varaksha_rf_model.onnx  #   RF-300 (6.2 MB)
│   │   ├── isolation_forest.onnx   #   IsolationForest (1.3 MB)
│   │   ├── scaler.onnx             #   StandardScaler
│   │   └── feature_meta.json       #   Feature schema (16 features)
│   └── datasets/
│       └── README.md               ← dataset download instructions
│
├── Cargo.toml                      ← root Rust workspace (gateway + risk-cache)
└── requirements.txt
```

---

## Key Design Decisions

- **Privacy:** VPAs are SHA-256 hashed before entering the Rust process. Raw PII never touches the cache.
- **Latency:** Graph analytics (heavy) run async, completely outside the payment path. The Rust DashMap lookup is the only thing in the hot path.
- **Accessibility:** `edge-tts` requires no API key — uses the free Microsoft Edge TTS endpoint. Multilingual NMT templates cover 8 Indian languages (EN, HI, TA, TE, BN, MR, GU, KN); swap `_translate_warning()` in `agent03_accessible_alert.py` for a real NMT API (e.g. IndicTrans2 or any ULCA-compliant service) in production.
- **SMOTE boundary:** Applied to the training split *only* — the test set always reflects the real class distribution.

---

## Datasets

See [data/datasets/README.md](data/datasets/README.md) for download instructions.

Datasets used for training (place under `data/datasets/`):

| Dataset | Source |
|---|---|
| PaySim (`PS_20174392719_*.csv`) | [Kaggle — López-Rojas 2016](https://www.kaggle.com/datasets/rupakroy/online-payments-fraud-detection-dataset) |
| UPI Transactions (`Untitled spreadsheet - upi_transactions.csv`) | Self-generated synthetic |
| Customer_DF + cust_transaction_details | Kaggle credit-fraud datasets |
| CDR Realtime Fraud | Kaggle telecom fraud dataset |
| Supervised Behavior (`supervised_dataset.csv`) | API behavior anomaly dataset |
| Remaining Behavior Extended (`remaining_behavior_ext.csv`) | Extended behavior classification dataset |
| ToN-IoT (`ton-iot.csv`) | IoT network intrusion dataset |

If no datasets are present, `train_ensemble.py` falls back to numpy synthetic generation (hackathon offline mode).
