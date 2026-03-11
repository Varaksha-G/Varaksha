# Varaksha V2 — Privacy-Preserving Collaborative UPI Fraud Intelligence Network

> **Hackathon:** Secure AI Software & Systems Hackathon — Blue Team: NPCI UPI Fraud Detection

---

## Architecture Overview

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
                    │  LLM + Mock-Bhashini NMT │
                    │  + edge-tts Hindi MP3    │
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
| Ensemble Methods | RandomForest (300 estimators, RF-only; XGBoost dropped for 512 MB memory budget) |
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

Model trained on 75,358 real rows from 4 datasets (PaySim stratified sample + UPI Transactions + Customer transactions joined + CDR Realtime Fraud):

| Metric | Value |
|---|---|
| RandomForest Accuracy | **94.4%** |
| ROC-AUC | **0.9869** |
| Fraud Precision | 0.8996 |
| Fraud Recall | 0.8983 |
| Fraud F1 | **0.899** |

| Dataset | Rows | Fraud % |
|---|---|---|
| PaySim (stratified) | 50,000 | 16.4% |
| UPI Transactions | 647 | 24.0% |
| Customer_DF + cust_transaction_details | 168 | 36.3% |
| CDR Realtime Fraud | 24,543 | 50.2% |
| **Total** | **75,358** | **27.5%** |

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
- **Accessibility:** `edge-tts` requires no API key — uses the free Microsoft Edge TTS endpoint. The Bhashini NMT stub is clearly marked for replacement with the real API.
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

If no datasets are present, `train_ensemble.py` falls back to numpy synthetic generation (hackathon offline mode).
