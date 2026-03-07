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
│  RF + XGB    │      │  Fan-out / Fan-in / Cycle│
│  + SMOTE     │      │  → pushes risk to cache  │
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
                    │  Streamlit               │
                    └──────────────────────────┘
```

---

## Hackathon "Bible" Compliance

| Requirement | Implementation |
|---|---|
| Anomaly Detection | IsolationForest (`services/local_engine/train_ensemble.py`) |
| Ensemble Methods (RF + XGB) | RandomForest + XGBoost + soft-voting ensemble |
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
# Optional with real CSV:
python services/local_engine/train_ensemble.py --data path/to/upi.csv
```

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
streamlit run services/demo/app.py
```

---

## Project Structure

```
varaksha/
├── gateway/                        ← Layer 2: Rust Actix-Web gateway
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # HTTP server, route handlers
│       ├── cache.rs                # DashMap risk cache (TODO: teammate)
│       └── models.rs               # Request/response structs
│
├── services/
│   ├── local_engine/
│   │   └── train_ensemble.py       ← Layer 1: SMOTE + RF + XGB training
│   ├── graph/
│   │   └── graph_agent.py          ← Layer 3: NetworkX mule detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  ← Layer 4: LLM + NMT + TTS
│   └── demo/
│       └── app.py                  ← Layer 5: Streamlit dashboard
│
├── data/
│   ├── models/                     ← saved .pkl model files (gitignored)
│   ├── audio_alerts/               ← generated .mp3 files (gitignored)
│   └── datasets/
│       └── README.md               ← dataset download instructions
│
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

Recommended:
- [Kaggle Online Payments Fraud Detection](https://www.kaggle.com/datasets/rupakroy/online-payments-fraud-detection-dataset)
- Synthetic UPI dataset generated automatically by `train_ensemble.py` if no CSV is provided
