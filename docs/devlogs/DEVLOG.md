# Varaksha V2 — Development Log

> Written March 10, 2026. Records every architectural decision, rebuild rationale,
> layer-by-layer implementation note, and current open items for the V2 test branch.

---

## Table of Contents

- [Why V2 Exists](#why-v2-exists)
- [Timeline](#timeline)
  - [Phase 0 — V1 Audit & Decision to Rebuild](#phase-0--v1-audit--decision-to-rebuild)
  - [Phase 1 — Layer 1: Local Fraud Engine](#phase-1--layer-1-local-fraud-engine)
  - [Phase 2 — Layer 2: Rust Gateway Stub](#phase-2--layer-2-rust-gateway-stub)
  - [Phase 3 — Layer 3: Graph Agent](#phase-3--layer-3-graph-agent)
  - [Phase 4 — Layer 4: Accessible Alert Agent](#phase-4--layer-4-accessible-alert-agent)
  - [Phase 5 — Layer 5: Streamlit Demo Dashboard](#phase-5--layer-5-streamlit-demo-dashboard)
- [Directory Map](#directory-map)
- [Architecture Deep-Dive](#architecture-deep-dive)
  - [Why Five Separate Layers?](#why-five-separate-layers)
  - [Why Rust for the Gateway?](#why-rust-for-the-gateway)
  - [Risk Cache Design](#risk-cache-design)
  - [Graph Typologies](#graph-typologies)
  - [Accessible Alert Design](#accessible-alert-design)
  - [ML Stack Rationale](#ml-stack-rationale)
- [Open Items — Rust Teammate Checklist](#open-items--rust-teammate-checklist)
- [Datasets Used](#datasets-used)
- [Honest Caveats](#honest-caveats)

---

## Why V2 Exists

V1 (committed on `main`) was a full working system: PyO3 Rust-Python bridge,
GATE-M OS-level security monitor, SLSA supply-chain verification, Ed25519 message
signing between agents. It compiled and passed tests.

The problem: **V1 was too deep into security research and too far from a legible
demo**. A judge running `demo.py` for the first time would hit PyO3 build
dependencies, a GATE-M kernel module, and a six-agent LangGraph pipeline before
seeing a single scored transaction. The barrier was too high.

V2 takes the opposite stance:

- **Three Python scripts runnable with `pip install -r requirements.txt`** — no
  native build, no kernel module, no API keys.
- **Rust gateway kept as a clearly-labelled stub** with a teammate implementation
  checklist, so the Rust layer can be filled in independently without blocking
  the Python demo.
- **One `streamlit run` command shows a live risk feed** with coloured verdict
  badges, a Plotly network graph, and a text narration.

The V1 codebase is preserved on `main` and documented in its own devlog
(`docs/devlogs/DEVLOG.md` on `main`).

---

## Timeline

### Phase 0 — V1 Audit & Decision to Rebuild

Reviewed V1 test results:

- Rust gateway: 3/3 arena tests PASS (rate-limit, ML evasion, graph ring)
- Python pipeline: full end-to-end scoring functional
- Demo friction: 12-step setup, PyO3 compilation required, GATE-M Linux-only

Decision: branch `test`, clean slate, five focused layers with clear interfaces
between them. V1 artefacts removed from `test` branch to avoid confusion.

Removed from `test`:
- `gateway/rust-core/` (full PyO3 gateway)
- `security/gate-m/` (kernel monitor)
- `scripts/` (adversarial scan, legal report)
- All V1 HTML pitch/flow files from `docs/`

---

### Phase 1 — Layer 1: Local Fraud Engine

**File:** `services/local_engine/train_ensemble.py`

The ML training script satisfies every hackathon evaluation criterion:

| Criterion | Implementation |
|-----------|---------------|
| Anomaly detection | `IsolationForest` (contamination=0.02) |
| Ensemble methods | `VotingClassifier` wrapping RF + XGBoost (soft vote) |
| Imbalanced dataset | `SMOTE` (imblearn) before train split |
| Feature engineering | 8 derived features: velocity, round-amount flag, out-degree, hour-of-day |
| Model persistence | `joblib.dump` → `data/models/` |

**Training path resolution:** The script auto-detects which dataset is available
and falls back through three sources in order:
1. `data/datasets/Untitled spreadsheet - upi_transactions.csv` (local synthetic)
2. `data/datasets/PS_20174392719_1491204439457_log.csv` (PaySim 6.36 M rows)
3. Synthetic generation via `numpy` if neither is present (hackathon offline mode)

**Why VotingClassifier instead of stacking?** Stacking requires a meta-learner
trained on out-of-fold predictions — that's an extra training pass and doubles
memory pressure on a free-tier machine. Soft voting with equal weights is
simpler, interpretable, and generalises comparably on tabular fraud data per the
PaySim benchmark paper (López-Rojas et al., 2016).

---

### Phase 2 — Layer 2: Rust Gateway Stub

**Files:** `gateway/src/main.rs`, `gateway/src/cache.rs`, `gateway/src/models.rs`

The gateway is an **Actix-Web 4** server on port `8082`. The structure is fully
scaffolded:

- All types defined in `models.rs` (`TxRequest`, `TxResponse`, `CacheUpdateRequest`, `Verdict`)
- `RiskCache` struct skeleton in `cache.rs` with `DashMap` field declared
- Three endpoints wired in `main.rs`: `GET /health`, `POST /v1/tx`, `POST /v1/webhook/update_cache`
- `hash_vpa()` helper (SHA-256 of raw VPA) implemented and used in the handler
- `score_to_verdict()` threshold logic implemented

**What is stubbed (TODO for Rust teammate):**
- `RiskCache::get()` — always returns `(0.0, "no cache entry")`
- `RiskCache::upsert()` — no-op
- HMAC-SHA256 verification on `update_cache` — skipped, always 200

All TODO items are inline-commented in the source with exact steps. The server
compiles and responds to all three endpoints — the stub behaviour is safe for
demo use (all transactions return `ALLOW` until the cache is populated).

**Why DashMap?** Lock-free concurrent hashmap with `Arc<DashMap>` shared across
Actix worker threads. At the expected demo load (< 100 RPS) a `Mutex<HashMap>`
would be fine, but DashMap is the idiomatic choice for a production gateway and
signals intent to reviewers.

---

### Phase 3 — Layer 3: Graph Agent

**File:** `services/graph/graph_agent.py`

Runs **out of the payment hot path** — it builds a transaction graph in memory
and pushes risk scores to the Rust cache via the webhook. This means a
slow graph computation never blocks a `/v1/tx` response.

**Typologies detected** (following BIS Project Hertha taxonomy):

| Typology | Detection method | Risk delta |
|----------|-----------------|------------|
| Fan-out | out-degree > threshold from single source | +0.35 |
| Fan-in | in-degree > threshold on single destination | +0.30 |
| Cycle | `nx.simple_cycles` on directed subgraph | +0.50 |
| Scatter | out-degree > 2× in-degree, high total degree | +0.20 |

Scores are clipped to `[0.0, 1.0]` after accumulation. The score pushed to
the Rust cache is the **max** across all detected typologies for a given VPA
hash, not a sum — summing caused false-flagging on high-volume but legitimate
merchants in testing.

**Webhook auth:** The graph agent signs each update with HMAC-SHA256 using
`WEBHOOK_SECRET`. The Rust gateway stub currently skips verification (TODO), but
the Python side always sends a valid signature so integration is drop-in once
the Rust side implements `verify_slice`.

---

### Phase 4 — Layer 4: Accessible Alert Agent

**File:** `services/agents/agent03_accessible_alert.py`

Handles the **last-mile communication** requirement: a flagged transaction
should reach the account holder in their language, not just log a JSON verdict.

**What it does:**

1. Takes a `TxResponse` JSON from the gateway
2. Generates a Hindi narration template via string interpolation (no LLM
   dependency — narration quality is deterministic and auditable)
3. Optionally translates to the user's preferred language via `googletrans` if
   available
4. Optionally synthesises speech via `edge-tts` (Microsoft TTS, free tier) if
   available
5. Cites the relevant Indian legal statute (IT Act 2000 §66C for identity fraud,
   BNSS §318 for cheating by personation)

**Graceful degradation:** Every optional dependency (`googletrans`, `edge-tts`,
`lime`) is wrapped in a try/except import. The agent works on base Python +
`requests` alone — it falls back to a printed narration string.

**Why not a real NMT model?** A full Bhashini API integration requires a
government API key and 200–500 ms per translation call. The hackathon judges
need a working demo in < 30 s. googletrans covers the same 22 Indian scheduled
languages synchronously with zero credentials.

---

### Phase 5 — Layer 5: Streamlit Demo Dashboard

**File:** `services/demo/app.py`

Single-file Streamlit dashboard. Run with:

```bash
streamlit run services/demo/app.py
```

**Panels:**

| Panel | Contents |
|-------|----------|
| Risk Feed | Live auto-refreshing table of synthetic transactions with verdict badges (ALLOW / FLAG / BLOCK) |
| Transaction Network | Plotly Scattergl force-directed graph, edges coloured by risk tier |
| Accessible Alert | Hindi narration + English translation for the most recent flagged transaction |
| Audit Log | Expandable JSON of last 50 scored transactions |

**No real PII is used.** All transactions are generated from a seeded RNG.
VPA strings are synthetic (`user_XXXX@okicici`, `merchant_XXXX@paytm`).

---

## Directory Map

```
varaksha/
├── gateway/
│   ├── Cargo.toml                     Actix-Web 4 + DashMap + sha2 + uuid
│   └── src/
│       ├── main.rs                    HTTP server, endpoint handlers (stubs marked)
│       ├── cache.rs                   RiskCache (DashMap wrapper — stubs marked)
│       └── models.rs                  Serde types: TxRequest, TxResponse, Verdict
│
├── services/
│   ├── local_engine/
│   │   └── train_ensemble.py          Layer 1 — ML training (RF + XGB + IF + SMOTE)
│   ├── graph/
│   │   └── graph_agent.py             Layer 3 — NetworkX mule-ring detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  Layer 4 — multilingual alert + law cite
│   └── demo/
│       └── app.py                     Layer 5 — Streamlit dashboard
│
├── data/
│   ├── datasets/                      Training data (CSV, Parquet, JSON)
│   └── models/                        Trained model artefacts (.pkl) — gitignored
│
├── docs/
│   └── devlogs/
│       └── DEVLOG.md                  ← this file
│
├── requirements.txt                   All Python dependencies
└── README.md                          Setup & run instructions
```

---

## Architecture Deep-Dive

### Why Five Separate Layers?

Each layer can be developed, tested, and replaced independently:

- Layer 1 (ML) can be retrained on new data without touching the gateway
- Layer 2 (Rust) can be filled in by a Rust developer without any Python knowledge
- Layer 3 (Graph) can upgrade typology logic without changing the webhook interface
- Layer 4 (Alert) can swap translation backends without touching the score pipeline
- Layer 5 (Demo) is purely a view layer — it reads output, never writes

The interfaces between layers are **plain JSON over HTTP**. No shared memory,
no message brokers, no compiled protocol buffers. This keeps the demo runnable
on a single laptop with no infrastructure.

---

### Why Rust for the Gateway?

The gateway is the single process that sees raw VPA strings (UPI IDs). It hashes
them immediately and nothing downstream ever sees the original. This is a
**privacy chokepoint** — it must:

1. Be fast enough to not add latency to the payment path (< 5 ms P99)
2. Be memory-safe to rule out buffer-overflow attacks on VPA inputs
3. Be the single source of truth for the risk cache (thread-safe concurrent reads)

Rust satisfies all three. A Python process behind `asyncio` could achieve the
latency target at demo load, but would require `multiprocessing.Manager` for
the shared cache and is harder to argue for in a security review.

The gateway stub compiles and runs today. A Rust developer can implement the two
TODO cache methods without touching any Python code.

---

### Risk Cache Design

```
VPA Hash (SHA-256 hex)  →  (risk_score: f32,  reason: String,  updated_at: u64)
```

- Written by: graph agent (via `POST /v1/webhook/update_cache`)
- Read by: `check_tx` handler (in-memory, no disk I/O on the hot path)
- TTL: entries older than 300 s should be treated as score 0.0 (not yet
  implemented in the stub — marked as TODO)
- Concurrency: `DashMap` provides per-shard locks, so concurrent reads from
  multiple Actix worker threads are lock-free

---

### Graph Typologies

All typologies are detected on a **sliding window** of the last N transactions
(configurable, default 500). The graph is rebuilt from scratch each iteration
rather than maintained incrementally — simpler to test, sufficient for demo load.

```
Fan-out:   sender_hash ──→ receiver_1
                        ──→ receiver_2   (out-degree > 5 in last 60 s)
                        ──→ receiver_N

Fan-in:    sender_1 ──→
           sender_2 ──→  receiver_hash  (in-degree > 8 in last 60 s)
           sender_N ──→

Cycle:     A ──→ B ──→ C ──→ A          (exact directed cycle, any length ≤ 10)
```

---

### Accessible Alert Design

The narration template for a BLOCK verdict:

```
⚠ Varaksha Alert: Transaction of ₹{amount} to {merchant} has been BLOCKED.
Reason: {reason}.
This may constitute an offence under IT Act 2000 §66C / BNSS §318.
Contact your bank's fraud desk immediately.
```

For FLAG verdicts, the message is advisory rather than prescriptive, and does
not cite criminal statutes (incorrect legal framing for a mere suspicion).

---

### ML Stack Rationale

| Choice | Rationale |
|--------|-----------|
| `IsolationForest` contamination=0.02 | PaySim fraud rate is ~1.3%; 2% gives a small margin without flooding FLAG verdicts |
| SMOTE before split | Resampling after split leaks synthetic samples into validation — SMOTE must precede `train_test_split` |
| Soft voting (RF + XGB) | Probability averaging smooths overconfident trees; hard voting loses calibration information |
| `LabelEncoder` per column | Frequency encoding would leak test-set frequencies during training; LE is count-free |
| `StandardScaler` | Tree ensembles are scale-invariant but IF benefits from normalised feature ranges |

---

## Open Items — Rust Teammate Checklist

These are the only items needed to make the gateway fully functional:

```
[ ] cache.rs  — RiskCache::get()
               Currently returns (0.0, "no cache entry") for all keys.
               Implement: return entry from inner DashMap, or (0.0, "cold") if absent.

[ ] cache.rs  — RiskCache::upsert()
               Currently a no-op.
               Implement: insert/update the DashMap entry with the provided score + reason.

[ ] main.rs   — HMAC verification in update_cache handler
               Currently skipped (any caller can update the cache).
               Implement: read x-varaksha-sig header, recompute HMAC-SHA256 over body
               using $VARAKSHA_WEBHOOK_SECRET env var, call Mac::verify_slice in constant time.

[ ] cache.rs  — TTL eviction
               Optional but recommended: entries older than 300 s should return score 0.0.
               Implement: store updated_at: u64 (Unix timestamp) and check on read.
```

Test command once implemented:

```bash
cargo run --manifest-path gateway/Cargo.toml
# In another terminal:
curl -s -X POST http://localhost:8082/v1/tx \
  -H "Content-Type: application/json" \
  -d '{"vpa":"test@okicici","amount":9999.0,"merchant":"test_merchant","timestamp":1234567890}'
```

Expected: `{"verdict":"Allow","risk_score":0.0,...}` before cache is populated,
then a real score after the graph agent pushes a webhook update.

---

## Datasets Used

| Dataset | File | Source | Used for |
|---------|------|--------|----------|
| PaySim | `PS_20174392719_1491204439457_log.csv` | Kaggle (López-Rojas 2016) | Primary ML training |
| UPI synthetic | `Untitled spreadsheet - upi_transactions.csv` | Self-generated | Local smoke-test training |
| JailbreakBench | `train-*.parquet`, `test-*.parquet` | HuggingFace | Prompt injection guard training |
| Sadaf & Manivannan UPI paper | `paper_extracted.txt` | Research paper extraction | Supplementary feature validation |
| Prompt injections | `prompt_injections.json` | Custom curated | PromptGuard fine-tune |

---

## Honest Caveats

**The Rust cache is a stub.** Until the teammate fills in `RiskCache::get()` and
`upsert()`, every transaction scores 0.0 and returns `ALLOW`. The demo Streamlit
dashboard bypasses the gateway and generates scores directly in Python — it
does not depend on the Rust server being fully implemented.

**googletrans is unofficial.** The Google Translate Python wrapper reverse-engineers
the public translation endpoint. It has no SLA and can break on API changes.
For production: use Bhashini (https://bhashini.gov.in/api) or DeepL.

**SMOTE is not a substitute for real data.** The synthetic oversampling improves
classifier recall on the minority class during training. It does not make the
model more accurate on real-world UPI fraud patterns, which differ from PaySim's
stylised simulation in timing, merchant category, and network topology.

**VPA hashing is SHA-256, not HMAC.** SHA-256 of a short predictable string (UPI
IDs follow `username@bank` format) is reversible via rainbow table. In production
the gateway should use HMAC-SHA256 with a per-deployment secret key so the hash
cannot be reversed even if the database is leaked.
