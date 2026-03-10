
# Varaksha V2 — Rust Gateway (Layer 2)

This document explains how to **run the Rust gateway** used in the Varaksha V2 fraud detection pipeline.

The Rust gateway provides **real-time (<5 ms) transaction risk decisions** using an in-memory fraud intelligence cache.

The Python ML and graph components interact with this service via HTTP.

---

# Architecture Overview

```

External Client
│
▼
Rust Gateway (Layer 2)
│
├── In-memory risk cache (DashMap)
│
▼
Verdict: ALLOW / FLAG / BLOCK

Python ML Engine (Layer 1)
│
▼
Graph Agent (Layer 3)
│
▼
POST /v1/webhook/update_cache

```

Key idea:

```

Transaction path = Rust
Heavy ML analysis = Python

```

This keeps the transaction decision path extremely fast.

---

# Rust Components

## gateway/

HTTP server implemented with **Actix Web**.

Responsibilities:

- serve HTTP API endpoints
- hash raw VPAs
- query the risk cache
- return verdicts
- accept async risk updates from Python graph agent

Docs:  
https://actix.rs

---

## risk-cache/

Rust library crate that implements:

- concurrent in-memory fraud intelligence cache
- TTL expiration
- background cleanup worker
- cache metrics

The cache uses **DashMap**, a concurrent hash map.

Docs:  
https://docs.rs/dashmap

---

# Directory Structure

```

varaksha/
│
├── gateway/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       └── models.rs
│
├── risk-cache/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── cache.rs
│       ├── entry.rs
│       ├── cleaner.rs
│       └── metrics.rs
│
├── services/
│   ├── local_engine/
│   ├── graph/
│   └── agents/
│
└── data/

````

---

# Prerequisites

Install Rust:

https://www.rust-lang.org/tools/install

Verify installation:

```bash
rustc --version
cargo --version
````

Example output:

```
rustc 1.78.0
cargo 1.78.0
```

---

# Environment Variables

The gateway requires a webhook secret.

```
VARAKSHA_WEBHOOK_SECRET
```

Example:

### Linux / macOS

```bash
export VARAKSHA_WEBHOOK_SECRET=mysecret
```

### Windows PowerShell

```powershell
$env:VARAKSHA_WEBHOOK_SECRET="mysecret"
```

This secret is used to verify **HMAC-SHA256 webhook signatures**.

---

# Running the Rust Gateway

Navigate to the gateway directory.

```bash
cd gateway
```

Build the project.

```bash
cargo build
```

Run the gateway.

```bash
cargo run
```

Expected output:

```
Varaksha V2 Gateway starting on port 8082
```

Gateway runs at:

```
http://localhost:8082
```

---

# API Endpoints

## Health Check

```
GET /health
```

Test:

```bash
curl http://localhost:8082/health
```

Response:

```json
{
 "status": "ok",
 "cache_entries": 0,
 "version": "2.0.0"
}
```

---

# Real-Time Transaction Risk Check

```
POST /v1/tx
```

Example request:

```bash
curl -X POST http://localhost:8082/v1/tx \
-H "Content-Type: application/json" \
-d '{
 "vpa":"alice@okaxis",
 "amount_paise":10000,
 "merchant_category":"5411",
 "device_id":"abc123",
 "initiated_at":"2026-03-10T10:00:00Z"
}'
```

Example response:

```json
{
 "vpa_hash": "7a9f1a...",
 "verdict": "ALLOW",
 "risk_score": 0.0,
 "trace_id": "uuid",
 "latency_us": 200
}
```

---

# Verdict Logic

```
risk_score < 0.40  → ALLOW
0.40 – 0.75        → FLAG
≥ 0.75             → BLOCK
```

Meaning:

| Verdict | Meaning                          |
| ------- | -------------------------------- |
| ALLOW   | transaction proceeds normally    |
| FLAG    | additional verification required |
| BLOCK   | transaction rejected             |

---

# Graph Agent → Cache Update

The Python graph engine updates the cache via:

```
POST /v1/webhook/update_cache
```

Example request:

```json
{
 "vpa_hash": "abc123",
 "risk_score": 0.85,
 "reason": "GRAPH:FAN_OUT",
 "ttl_seconds": 600
}
```

This inserts or updates a cache entry.

---

# Webhook Authentication

Cache updates are authenticated using **HMAC-SHA256**.

Required header:

```
x-varaksha-sig
```

Signature format:

```
HMAC_SHA256(secret, "hash:score:reason:ttl")
```

Example Python signature generation:

```python
import hmac
import hashlib

secret=b"mysecret"
msg=b"abc123:0.85:GRAPH:FAN_OUT:600"

print(hmac.new(secret,msg,hashlib.sha256).hexdigest())
```

Send the signature as:

```
x-varaksha-sig: <signature>
```

Invalid signatures return:

```
HTTP 401 Unauthorized
```

---

# Cache Behavior

Each cache entry contains:

```
risk_score
reason
expiration timestamp
```

TTL is provided by the graph agent.

Example:

```
ttl_seconds = 600
```

Entries expire automatically via a background cleanup worker.

---

# Performance

Typical latency:

```
100–500 microseconds
```

Target latency:

```
< 5 ms
```

This is possible because:

* risk lookups occur entirely in-memory
* DashMap supports concurrent access
* heavy ML computation runs outside the transaction path

---

# Logging

The gateway logs:

* cache updates
* blocked transactions
* invalid webhook signatures

Example log:

```
WARN BLOCKED tx hash=abc123 score=0.92 reason=GRAPH:CYCLE
```

Logging crate:

[https://docs.rs/log](https://docs.rs/log)

---

# Quick Local Test

Start gateway:

```bash
cargo run
```

Check health:

```bash
curl http://localhost:8082/health
```

Test transaction endpoint:

```bash
curl -X POST http://localhost:8082/v1/tx \
-H "Content-Type: application/json" \
-d '{"vpa":"alice@okaxis","amount_paise":10000,"merchant_category":"5411","device_id":"abc123","initiated_at":"2026-03-10T10:00:00Z"}'
```

---

# Integration With Python Pipeline

The Python components interact with the gateway in two ways.

### ML Engine

The ML model produces fraud intelligence signals.

It does **not directly call the gateway**.

---

### Graph Agent

The graph agent sends risk updates:

```
POST /v1/webhook/update_cache
```

The gateway then serves these scores during real-time transaction checks.

---

# Summary

The Rust gateway provides:

* real-time fraud decisioning
* sub-5 ms latency
* privacy-preserving SHA-256 VPA hashing
* concurrent in-memory risk cache
* secure webhook updates via HMAC
* automatic TTL eviction

It acts as the **low-latency fraud intelligence layer connecting the payment system and the Python ML pipeline**.

```
```
