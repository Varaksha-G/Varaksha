# Varaksha Security Architecture

## Overview

Varaksha is a four-service agentic pipeline for real-time fraud detection.  A
layered security model protects both the *runtime* (live transactions) and the
*supply chain* (code that runs in production).

```
 External Client
      │
      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │   Rust Gateway  (port 8080)                                │
 │   • HMAC-SHA256 request authentication                     │
 │   • Rate limiting (token bucket, per-IP)                   │
 │   • TLS termination                                        │
 └───────────────────────┬─────────────────────────────────────┘
                         │  signed internal request
                         ▼
 ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
 │  Agent 01     │──▶│  Agent 02     │──▶│  Agent 03     │
 │  (Ingest)     │   │  (ML Score)   │   │  (Decision)   │
 │  port 8001    │   │  port 8002    │   │  port 8003    │
 └───────────────┘   └───────────────┘   └───────────────┘
```

---

## Security Layers

The architecture is split into two planes: **runtime security** (protecting
live inference) and **build-time / supply-chain security** (protecting the code
before it ever reaches production).

### Runtime Security (Hot Path)

| Layer | Component | What it does |
|-------|-----------|--------------|
| L0 | Rust Gateway | HMAC-SHA256 signs every inter-service request.  Agents reject unsigned messages. |
| L0 | Rate Limiter | Token-bucket per client IP; blocks enumeration and DoS. |
| L1 | ML Fraud Model | RandomForest classifier scores each transaction; threshold 0.7 for HIGH risk. |
| L1 | Injection Scanner | Cosine-similarity check against known injection prompt embeddings. |

### Supply-Chain Security (GATE-M + SLSA)

Every code change proposed by an AI agent must pass **GATE-M** before it can
be merged or built.  After a successful build, the **SLSA pipeline** produces
a cryptographically signed provenance record that links the artifact back to
the GATE-M approval.

---

## GATE-M — AI Code Gate with Multi-Layer Enforcement

GATE-M sits in the *development* path, not the production hot path.  Its role
is to ensure that no AI-generated code change can introduce a backdoor, data
exfiltration path, or supply-chain implant.

```
 AI Agent proposes a ToolCall (write/read/exec)
          │
          ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Layer 1 — Scope & Forbidden-Path Enforcement               │
 │  CapabilityToken: read_scope, write_scope, forbidden globs  │
 │  Hard-stop if path outside declared scope.                  │
 └─────────────────────────┬───────────────────────────────────┘
                           │ path cleared
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Layer 2 — AST Security Inspection (ast_inspector.py)       │
 │                                                             │
 │  Category A  exec/eval/subprocess/os.system                 │
 │  Category B  network modules, external URL literals         │
 │  Category C  os.environ read → network send (exfiltration)  │
 │  Category D  base64+exec obfuscation, __import__ dynamic    │
 │  Category E  pickle.loads, yaml.load, /proc/* open          │
 │  Category F  inline import of unpinned supply-chain pkg     │
 │                                                             │
 │  CRITICAL finding → hard reject, no override.              │
 │  HIGH finding → block by default.                           │
 └─────────────────────────┬───────────────────────────────────┘
                           │ no CRITICAL/HIGH findings
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Layer 3 — Diff-Intent LLM Verification (verifier.py)       │
 │  Triggers for diffs > 20 lines.                             │
 │  Primary: Groq (llama-3)  Fallback: Gemini                 │
 │  Checks: does the diff match the declared IntentDeclaration?│
 └─────────────────────────┬───────────────────────────────────┘
                           │ intent matches
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Layer 4 — Invariant Checks (kernel.py)                     │
 │  Post-apply assertions: test suite must still pass,         │
 │  critical functions must not be removed.                    │
 └─────────────────────────┬───────────────────────────────────┘
                           │ invariants hold
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Layer 5 — Snapshot & Rollback (snapshot.py)                │
 │  git-stash + file copy before every write.                  │
 │  Any layer failure triggers automatic rollback.             │
 └─────────────────────────┬───────────────────────────────────┘
                           │ all layers pass
                           ▼
                     ToolCall APPROVED
                     (GATE-M task_id recorded)
```

### OS Hooks (Optional, Linux Only)

Three optional monitors observe filesystem and syscall activity during
GATE-M-supervised execution:

| Monitor | Mechanism | Privilege |
|---------|-----------|-----------|
| `fanotify_monitor.py` | `fanotify(2)` FAN_OPEN_PERM — holds kernel open() until verdict | `CAP_SYS_ADMIN` |
| `inotify_monitor.py` | `inotify(7)` IN_CREATE/MODIFY/CLOSE_WRITE — post-hoc event stream | User-land |
| `ebpf_monitor.py` | BCC kprobes on `openat`, `execve`, `connect` syscalls | Root + BCC |

On Windows and in non-privileged environments, all three degrade gracefully
to a `NullMonitor` no-op.  The `os_hooks/__init__.py` factory handles
detection and fallback.

---

## SLSA Supply-Chain Integrity Pipeline

After GATE-M approves a change and the build succeeds, a SLSA Level 2
provenance record is produced, signed, and verified.

```
 GATE-M Approval
 (task_id recorded)
       │
       ▼
 ┌─────────────────┐
 │  Build Artifact │  (varaksha-gw, agents, etc.)
 └────────┬────────┘
          │
          ▼
 generate_provenance.py
 ┌──────────────────────────────────────────────┐
 │  SLSA v0.2 / in-toto v0.1 provenance JSON   │
 │  • artifact SHA-256 (subject digest)         │
 │  • git commit SHA (material)                 │
 │  • dependency lock-file hashes               │
 │  • varaksha_ext.gate_m_task_id ← links back  │
 └──────────────────────────────────────────────┘
          │
          ▼
 sign_artifact.py
 ┌──────────────────────────────────────────────┐
 │  Ed25519 signing                             │
 │  Payload: SHA256(artifact) ‖                 │
 │           SHA256(provenance) ‖ signed_at     │
 │  Output: <artifact>.sig (JSON envelope)      │
 └──────────────────────────────────────────────┘
          │
          ▼
 verify_artifact.py  (CI gate / deployment check)
 ┌──────────────────────────────────────────────┐
 │  Check 1: artifact SHA-256 integrity         │
 │  Check 2: Ed25519 signature validity         │
 │  Check 3: provenance self-hash intact        │
 │  Check 4: gate_m_task_id present & non-empty │
 └──────────────────────────────────────────────┘
          │ all 4 checks pass
          ▼
     Artifact cleared for deployment
```

### Key Management

Keys are stored in `security/slsa/.keys/` (gitignored).  `sign_artifact.py`
generates a new Ed25519 keypair on first use if none exists.  In a production
deployment, this should be replaced with an HSM (FIPS 140-2 Level 3) or a
cloud KMS (e.g. Azure Key Vault, AWS CloudHSM).

---

## Security Battleground — Evaluation Arenas

The `security_battleground/` package provides automated adversarial evaluation
across four arenas:

| Arena | Tests | What it evaluates |
|-------|-------|-------------------|
| `fraud_arena` | 10 | Live Varaksha pipeline: ML model blocks attack transactions |
| `injection_arena` | variable | Prompt/code injection memo scanning (cosine similarity) |
| `gate_m_arena` | 8 | GATEKernel: scope checks, path traversal, forbidden execs |
| `supply_chain_arena` | 9 | AST inspection + scope enforcement against supply-chain attacks |

Run all arenas:

```powershell
.venv\Scripts\python.exe security_battleground/runner.py --arena all
```

Run only supply chain:

```powershell
.venv\Scripts\python.exe security_battleground/runner.py --arena supply_chain
```

Run the SLSA pipeline simulation:

```powershell
.\security\slsa\examples\run_pipeline.ps1
```

---

## Threat Model

### In scope

| Threat | Mitigated by |
|--------|-------------|
| Fraudulent financial transactions | ML model (Agent 02) + Risk threshold |
| Prompt injection in memo/note fields | Injection scanner (Agent 02) |
| AI-generated backdoors in code diffs | GATE-M Layer 1–5 |
| Env var / secret exfiltration via AI code | GATE-M Layer 2 (Category C) |
| Obfuscated malicious payloads | GATE-M Layer 2 (Category D) |
| Unsigned / tampered build artifacts | SLSA sign + verify |
| Build without GATE-M approval | SLSA Check 4 (gate_m_task_id) |
| Supply-chain dependency confusion | GATE-M Layer 2 (Category F) |
| Unauthenticated inter-service calls | Gateway HMAC-SHA256 |

### Out of scope (honest caveat)

- **Runtime zero-day in compiled Rust gateway** — GATE-M does not monitor
  production execution.  Falco eBPF or similar runtime security is needed.
- **Compromised developer workstation** — GATE-M can be bypassed by a
  developer with repo write access.  HSM-backed signing and branch protection
  rules are the correct mitigations.
- **LLM model-level adversarial attacks** — not addressed.

---

## File Map

```
security/
├── gate-m/
│   ├── gate/
│   │   ├── kernel.py            # GATEKernel — orchestrates all 5 layers
│   │   ├── ast_inspector.py     # Layer 2: deep AST scanner (Categories A–F)
│   │   ├── sip_checker.py       # Layer 2: SIP side-effect visitor (legacy)
│   │   ├── verifier.py          # Layer 3: LLM diff-intent verifier
│   │   ├── snapshot.py          # Layer 5: git-stash + file snapshot
│   │   ├── models.py            # CapabilityToken, ToolCall, ApprovalResult
│   │   ├── os_watcher.py        # OS watcher (fanotify / audit hook)
│   │   ├── token.py
│   │   ├── cli.py
│   │   └── corrector.py
│   └── os_hooks/
│       ├── __init__.py          # Factory: get_monitor(backend, ...)
│       ├── fanotify_monitor.py  # Linux fanotify FAN_OPEN_PERM
│       ├── inotify_monitor.py   # inotify_simple + sys.addaudithook fallback
│       └── ebpf_monitor.py      # BCC eBPF kprobe monitor
└── slsa/
    ├── __init__.py
    ├── generate_provenance.py   # SLSA v0.2 provenance generator
    ├── sign_artifact.py         # Ed25519 artifact signing
    ├── verify_artifact.py       # 4-point SLSA verification
    ├── .keys/                   # gitignored — signing keypair
    ├── pipeline_output/         # gitignored — pipeline artefacts
    └── examples/
        ├── pipeline_simulation.py  # 5-step pipeline simulation
        └── run_pipeline.ps1        # PowerShell wrapper

security_battleground/
├── runner.py                    # Entry point — all 4 arenas
├── arenas/
│   ├── fraud_arena.py
│   ├── injection_arena.py
│   ├── gate_m_arena.py
│   └── supply_chain_arena.py    # NEW — 9 supply-chain attack tests
├── attacks/
│   ├── fraud_attacks.json
│   ├── injection_attacks.json
│   └── gate_m_attacks.json
├── report/
│   └── battleground_report.json
└── sandbox/
    └── src/
        └── sample_agent.py
```
