"""pipeline_simulation.py — End-to-end SLSA pipeline simulation for Varaksha.

Simulates the 5-step secure build pipeline that a CI/CD system would execute:

  Step 1 — GATE-M Review    : Submit a code diff for GATE-M approval
  Step 2 — Build            : Compile / assemble the artifact (simulated)
  Step 3 — Provenance       : Generate SLSA v0.2 provenance JSON
  Step 4 — Sign             : Ed25519-sign artifact + provenance
  Step 5 — Verify           : Verify signature + 4-point SLSA checks

The pipeline writes artefacts to security/slsa/pipeline_output/ and prints
a structured summary of each step.

Usage:
    python security/slsa/examples/pipeline_simulation.py \\
        [--gate-m-task-id <uuid>] [--output-dir <path>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import textwrap
import time
import uuid
from pathlib import Path
from typing import Optional

# ── repo root on path ─────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_SLSA_DIR = _ROOT / "security" / "slsa"
_GATE_M_PKG = _ROOT / "security" / "gate-m"
if str(_GATE_M_PKG) not in sys.path:
    sys.path.insert(0, str(_GATE_M_PKG))


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def _header(n: int, title: str) -> None:
    width = 60
    print()
    print("=" * width)
    print(f"  Step {n}/{_TOTAL_STEPS}: {title}")
    print("=" * width)


def _ok(msg: str) -> None:
    print(f"  [PASS]  {msg}")


def _fail(msg: str) -> None:
    print(f"  [FAIL]  {msg}")


def _info(msg: str) -> None:
    print(f"  [INFO]  {msg}")


_TOTAL_STEPS = 5

# ---------------------------------------------------------------------------
# Simulated diff (a safe null-check fix — no dangerous patterns)
# ---------------------------------------------------------------------------

_SAFE_DIFF = textwrap.dedent("""\
    --- a/services/agents/agent01/main.py
    +++ b/services/agents/agent01/main.py
    @@ -42,6 +42,9 @@ async def evaluate(request: FraudRequest):
         risk = model.predict(request.transaction_id)
    +    if risk is None:
    +        risk = 0.0
         return {"risk": float(risk)}
""")

# ---------------------------------------------------------------------------
# Step 1 — GATE-M Review
# ---------------------------------------------------------------------------

def step_gate_m_review(diff: str, task_id: str) -> bool:
    _header(1, "GATE-M Review")

    # Try real AST inspector; fall back to pass-through if unavailable
    try:
        from gate.ast_inspector import ASTInspector  # type: ignore
        inspector = ASTInspector()
        findings = inspector.inspect_diff(diff)
        if inspector.has_critical_findings():
            for f in findings:
                if f.severity == "CRITICAL":
                    _fail(f"AST CRITICAL: {f.message}")
            return False
        _ok(f"AST inspection: {len(findings)} finding(s), none CRITICAL")
    except ImportError:
        _info("ast_inspector not importable in this context — performing pattern scan")
        dangerous = ["subprocess", "eval(", "exec(", "os.system", "requests.get",
                     "os.environ", "base64.b64decode"]
        hits = [p for p in dangerous if p in diff]
        if hits:
            _fail(f"Pattern scan blocked: {hits}")
            return False
        _ok("Pattern scan: no dangerous patterns found")

    _ok(f"GATE-M approved (task_id={task_id})")
    return True


# ---------------------------------------------------------------------------
# Step 2 — Build
# ---------------------------------------------------------------------------

def step_build(output_dir: Path, task_id: str) -> Optional[Path]:
    _header(2, "Build (simulated)")

    # Produce a synthetic binary representing the patch + a hash of its intent
    content = (
        f"VARAKSHA_BUILD\n"
        f"gate_m_task_id={task_id}\n"
        f"build_host=pipeline_simulation\n"
        f"diff_sha256={hashlib.sha256(_SAFE_DIFF.encode()).hexdigest()}\n"
    ).encode("utf-8")

    artifact_path = output_dir / "varaksha_patch.bin"
    with open(artifact_path, "wb") as f:
        f.write(content)

    sha = hashlib.sha256(content).hexdigest()
    _ok(f"Artifact: {artifact_path.name}")
    _ok(f"SHA-256 : {sha}")
    return artifact_path


# ---------------------------------------------------------------------------
# Step 3 — Provenance
# ---------------------------------------------------------------------------

def step_provenance(artifact_path: Path, output_dir: Path, task_id: str) -> Optional[Path]:
    _header(3, "Generate SLSA Provenance")

    prov_path = output_dir / "provenance.json"

    try:
        from security.slsa.generate_provenance import build_provenance, write_provenance

        prov = build_provenance(
            artifact_path=str(artifact_path),
            repo_root=str(_ROOT),
            gate_m_task_id=task_id,
        )
        write_provenance(prov, str(prov_path))
        _ok(f"Provenance written: {prov_path.name}")
        _ok(f"builder.id: {prov['predicate']['builder']['id']}")
        _ok(f"gate_m_task_id: {prov['predicate']['varaksha_ext']['gate_m_task_id']}")
        return prov_path

    except Exception as exc:
        # fallback — write minimal provenance
        _info(f"generate_provenance unavailable ({exc}) — writing minimal provenance")
        sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        prov = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": artifact_path.name, "digest": {"sha256": sha256}}],
            "predicate": {
                "builder": {"id": "https://github.com/Varaksha/pipeline-simulation"},
                "buildType": "varaksha/pipeline_simulation/v1",
                "varaksha_ext": {
                    "gate_m_task_id": task_id,
                    "provenance_sha256": "",
                },
            },
        }
        with open(prov_path, "w") as f:
            json.dump(prov, f, indent=2)
        _ok(f"Minimal provenance written: {prov_path.name}")
        return prov_path


# ---------------------------------------------------------------------------
# Step 4 — Sign
# ---------------------------------------------------------------------------

def step_sign(
    artifact_path: Path,
    prov_path: Path,
    output_dir: Path,
) -> Optional[Path]:
    _header(4, "Sign Artifact (Ed25519)")

    sig_path = output_dir / (artifact_path.name + ".sig")
    key_path = _SLSA_DIR / ".keys" / "signing_key.pem"

    try:
        from security.slsa.sign_artifact import load_or_create_key, sign

        private_key = load_or_create_key(str(key_path))
        actual_sig_path = sign(
            private_key,
            artifact_path=str(artifact_path),
            provenance_path=str(prov_path),
            output_path=str(sig_path),
        )
        with open(actual_sig_path) as f:
            env = json.load(f)
        _ok(f"Signature written : {sig_path.name}")
        _ok(f"Signer fingerprint: {env['signer']}")
        _ok(f"Signed at         : {env['signed_at']}")
        return sig_path

    except Exception as exc:
        _fail(f"Signing failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Step 5 — Verify
# ---------------------------------------------------------------------------

def step_verify(
    artifact_path: Path,
    sig_path: Path,
    prov_path: Path,
    output_dir: Path,
) -> bool:
    _header(5, "Verify Artifact (SLSA 4-point check)")

    pub_key_path = _SLSA_DIR / ".keys" / "signing_key.pem.pub"

    try:
        from security.slsa.verify_artifact import verify

        result = verify(
            artifact_path=str(artifact_path),
            sig_path=str(sig_path),
            provenance_path=str(prov_path),
            public_key_path=str(pub_key_path) if pub_key_path.exists() else None,
        )
        for check, verdict in result.checks.items():
            if verdict == "PASS":
                _ok(f"{check}: {verdict}")
            elif verdict.startswith("SKIP"):
                _info(f"{check}: {verdict}")
            else:
                _fail(f"{check}: {verdict}")

        if result.gate_m_task_id:
            _ok(f"GATE-M task linked: {result.gate_m_task_id}")

        return result.ok

    except Exception as exc:
        _fail(f"Verification engine unavailable: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(output_dir: Path, gate_m_task_id: str) -> bool:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   VARAKSHA SLSA SECURE PIPELINE SIMULATION          ║")
    print("╚══════════════════════════════════════════════════════╝")
    _info(f"Output directory: {output_dir}")
    _info(f"GATE-M task ID  : {gate_m_task_id}")

    output_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    # Step 1 — GATE-M
    if not step_gate_m_review(_SAFE_DIFF, gate_m_task_id):
        _fail("Pipeline aborted at Step 1 (GATE-M Review)")
        return False

    # Step 2 — Build
    artifact = step_build(output_dir, gate_m_task_id)
    if not artifact:
        _fail("Pipeline aborted at Step 2 (Build)")
        return False

    # Step 3 — Provenance
    prov = step_provenance(artifact, output_dir, gate_m_task_id)
    if not prov:
        _fail("Pipeline aborted at Step 3 (Provenance)")
        return False

    # Step 4 — Sign
    sig = step_sign(artifact, prov, output_dir)
    if not sig:
        _fail("Pipeline aborted at Step 4 (Sign)")
        return False

    # Step 5 — Verify
    ok = step_verify(artifact, sig, prov, output_dir)

    elapsed = (time.perf_counter() - t0) * 1000
    print()
    print("=" * 60)
    if ok:
        print(f"  PIPELINE RESULT: PASS  ({elapsed:.0f} ms)")
    else:
        print(f"  PIPELINE RESULT: FAIL  ({elapsed:.0f} ms)")
    print("=" * 60)
    print()
    return ok


def main() -> None:
    parser = argparse.ArgumentParser(description="Varaksha SLSA pipeline simulation")
    parser.add_argument(
        "--gate-m-task-id",
        default=None,
        help="GATE-M task UUID to embed in provenance (generated if omitted)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(_SLSA_DIR / "pipeline_output"),
        help="Directory to write pipeline artefacts",
    )
    args = parser.parse_args()

    task_id = args.gate_m_task_id or str(uuid.uuid4())
    ok = run_pipeline(Path(args.output_dir), task_id)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
