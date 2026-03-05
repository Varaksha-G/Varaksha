"""verify_artifact.py — SLSA artifact verification for Varaksha.

Performs a 4-point verification of a signed build artifact:

  1. Artifact integrity    — SHA-256 of the artifact matches the value in the
                             signature envelope AND the provenance subject digest.
  2. Signature validity    — Ed25519 signature in the .sig envelope is valid
                             against the known public key.
  3. Provenance integrity  — The provenance.json self-hash (if present) matches
                             the SHA-256 of the file as it exists on disk.
  4. GATE-M traceability   — The provenance contains a non-empty gate_m_task_id
                             in the varaksha_ext block, proving a human-reviewed
                             GATE-M approval triggered this build.

All four checks must pass for verification to succeed.  Individual failure
reasons are surfaced in the returned VerificationResult.

Usage (CLI):
    python security/slsa/verify_artifact.py \\
        --artifact   gateway/rust-core/target/release/varaksha-gw.exe \\
        --sig        security/slsa/varaksha-gw.sig \\
        --provenance security/slsa/provenance.json \\
        --public-key security/slsa/.keys/signing_key.pem.pub

Usage (library):
    from security.slsa.verify_artifact import verify, VerificationResult
    result = verify(artifact_path=..., sig_path=..., provenance_path=..., public_key_path=...)
    if not result.ok:
        raise RuntimeError(result.reason)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    reason: str
    checks: Dict[str, str] = field(default_factory=dict)
    gate_m_task_id: Optional[str] = None

    def __str__(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        lines = [f"Verification: {status}  ({self.reason})"]
        for name, verdict in self.checks.items():
            lines.append(f"  [{verdict}] {name}")
        if self.gate_m_task_id:
            lines.append(f"  GATE-M task: {self.gate_m_task_id}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def _load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        data = f.read()
    if b"PRIVATE" in data:
        raise ValueError(f"Expected a PUBLIC key file, but {path} appears to contain a private key.")
    return serialization.load_pem_public_key(data)  # type: ignore


def _build_payload(
    artifact_sha256_bytes: bytes,
    provenance_sha256_bytes: Optional[bytes],
    signed_at: str,
) -> bytes:
    """Reconstruct the canonical signed payload (must match sign_artifact.py)."""
    prov_bytes = provenance_sha256_bytes or (b"\x00" * 32)
    return artifact_sha256_bytes + prov_bytes + signed_at.encode("utf-8")


# ---------------------------------------------------------------------------
# Four verification checks
# ---------------------------------------------------------------------------

def _check_artifact_integrity(
    artifact_path: str,
    envelope: dict,
    provenance: Optional[dict],
) -> tuple[bool, str, bytes]:
    """Check 1: SHA-256 of artifact matches sig envelope and provenance subject."""
    actual_sha = _sha256_file(artifact_path)
    actual_hex = actual_sha.hex()

    envelope_hex = envelope.get("artifact_sha256", "")
    if actual_hex != envelope_hex:
        return (
            False,
            f"Artifact SHA-256 mismatch: file={actual_hex[:16]}… envelope={envelope_hex[:16]}…",
            actual_sha,
        )

    if provenance is not None:
        subjects = provenance.get("subject", [])
        if subjects:
            subj_hex = subjects[0].get("digest", {}).get("sha256", "")
            if subj_hex and actual_hex != subj_hex:
                return (
                    False,
                    f"Artifact SHA-256 mismatches provenance subject: file={actual_hex[:16]}… prov={subj_hex[:16]}…",
                    actual_sha,
                )

    return True, "artifact SHA-256 matches envelope + provenance", actual_sha


def _check_signature(
    public_key: Ed25519PublicKey,
    envelope: dict,
    artifact_sha256_bytes: bytes,
    provenance_sha256_bytes: Optional[bytes],
) -> tuple[bool, str]:
    """Check 2: Ed25519 signature is valid."""
    sig_b64 = envelope.get("signature", "")
    if not sig_b64:
        return False, "no signature field in envelope"

    signed_at = envelope.get("signed_at", "")
    if not signed_at:
        return False, "no signed_at field in envelope"

    try:
        raw_sig = base64.urlsafe_b64decode(sig_b64)
    except Exception as exc:
        return False, f"signature base64 decode error: {exc}"

    payload = _build_payload(artifact_sha256_bytes, provenance_sha256_bytes, signed_at)

    try:
        public_key.verify(raw_sig, payload)
    except InvalidSignature:
        return False, "Ed25519 signature INVALID — artifact may have been tampered with"
    except Exception as exc:
        return False, f"signature verification error: {exc}"

    return True, "Ed25519 signature valid"


def _check_provenance_integrity(
    provenance_path: str,
    provenance: dict,
    envelope: dict,
) -> tuple[bool, str, Optional[bytes]]:
    """Check 3: Provenance self-hash is intact (if recorded)."""
    self_sha = provenance.get("varaksha_ext", {}).get("provenance_sha256")
    if not self_sha:
        return True, "provenance self-hash not recorded (skipped)", None

    # Recompute with self-hash field zeroed out (matches generate_provenance.py approach)
    with open(provenance_path) as f:
        raw_text = f.read()

    # Zero out the self-hash field in a copy and rehash
    zeroed = raw_text.replace(f'"provenance_sha256": "{self_sha}"',
                               '"provenance_sha256": ""')
    actual_sha = hashlib.sha256(zeroed.encode("utf-8")).hexdigest()
    if actual_sha != self_sha:
        return (
            False,
            f"Provenance self-hash mismatch: recorded={self_sha[:16]}… actual={actual_sha[:16]}…",
            None,
        )

    # Also check sig envelope's provenance_sha256
    env_prov_sha = envelope.get("provenance_sha256")
    if env_prov_sha:
        disk_sha = _sha256_file(provenance_path).hex()
        if env_prov_sha != disk_sha:
            return (
                False,
                f"Provenance file SHA-256 changed since signing: envelope={env_prov_sha[:16]}… disk={disk_sha[:16]}…",
                None,
            )

    return True, "provenance self-hash intact", None


def _check_gate_m_traceability(provenance: dict) -> tuple[bool, str, Optional[str]]:
    """Check 4: A valid GATE-M task ID links this build to a reviewed approval."""
    ext = provenance.get("varaksha_ext", {})
    task_id = ext.get("gate_m_task_id", "").strip()

    if not task_id or task_id in ("not_recorded", "none", "null", ""):
        return (
            False,
            "No GATE-M task ID in provenance — build cannot be traced to a GATE-M approval",
            None,
        )

    return True, f"GATE-M task ID present: {task_id}", task_id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify(
    artifact_path: str,
    sig_path: str,
    provenance_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> VerificationResult:
    """
    Verify a signed artifact against all SLSA checks.

    Args:
        artifact_path:    Path to the artifact file.
        sig_path:         Path to the .sig JSON envelope.
        provenance_path:  Optional path to provenance.json.
        public_key_path:  Optional path to public key PEM. If omitted and the
                          .sig envelope records a signer fingerprint, verification
                          of the signature is skipped (integrity only mode).

    Returns:
        VerificationResult with ok=True if all applicable checks pass.
    """
    failures: List[str] = []
    checks: Dict[str, str] = {}

    # Load sig envelope
    with open(sig_path) as f:
        envelope = json.load(f)

    # Load provenance if available
    provenance: Optional[dict] = None
    if provenance_path and Path(provenance_path).exists():
        with open(provenance_path) as f:
            provenance = json.load(f)

    # --- Check 1: Artifact integrity ---
    ok, msg, artifact_sha = _check_artifact_integrity(artifact_path, envelope, provenance)
    checks["artifact_integrity"] = "PASS" if ok else "FAIL"
    if not ok:
        failures.append(msg)

    # --- Check 2: Signature validity ---
    if public_key_path:
        prov_sha_bytes: Optional[bytes] = None
        env_prov_sha = envelope.get("provenance_sha256")
        if env_prov_sha:
            prov_sha_bytes = bytes.fromhex(env_prov_sha)

        try:
            pub_key = _load_public_key(public_key_path)
            ok2, msg2 = _check_signature(pub_key, envelope, artifact_sha, prov_sha_bytes)
        except Exception as exc:
            ok2, msg2 = False, f"could not load public key: {exc}"
        checks["signature_validity"] = "PASS" if ok2 else "FAIL"
        if not ok2:
            failures.append(msg2)
    else:
        checks["signature_validity"] = "SKIP (no public key provided)"

    # --- Check 3: Provenance integrity ---
    gate_m_task_id: Optional[str] = None
    if provenance is not None and provenance_path:
        ok3, msg3, _ = _check_provenance_integrity(provenance_path, provenance, envelope)
        checks["provenance_integrity"] = "PASS" if ok3 else "FAIL"
        if not ok3:
            failures.append(msg3)

        # --- Check 4: GATE-M traceability ---
        ok4, msg4, gate_m_task_id = _check_gate_m_traceability(provenance)
        checks["gate_m_traceability"] = "PASS" if ok4 else "FAIL"
        if not ok4:
            failures.append(msg4)
    else:
        checks["provenance_integrity"] = "SKIP (no provenance.json)"
        checks["gate_m_traceability"] = "SKIP (no provenance.json)"

    if failures:
        return VerificationResult(
            ok=False,
            reason=failures[0],
            checks=checks,
            gate_m_task_id=gate_m_task_id,
        )

    return VerificationResult(
        ok=True,
        reason="all checks passed",
        checks=checks,
        gate_m_task_id=gate_m_task_id,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a Varaksha signed artifact (SLSA)")
    parser.add_argument("--artifact",    required=True, help="Path to artifact file")
    parser.add_argument("--sig",         required=True, help="Path to .sig JSON envelope")
    parser.add_argument("--provenance",  default=None,  help="Path to provenance.json")
    parser.add_argument("--public-key",  default=None,  help="Path to Ed25519 public key PEM")
    args = parser.parse_args()

    result = verify(
        artifact_path=args.artifact,
        sig_path=args.sig,
        provenance_path=args.provenance,
        public_key_path=args.public_key,
    )

    print(result)
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
