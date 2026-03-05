"""sign_artifact.py — Ed25519 artifact signing for SLSA supply chain.

Signs a build artifact (binary or provenance JSON) with an Ed25519 private key,
producing a detached signature file (.sig).

The same Ed25519 scheme used by the Varaksha runtime (gateway ↔ agents) is used
here, making the trust model consistent end-to-end.

Signature format:
  A JSON envelope:
  {
    "algorithm":     "ed25519",
    "signer":        "<key fingerprint (first 16 hex chars of public key)>",
    "artifact_sha256": "<sha256 of artifact>",
    "provenance_sha256": "<sha256 of provenance.json, or null>",
    "signed_at":     "<ISO-8601 UTC>",
    "signature":     "<base64url-encoded 64-byte Ed25519 signature>"
  }

  The signed payload (what the signature covers) is:
    SHA256(artifact) | SHA256(provenance) | signed_at (UTF-8)
  concatenated as bytes before signing.

Key management:
  Keys are generated at first use and stored in security/slsa/.keys/
  (excluded from git via .gitignore).  In production, replace with HSM.

Usage (CLI):
    python security/slsa/sign_artifact.py \\
        --artifact   gateway/rust-core/target/release/varaksha-gw.exe \\
        --provenance security/slsa/provenance.json \\
        --key-path   security/slsa/.keys/signing_key.pem \\
        --output     security/slsa/varaksha-gw.sig

Usage (library):
    from security.slsa.sign_artifact import sign, load_or_create_key
    private_key = load_or_create_key("security/slsa/.keys/signing_key.pem")
    sig_path = sign(private_key, artifact_path="...", provenance_path="...")
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: str | Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def _key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """First 16 hex chars of the raw public key bytes."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()[:16]


def generate_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 private key."""
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: str) -> None:
    """Serialize and save private key as PEM (no password)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)
    # Restrict to owner only
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows doesn't support chmod


def save_public_key(key: Ed25519PrivateKey, path: str) -> None:
    """Save the corresponding public key as PEM."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pub_pem)


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)  # type: ignore


def load_public_key(path: str) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())  # type: ignore


def load_or_create_key(key_path: str) -> Ed25519PrivateKey:
    """
    Load existing key from key_path, or generate + save a new one.
    Also saves the public key as <key_path>.pub.
    """
    if os.path.exists(key_path):
        return load_private_key(key_path)

    print(f"[SLSA] No signing key at {key_path} — generating new Ed25519 key pair")
    key = generate_key()
    save_private_key(key, key_path)
    save_public_key(key, key_path + ".pub")
    fp = _key_fingerprint(key.public_key())
    print(f"[SLSA] Key pair saved. Fingerprint: {fp}")
    return key


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _build_payload(
    artifact_sha256_bytes: bytes,
    provenance_sha256_bytes: Optional[bytes],
    signed_at: str,
) -> bytes:
    """
    Build the canonical byte payload that is actually signed.
    Layout: artifact_sha256 (32 bytes) || provenance_sha256 (32 bytes, zeros if None)
            || signed_at (UTF-8)
    """
    prov_bytes = provenance_sha256_bytes or (b"\x00" * 32)
    return artifact_sha256_bytes + prov_bytes + signed_at.encode("utf-8")


def sign(
    private_key: Ed25519PrivateKey,
    artifact_path: str,
    provenance_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> str:
    """
    Sign an artifact (and optionally its provenance) with Ed25519.

    Args:
        private_key:      Ed25519PrivateKey to sign with.
        artifact_path:    Path to the artifact file.
        provenance_path:  Optional path to provenance.json.
        output_path:      Where to write the .sig file (default: artifact + ".sig").

    Returns:
        Path to the written .sig file.
    """
    artifact_path = str(Path(artifact_path).resolve())
    artifact_sha256 = _sha256_file(artifact_path)
    artifact_hex    = artifact_sha256.hex()

    prov_hex: Optional[str] = None
    prov_sha256_bytes: Optional[bytes] = None
    if provenance_path and os.path.exists(provenance_path):
        prov_sha256_bytes = _sha256_file(provenance_path)
        prov_hex = prov_sha256_bytes.hex()

    signed_at = datetime.now(timezone.utc).isoformat()
    payload   = _build_payload(artifact_sha256, prov_sha256_bytes, signed_at)

    raw_sig   = private_key.sign(payload)
    sig_b64   = base64.urlsafe_b64encode(raw_sig).decode("ascii")

    pub_key   = private_key.public_key()
    fingerprint = _key_fingerprint(pub_key)

    envelope = {
        "algorithm":          "ed25519",
        "signer":             fingerprint,
        "artifact_name":      os.path.basename(artifact_path),
        "artifact_sha256":    artifact_hex,
        "provenance_sha256":  prov_hex,
        "signed_at":          signed_at,
        "signature":          sig_b64,
    }

    if output_path is None:
        output_path = artifact_path + ".sig"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(envelope, f, indent=2)

    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Sign a Varaksha build artifact with Ed25519")
    parser.add_argument("--artifact",    required=True, help="Path to artifact to sign")
    parser.add_argument("--provenance",  default=None,  help="Path to provenance.json")
    parser.add_argument("--key-path",    default="security/slsa/.keys/signing_key.pem",
                        help="Ed25519 private key PEM path (generated if missing)")
    parser.add_argument("--output",      default=None,  help="Output .sig file path")
    args = parser.parse_args()

    private_key = load_or_create_key(args.key_path)
    sig_path = sign(
        private_key,
        artifact_path=args.artifact,
        provenance_path=args.provenance,
        output_path=args.output,
    )

    with open(sig_path) as f:
        envelope = json.load(f)

    print(f"[SLSA] Signed artifact    : {args.artifact}")
    print(f"[SLSA] Signature written  : {sig_path}")
    print(f"[SLSA] Signer fingerprint : {envelope['signer']}")
    print(f"[SLSA] Artifact SHA-256   : {envelope['artifact_sha256']}")
    print(f"[SLSA] Signed at          : {envelope['signed_at']}")


if __name__ == "__main__":
    main()
