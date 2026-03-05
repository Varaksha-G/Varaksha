"""generate_provenance.py — SLSA Build Provenance Generator.

Produces a SLSA provenance record (in-toto Statement v0.1,
predicateType slsa.dev/provenance/v0.2) for a Varaksha build artifact.

The provenance record cryptographically binds:
  • The source commit hash (what code was compiled)
  • Build timestamp
  • Builder identity
  • Dependency hashes (requirements.txt / Cargo.lock)
  • GATE-M approval token ID (links supply-chain gate to this build)

Output: provenance.json — a JSON file that can be bundled alongside
the artifact and verified before any deployment.

Usage (CLI):
    python security/slsa/generate_provenance.py \\
        --artifact gateway/rust-core/target/release/varaksha-gw.exe \\
        --output   security/slsa/provenance.json \\
        --gate-m-task-id <uuid from gate-m session log>

Usage (library):
    from security.slsa.generate_provenance import build_provenance, write_provenance
    prov = build_provenance(artifact_path="...", gate_m_task_id="...")
    write_provenance(prov, "provenance.json")
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# SLSA provenance schema constants
# ---------------------------------------------------------------------------

_STATEMENT_TYPE   = "https://in-toto.io/Statement/v0.1"
_PREDICATE_TYPE   = "https://slsa.dev/provenance/v0.2"
_BUILDER_ID       = "https://github.com/Vibhor2702/Varaksha/builders/local-v1"
_BUILD_TYPE       = "https://github.com/Vibhor2702/Varaksha/buildTypes/make@v1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: str | Path) -> str:
    """SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _git_commit_hash(repo_root: str) -> Optional[str]:
    """Return HEAD commit hash, or None if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _git_remote_url(repo_root: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _collect_dependency_hashes(repo_root: str) -> dict[str, str]:
    """
    Hash known dependency lock files to capture dependency state.
    Returns a dict of {relative_path: sha256}.
    """
    candidates = [
        "gateway/rust-core/Cargo.lock",
        "services/agents/requirements.txt",
        "security/gate-m/pyproject.toml",
    ]
    result: dict[str, str] = {}
    root = Path(repo_root)
    for rel in candidates:
        full = root / rel
        if full.exists():
            result[rel] = _sha256_file(full)
    return result


# ---------------------------------------------------------------------------
# Core provenance builder
# ---------------------------------------------------------------------------

def build_provenance(
    artifact_path: str,
    repo_root: str | None = None,
    gate_m_task_id: str | None = None,
    builder_id: str = _BUILDER_ID,
) -> dict:
    """
    Build a SLSA provenance record for the given artifact.

    Args:
        artifact_path:    Path to the compiled binary or package.
        repo_root:        Root of the git repository (auto-detected if None).
        gate_m_task_id:   GATE-M CapabilityToken task_id that approved the
                          code changes in this build.  None if not using GATE-M.
        builder_id:       URI identifying the build system.

    Returns:
        dict: SLSA provenance record (in-toto Statement).
    """
    artifact_path = str(Path(artifact_path).resolve())
    if not os.path.exists(artifact_path):
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    if repo_root is None:
        # Walk up from artifact to find .git
        search = Path(artifact_path)
        for parent in search.parents:
            if (parent / ".git").exists():
                repo_root = str(parent)
                break
        else:
            repo_root = str(Path(artifact_path).parent)

    artifact_name = Path(artifact_path).name
    artifact_sha256 = _sha256_file(artifact_path)

    commit_hash = _git_commit_hash(repo_root)
    remote_url  = _git_remote_url(repo_root)
    dep_hashes  = _collect_dependency_hashes(repo_root)
    build_ts    = datetime.now(timezone.utc).isoformat()

    # Materials = source + dependency lock files
    materials: list[dict] = []

    if commit_hash and remote_url:
        materials.append({
            "uri":    remote_url,
            "digest": {"sha1": commit_hash},
        })

    for dep_path, dep_hash in dep_hashes.items():
        materials.append({
            "uri":    f"file://{dep_path}",
            "digest": {"sha256": dep_hash},
        })

    # Build invocation parameters
    invocation: dict = {
        "configSource": {
            "uri":        remote_url or "file://local",
            "digest":     {"sha1": commit_hash} if commit_hash else {},
            "entryPoint": "Makefile",
        },
        "parameters": {
            "gate_m_task_id": gate_m_task_id or "not_recorded",
            "build_host":     os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "unknown"),
        },
    }

    # SLSA metadata
    metadata: dict = {
        "buildStartedOn":   build_ts,
        "buildFinishedOn":  build_ts,
        "completeness": {
            "parameters":  True,
            "environment": False,
            "materials":   bool(materials),
        },
        "reproducible": False,
    }

    # Full in-toto statement
    statement = {
        "_type":         _STATEMENT_TYPE,
        "predicateType": _PREDICATE_TYPE,
        "subject": [
            {
                "name":   artifact_name,
                "digest": {"sha256": artifact_sha256},
            }
        ],
        "predicate": {
            "builder":     {"id": builder_id},
            "buildType":   _BUILD_TYPE,
            "invocation":  invocation,
            "buildConfig": None,
            "metadata":    metadata,
            "materials":   materials,
        },
        # Varaksha-specific extension
        "varaksha_ext": {
            "gate_m_task_id":   gate_m_task_id or "not_recorded",
            "artifact_path":    artifact_path,
            "provenance_sha256": None,  # filled by write_provenance after serialization
        },
    }

    return statement


def write_provenance(provenance: dict, output_path: str) -> str:
    """
    Serialize provenance to JSON and fill in self-hash.
    Returns the output path.
    """
    output_path = str(Path(output_path))

    # Serialize without self-hash first
    body = json.dumps(provenance, indent=2, sort_keys=True)

    # Compute hash of the serialized body and embed it
    body_hash = _sha256_text(body)
    provenance["varaksha_ext"]["provenance_sha256"] = body_hash

    # Re-serialize with hash included
    final = json.dumps(provenance, indent=2, sort_keys=True)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w") as f:
        f.write(final)

    return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate SLSA provenance for a Varaksha build artifact"
    )
    parser.add_argument("--artifact",       required=True, help="Path to build artifact")
    parser.add_argument("--output",         default="security/slsa/provenance.json",
                        help="Output provenance JSON path")
    parser.add_argument("--gate-m-task-id", default=None,
                        help="GATE-M CapabilityToken task ID that approved this build")
    parser.add_argument("--repo-root",      default=None,
                        help="Git repository root (auto-detected if omitted)")
    args = parser.parse_args()

    print(f"[SLSA] Generating provenance for: {args.artifact}")
    prov = build_provenance(
        artifact_path=args.artifact,
        repo_root=args.repo_root,
        gate_m_task_id=args.gate_m_task_id,
    )
    out = write_provenance(prov, args.output)
    print(f"[SLSA] Provenance written → {out}")

    artifact_digest = prov["subject"][0]["digest"]["sha256"]
    commit = prov["predicate"]["materials"][0]["digest"].get("sha1", "n/a") if prov["predicate"]["materials"] else "n/a"
    print(f"[SLSA] Artifact SHA-256 : {artifact_digest}")
    print(f"[SLSA] Source commit    : {commit}")
    print(f"[SLSA] GATE-M task      : {args.gate_m_task_id or 'not_recorded'}")


if __name__ == "__main__":
    main()
