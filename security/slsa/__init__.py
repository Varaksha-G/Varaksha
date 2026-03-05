"""SLSA supply chain security for Varaksha.

Implements SLSA Level 2 build provenance generation, Ed25519 artifact signing,
and deployment-time verification.

Modules:
  generate_provenance  — create SLSA provenance.json from build inputs
  sign_artifact        — Ed25519-sign a build artifact
  verify_artifact      — verify signature + provenance integrity before deploy

SLSA specification: https://slsa.dev/spec/v0.1/
Provenance format: SLSA Provenance v0.2 (in-toto Statement)
"""
