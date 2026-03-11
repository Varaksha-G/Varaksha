"""
services/graph/graph_agent.py
──────────────────────────────
Layer 3: Asynchronous Graph Network (BIS Project Aurora model)
Varaksha V2

Runs OUT of the payment hot path.
Builds a directed transaction graph with NetworkX, detects money-mule
typologies, and pushes risk scores to the Rust DashMap cache via webhook.

Typologies detected (matching BIS Project Hertha taxonomy):
  - Fan-out   : one source node → many destinations  (rapid disbursement)
  - Fan-in    : many sources   → one destination     (fund collection)
  - Cycle     : simple directed cycle A→B→C→A        (layering / circular flow)
  - Scatter   : high out-degree > in-degree node     (structuring)

Usage:
    python services/graph/graph_agent.py
    python services/graph/graph_agent.py --iterations 5 --interval 30
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import time
from dataclasses import dataclass, field

import networkx as nx
import numpy as np
import requests  # type: ignore

log = logging.getLogger("varaksha.graph_agent")

GATEWAY_WEBHOOK = "http://localhost:8082/v1/webhook/update_cache"
WEBHOOK_SECRET  = "dev-secret-change-me"   # Must match $VARAKSHA_WEBHOOK_SECRET in the Rust env

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class MuleCluster:
    """A detected money-mule cluster."""
    nodes:       list[str]          # hashed VPA node IDs
    typology:    str                # "FAN_OUT" | "FAN_IN" | "CYCLE" | "SCATTER"
    risk_score:  float              # 0.0 – 1.0
    edge_count:  int


@dataclass
class GraphSweepResult:
    clusters_found:  int
    nodes_flagged:   int
    sweep_duration_s: float
    clusters:        list[MuleCluster] = field(default_factory=list)


# ── Synthetic graph builder ───────────────────────────────────────────────────

def _normalise_vpa(vpa: str) -> str:
    """
    Canonical form before hashing — mirrors the Rust gateway's normalise_vpa().

    A full phone-number VPA and its masked counterpart must hash identically
    so that consortium-cache lookups remain consistent regardless of which
    form a PSP submits.

    Rules:
      - 10+ digit handle  →  XX****XX@bank  (e.g. 9876543210@ybl → 98****10@ybl)
      - already-masked    →  unchanged       (e.g. 98****10@ybl  → 98****10@ybl)
      - name-based        →  unchanged       (e.g. ravi.kumar@axisbank)
    """
    if "@" not in vpa:
        return vpa
    handle, bank = vpa.split("@", 1)
    # Full phone number
    if handle.isdigit() and len(handle) >= 10:
        return f"{handle[:2]}****{handle[-2:]}@{bank}"
    # Already-masked phone (e.g. "98****10")
    if (
        len(handle) == 8
        and handle[:2].isdigit()
        and handle[2:6] == "****"
        and handle[6:].isdigit()
    ):
        return vpa
    return vpa


def _hash_vpa(vpa: str) -> str:
    canonical = _normalise_vpa(vpa)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]  # short for readability


def build_demo_graph() -> nx.DiGraph:
    """
    Build a synthetic transaction graph that contains all four typologies.
    In production: replace with real transaction data from the ML pipeline.

    Nodes = hashed VPA identifiers
    Edges = directed payments (src → dst, weight = amount INR)
    """
    G = nx.DiGraph()

    # ── Fan-out ring (mule distributes to many) ───────────────────────────────
    hub = _hash_vpa("hub_mule@ybl")
    for i in range(8):
        dst = _hash_vpa(f"recipient_{i}@okaxis")
        G.add_edge(hub, dst, weight=np.random.uniform(9_000, 49_000), typology_hint="FAN_OUT")

    # ── Fan-in ring (aggregator collects from many) ───────────────────────────
    collector = _hash_vpa("collector@oksbi")
    for i in range(6):
        src = _hash_vpa(f"victim_{i}@okaxis")
        G.add_edge(src, collector, weight=np.random.uniform(5_000, 20_000), typology_hint="FAN_IN")

    # ── Simple cycle A → B → C → A (layering) ────────────────────────────────
    cycle_nodes = [_hash_vpa(f"layer_{i}@paytm") for i in range(3)]
    for i, node in enumerate(cycle_nodes):
        G.add_edge(node, cycle_nodes[(i + 1) % len(cycle_nodes)],
                   weight=95_000, typology_hint="CYCLE")

    # ── Legitimate benign edges (to test false-positive rate) ─────────────────
    for i in range(20):
        src = _hash_vpa(f"legit_src_{i}@upi")
        dst = _hash_vpa(f"legit_dst_{i}@upi")
        G.add_edge(src, dst, weight=np.random.uniform(100, 5_000))

    log.info("Demo graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G


# ── Typology detectors ────────────────────────────────────────────────────────

def detect_fan_out(G: nx.DiGraph, threshold: int = 5) -> list[MuleCluster]:
    """Nodes with out-degree > threshold and low in-degree = rapid disbursement."""
    clusters = []
    for node in G.nodes():
        out_d = G.out_degree(node)
        in_d  = G.in_degree(node)
        if out_d >= threshold and out_d > in_d * 3:
            neighbours = list(G.successors(node))
            score      = min(0.95, 0.50 + (out_d - threshold) * 0.04)
            clusters.append(MuleCluster(
                nodes      = [node] + neighbours,
                typology   = "FAN_OUT",
                risk_score = score,
                edge_count = out_d,
            ))
    return clusters


def detect_fan_in(G: nx.DiGraph, threshold: int = 4) -> list[MuleCluster]:
    """Nodes with in-degree > threshold and low out-degree = aggregation."""
    clusters = []
    for node in G.nodes():
        in_d  = G.in_degree(node)
        out_d = G.out_degree(node)
        if in_d >= threshold and in_d > out_d * 3:
            predecessors = list(G.predecessors(node))
            score        = min(0.90, 0.45 + (in_d - threshold) * 0.04)
            clusters.append(MuleCluster(
                nodes      = predecessors + [node],
                typology   = "FAN_IN",
                risk_score = score,
                edge_count = in_d,
            ))
    return clusters


def detect_cycles(G: nx.DiGraph) -> list[MuleCluster]:
    """Directed cycles of length 2–6 = circular flow / layering."""
    clusters = []
    try:
        for cycle in nx.simple_cycles(G):
            if 2 <= len(cycle) <= 6:
                clusters.append(MuleCluster(
                    nodes      = cycle,
                    typology   = "CYCLE",
                    risk_score = 0.90,
                    edge_count = len(cycle),
                ))
    except Exception as exc:  # nx may raise on very large graphs
        log.warning("Cycle detection error: %s", exc)
    return clusters


def run_detection(G: nx.DiGraph) -> list[MuleCluster]:
    """Run all typology detectors and return combined cluster list."""
    all_clusters = (
        detect_fan_out(G) +
        detect_fan_in(G) +
        detect_cycles(G)
    )
    log.info("Detected %d clusters across all typologies", len(all_clusters))
    return all_clusters


# ── Rust cache webhook push ───────────────────────────────────────────────────

def push_to_cache(clusters: list[MuleCluster], dry_run: bool = False) -> int:
    """
    POST each flagged node's risk score to the Rust gateway webhook.
    Returns the number of successful updates.
    """
    import hmac as hmac_lib
    import hashlib as hl

    pushed = 0
    for cluster in clusters:
        for node_hash in cluster.nodes:
            payload = {
                "vpa_hash"   : node_hash,
                "risk_score" : round(cluster.risk_score, 4),
                "reason"     : f"GRAPH:{cluster.typology}",
                "ttl_seconds": 3600,
            }

            if dry_run:
                log.info("[DRY RUN] would push: %s", payload)
                pushed += 1
                continue

            import json as _json
            body       = _json.dumps(payload).encode()
            sig        = hmac_lib.new(
                WEBHOOK_SECRET.encode(), body, hl.sha256
            ).hexdigest()

            try:
                resp = requests.post(
                    GATEWAY_WEBHOOK,
                    data=body,
                    headers={
                        "Content-Type"      : "application/json",
                        "x-varaksha-sig"    : sig,
                    },
                    timeout=2.0,
                )
                if resp.status_code == 200:
                    pushed += 1
                else:
                    log.warning("Cache push failed for %s: HTTP %d", node_hash, resp.status_code)
            except requests.exceptions.ConnectionError:
                log.warning("Gateway unreachable — running in offline mode")

    return pushed


# ── Main sweep loop ───────────────────────────────────────────────────────────

def sweep_once(dry_run: bool = False) -> GraphSweepResult:
    started  = time.perf_counter()
    G        = build_demo_graph()
    clusters = run_detection(G)
    flagged  = {n for c in clusters for n in c.nodes}
    pushed   = push_to_cache(clusters, dry_run=dry_run)
    elapsed  = time.perf_counter() - started

    log.info(
        "Sweep complete: %d clusters | %d nodes flagged | %d cache updates | %.2fs",
        len(clusters), len(flagged), pushed, elapsed,
    )
    return GraphSweepResult(
        clusters_found   = len(clusters),
        nodes_flagged    = len(flagged),
        sweep_duration_s = elapsed,
        clusters         = clusters,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Varaksha V2 — graph sweep agent")
    parser.add_argument("--iterations", type=int, default=1,  help="Number of sweep iterations")
    parser.add_argument("--interval",   type=int, default=60, help="Seconds between sweeps")
    parser.add_argument("--dry-run",    action="store_true",  help="Skip Rust webhook push")
    args = parser.parse_args()

    for i in range(args.iterations):
        log.info("Sweep %d / %d", i + 1, args.iterations)
        result = sweep_once(dry_run=args.dry_run)
        print(f"\n  Clusters : {result.clusters_found}")
        print(f"  Flagged  : {result.nodes_flagged} nodes")
        print(f"  Duration : {result.sweep_duration_s:.3f}s")
        for c in result.clusters:
            print(f"    [{c.typology}] {len(c.nodes)} nodes, score={c.risk_score:.2f}")
        if i < args.iterations - 1:
            time.sleep(args.interval)
