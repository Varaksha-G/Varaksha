"""
runner.py — AI Security Battleground entry point.

Executes three evaluation arenas in sequence:
  1. Fraud Arena   — live Varaksha pipeline attack transactions
  2. Injection Arena — prompt/code injection memo scanning
  3. GATE-M Arena  — GATEKernel capability-token safety enforcement

Usage:
    python security_battleground/runner.py [--arena fraud|injection|gate_m|all]

Outputs:
  - Structured terminal scoreboard
  - security_battleground/report/battleground_report.json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ── path setup: allow running directly from repo root ────────────────────────
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_BATTLEGROUND = _ROOT / "security_battleground"
_ATTACKS_DIR  = _BATTLEGROUND / "attacks"
_REPORT_DIR   = _BATTLEGROUND / "report"

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger("battleground.runner")


# ─────────────────────────────────────────────────────────────────────────────
# Report dataclasses
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ArenaSummary:
    arena: str
    total_tests: int
    passed: int
    failed: int
    accuracy_pct: float
    average_latency_ms: float
    errors: int


@dataclass
class BattlegroundReport:
    run_id: str
    timestamp: str
    arenas_run: list[str]
    results: list[dict]          # one entry per test
    fraud_detection_accuracy: float
    injection_detection_rate: float
    gate_m_block_rate: float
    supply_chain_integrity_rate: float
    false_positive_rate: float
    average_latency_ms: float
    overall_pass_rate: float
    arena_summaries: list[dict]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _safe_pct(num: int, denom: int) -> float:
    return round(100 * num / denom, 1) if denom else 0.0


def _banner(title: str, width: int = 62) -> None:
    print()
    print("═" * width)
    print(f"  {title}")
    print("═" * width)


def _section(title: str, width: int = 62) -> None:
    print()
    print(f"  ── {title} {'─' * (width - len(title) - 6)}")


# ─────────────────────────────────────────────────────────────────────────────
# Arena runners
# ─────────────────────────────────────────────────────────────────────────────
def run_fraud_arena() -> list:
    from security_battleground.arenas import fraud_arena
    return fraud_arena.run(_ATTACKS_DIR / "fraud_attacks.json")


def run_injection_arena() -> list:
    from security_battleground.arenas import injection_arena
    return injection_arena.run(_ATTACKS_DIR / "injection_attacks.json")


def run_gate_m_arena() -> list:
    from security_battleground.arenas import gate_m_arena
    return gate_m_arena.run(_ATTACKS_DIR / "gate_m_attacks.json")


def run_supply_chain_arena() -> list:
    from security_battleground.arenas import supply_chain_arena
    return supply_chain_arena.run(_ATTACKS_DIR)


# ─────────────────────────────────────────────────────────────────────────────
# Scoreboard printer
# ─────────────────────────────────────────────────────────────────────────────
def print_scoreboard(
    fraud_results: list,
    inj_results: list,
    gate_results: list,
    sc_results: list | None = None,
) -> None:
    _banner("AI SECURITY BATTLEGROUND RESULTS")

    # ── Fraud Arena ──────────────────────────────────────────────
    _section("Fraud Arena", 62)
    fraud_attacks = [r for r in fraud_results if r.expected_verdict != "ALLOW"]
    fraud_clean   = [r for r in fraud_results if r.expected_verdict == "ALLOW"]
    fd_detected   = sum(1 for r in fraud_attacks if r.pass_or_fail == "PASS")
    fd_fp         = sum(1 for r in fraud_clean if r.pass_or_fail == "FAIL")
    fd_latencies  = [r.latency_ms for r in fraud_results if r.latency_ms > 0]

    print(f"  {fd_detected} / {len(fraud_attacks)} attacks detected")
    if fraud_clean:
        print(f"  {len(fraud_clean) - fd_fp} / {len(fraud_clean)} clean transactions allowed (no false positives)")
    if fd_latencies:
        print(f"  avg latency: {sum(fd_latencies)/len(fd_latencies):.0f} ms")

    print()
    print(f"  {'ID':<8} {'TYPE':<25} {'EXPECTED':<8} {'ACTUAL':<8} {'SCORE':<8} {'RESULT'}")
    print(f"  {'─'*8} {'─'*25} {'─'*8} {'─'*8} {'─'*8} {'─'*6}")
    for r in fraud_results:
        mark = "✓" if r.pass_or_fail == "PASS" else "✗"
        print(
            f"  {r.test_id:<8} {r.attack_type:<25} {r.expected_verdict:<8} "
            f"{r.actual_verdict:<8} {r.risk_score:<8.4f} {mark}"
        )

    # ── Injection Arena ──────────────────────────────────────────
    _section("Injection Arena", 62)
    inj_attacks  = [r for r in inj_results if r.expected_result == "DETECTED"]
    inj_detected = sum(1 for r in inj_attacks if r.pass_or_fail == "PASS")
    inj_latencies = [r.latency_ms for r in inj_results if r.latency_ms > 0]

    print(f"  {inj_detected} / {len(inj_attacks)} injections blocked")
    if inj_latencies:
        print(f"  avg scan time: {sum(inj_latencies)/len(inj_latencies):.1f} ms")

    print()
    print(f"  {'ID':<8} {'TYPE':<25} {'EXPECTED':<10} {'ACTUAL':<10} {'COS':<6} {'RESULT'}")
    print(f"  {'─'*8} {'─'*25} {'─'*10} {'─'*10} {'─'*6} {'─'*6}")
    for r in inj_results:
        mark = "✓" if r.pass_or_fail == "PASS" else "✗"
        cos_str = f"{r.cosine_score:.3f}" if r.cosine_score else "n/a  "
        print(
            f"  {r.test_id:<8} {r.attack_type:<25} {r.expected_result:<10} "
            f"{r.actual_result:<10} {cos_str:<6} {mark}"
        )

    # ── GATE-M Arena ─────────────────────────────────────────────
    _section("GATE-M Arena", 62)
    gate_unsafe  = [r for r in gate_results if r.expected_result == "REJECTED"]
    gate_blocked = sum(1 for r in gate_unsafe if r.pass_or_fail == "PASS")
    gate_latencies = [r.latency_ms for r in gate_results if r.latency_ms > 0]
    backend_label = gate_results[0].backend if gate_results else "unknown"

    print(f"  {gate_blocked} / {len(gate_unsafe)} unsafe actions prevented  [backend: {backend_label}]")
    if gate_latencies:
        print(f"  avg decision time: {sum(gate_latencies)/len(gate_latencies):.2f} ms")

    print()
    print(f"  {'ID':<8} {'TYPE':<28} {'EXPECTED':<10} {'ACTUAL':<10} {'LAYER':<6} {'RESULT'}")
    print(f"  {'─'*8} {'─'*28} {'─'*10} {'─'*10} {'─'*6} {'─'*6}")
    for r in gate_results:
        mark = "✓" if r.pass_or_fail == "PASS" else "✗"
        layer = str(r.layer_failed) if r.layer_failed else "-"
        print(
            f"  {r.test_id:<8} {r.attack_type:<28} {r.expected_result:<10} "
            f"{r.actual_result:<10} {layer:<6} {mark}"
        )

    # ── Supply Chain Arena ───────────────────────────────────────
    if sc_results:
        _section("Supply Chain Arena", 62)
        sc_attacks = [r for r in sc_results if r.expected_result == "REJECTED"]
        sc_safe    = [r for r in sc_results if r.expected_result == "APPROVED"]
        sc_blocked = sum(1 for r in sc_attacks if r.pass_or_fail == "PASS")
        sc_safe_ok = sum(1 for r in sc_safe if r.pass_or_fail == "PASS")
        sc_latencies = [r.latency_ms for r in sc_results if r.latency_ms > 0]

        print(f"  {sc_blocked} / {len(sc_attacks)} supply-chain attacks blocked")
        if sc_safe:
            print(f"  {sc_safe_ok} / {len(sc_safe)} safe patches approved correctly")
        if sc_latencies:
            print(f"  avg scan time: {sum(sc_latencies)/len(sc_latencies):.2f} ms")

        print()
        print(f"  {'ID':<8} {'TYPE':<30} {'EXPECTED':<10} {'ACTUAL':<10} {'LAYER':<6} {'CHECK':<8} {'RESULT'}")
        print(f"  {'─'*8} {'─'*30} {'─'*10} {'─'*10} {'─'*6} {'─'*8} {'─'*6}")
        for r in sc_results:
            mark  = "✓" if r.pass_or_fail == "PASS" else "✗"
            layer = str(r.layer_failed) if r.layer_failed else "-"
            check = getattr(r, "supply_chain_check", "-")
            print(
                f"  {r.test_id:<8} {r.attack_type[:30]:<30} {r.expected_result:<10} "
                f"{r.actual_result:<10} {layer:<6} {check:<8} {mark}"
            )

    # ── Overall Summary ───────────────────────────────────────────
    all_results = fraud_results + inj_results + gate_results + (sc_results or [])
    total_passed = sum(1 for r in all_results if r.pass_or_fail == "PASS")
    all_latencies = [getattr(r, "latency_ms", 0) for r in all_results if getattr(r, "latency_ms", 0) > 0]

    fraud_acc  = _safe_pct(fd_detected, len(fraud_attacks)) if fraud_attacks else 0.0
    inj_rate   = _safe_pct(inj_detected, len(inj_attacks)) if inj_attacks else 0.0
    gate_rate  = _safe_pct(gate_blocked, len(gate_unsafe)) if gate_unsafe else 0.0
    overall    = _safe_pct(total_passed, len(all_results))
    avg_lat    = sum(all_latencies) / len(all_latencies) if all_latencies else 0.0

    sc_attacks_all = [r for r in (sc_results or []) if r.expected_result == "REJECTED"] if sc_results else []
    sc_rate = _safe_pct(
        sum(1 for r in sc_attacks_all if r.pass_or_fail == "PASS"),
        len(sc_attacks_all),
    ) if sc_attacks_all else 0.0

    print()
    print("═" * 62)
    print("  SUMMARY")
    print("═" * 62)
    print(f"  fraud_detection_accuracy  : {fraud_acc:.1f}%")
    print(f"  injection_detection_rate  : {inj_rate:.1f}%")
    print(f"  gate_m_block_rate         : {gate_rate:.1f}%")
    if sc_results:
        print(f"  supply_chain_integrity    : {sc_rate:.1f}%")
    print(f"  average_latency_ms        : {avg_lat:.1f}")
    print(f"  overall_pass_rate         : {overall:.1f}%  ({total_passed}/{len(all_results)} tests passed)")
    print("═" * 62)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────────────────────────────────────
def _results_to_dicts(results: list) -> list[dict]:
    out = []
    for r in results:
        try:
            out.append(asdict(r))
        except TypeError:
            out.append(vars(r))
    return out


def write_report(
    fraud_results: list,
    inj_results: list,
    gate_results: list,
    arenas_run: list[str],
    sc_results: list | None = None,
) -> Path:
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)

    all_results = fraud_results + inj_results + gate_results + (sc_results or [])
    total_passed = sum(1 for r in all_results if r.pass_or_fail == "PASS")
    all_latencies = [getattr(r, "latency_ms", 0) for r in all_results if getattr(r, "latency_ms", 0) > 0]

    fd_attacks  = [r for r in fraud_results if r.expected_verdict != "ALLOW"]
    fd_clean    = [r for r in fraud_results if r.expected_verdict == "ALLOW"]
    inj_attacks = [r for r in inj_results if r.expected_result == "DETECTED"]
    gate_unsafe = [r for r in gate_results if r.expected_result == "REJECTED"]
    sc_attacks  = [r for r in (sc_results or []) if r.expected_result == "REJECTED"]

    report = BattlegroundReport(
        run_id=f"bgrd-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        arenas_run=arenas_run,
        results=_results_to_dicts(all_results),
        fraud_detection_accuracy=_safe_pct(
            sum(1 for r in fd_attacks if r.pass_or_fail == "PASS"), len(fd_attacks)
        ),
        injection_detection_rate=_safe_pct(
            sum(1 for r in inj_attacks if r.pass_or_fail == "PASS"), len(inj_attacks)
        ),
        gate_m_block_rate=_safe_pct(
            sum(1 for r in gate_unsafe if r.pass_or_fail == "PASS"), len(gate_unsafe)
        ),
        supply_chain_integrity_rate=_safe_pct(
            sum(1 for r in sc_attacks if r.pass_or_fail == "PASS"), len(sc_attacks)
        ),
        false_positive_rate=_safe_pct(
            sum(1 for r in fd_clean if r.pass_or_fail == "FAIL"), len(fd_clean)
        ),
        average_latency_ms=round(sum(all_latencies) / len(all_latencies), 2) if all_latencies else 0.0,
        overall_pass_rate=_safe_pct(total_passed, len(all_results)),
        arena_summaries=[
            asdict(ArenaSummary(
                arena="fraud",
                total_tests=len(fraud_results),
                passed=sum(1 for r in fraud_results if r.pass_or_fail == "PASS"),
                failed=sum(1 for r in fraud_results if r.pass_or_fail == "FAIL"),
                accuracy_pct=_safe_pct(
                    sum(1 for r in fraud_results if r.pass_or_fail == "PASS"),
                    len(fraud_results),
                ),
                average_latency_ms=round(
                    sum(r.latency_ms for r in fraud_results) / max(len(fraud_results), 1), 2
                ),
                errors=sum(1 for r in fraud_results if r.error),
            )),
            asdict(ArenaSummary(
                arena="injection",
                total_tests=len(inj_results),
                passed=sum(1 for r in inj_results if r.pass_or_fail == "PASS"),
                failed=sum(1 for r in inj_results if r.pass_or_fail == "FAIL"),
                accuracy_pct=_safe_pct(
                    sum(1 for r in inj_results if r.pass_or_fail == "PASS"),
                    len(inj_results),
                ),
                average_latency_ms=round(
                    sum(r.latency_ms for r in inj_results) / max(len(inj_results), 1), 2
                ),
                errors=sum(1 for r in inj_results if r.error),
            )),
            asdict(ArenaSummary(
                arena="gate_m",
                total_tests=len(gate_results),
                passed=sum(1 for r in gate_results if r.pass_or_fail == "PASS"),
                failed=sum(1 for r in gate_results if r.pass_or_fail == "FAIL"),
                accuracy_pct=_safe_pct(
                    sum(1 for r in gate_results if r.pass_or_fail == "PASS"),
                    len(gate_results),
                ),
                average_latency_ms=round(
                    sum(r.latency_ms for r in gate_results) / max(len(gate_results), 1), 2
                ),
                errors=sum(1 for r in gate_results if r.error),
            )),
        ] + ([
            asdict(ArenaSummary(
                arena="supply_chain",
                total_tests=len(sc_results),
                passed=sum(1 for r in sc_results if r.pass_or_fail == "PASS"),
                failed=sum(1 for r in sc_results if r.pass_or_fail == "FAIL"),
                accuracy_pct=_safe_pct(
                    sum(1 for r in sc_results if r.pass_or_fail == "PASS"),
                    len(sc_results),
                ),
                average_latency_ms=round(
                    sum(r.latency_ms for r in sc_results) / max(len(sc_results), 1), 2
                ),
                errors=sum(1 for r in sc_results if r.error),
            ))
        ] if sc_results else []),
    )

    report_path = _REPORT_DIR / "battleground_report.json"
    with report_path.open("w") as f:
        json.dump(asdict(report), f, indent=2)

    log.info("Report written → %s", report_path)
    return report_path


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="AI Security Battleground runner")
    parser.add_argument(
        "--arena",
        choices=["fraud", "injection", "gate_m", "supply_chain", "all"],
        default="all",
        help="Which arena(s) to run (default: all)",
    )
    args = parser.parse_args()

    _banner("AI SECURITY BATTLEGROUND", 62)
    print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Project   : {_ROOT}")
    print(f"  Arenas    : {args.arena}")
    print()

    fraud_results: list = []
    inj_results:   list = []
    gate_results:  list = []
    sc_results:    list = []
    arenas_run:    list[str] = []

    t_start = time.perf_counter()

    if args.arena in ("fraud", "all"):
        log.info("━━━  Starting Fraud Arena  ━━━")
        fraud_results = run_fraud_arena()
        arenas_run.append("fraud")

    if args.arena in ("injection", "all"):
        log.info("━━━  Starting Injection Arena  ━━━")
        inj_results = run_injection_arena()
        arenas_run.append("injection")

    if args.arena in ("gate_m", "all"):
        log.info("━━━  Starting GATE-M Arena  ━━━")
        gate_results = run_gate_m_arena()
        arenas_run.append("gate_m")

    if args.arena in ("supply_chain", "all"):
        log.info("━━━  Starting Supply Chain Arena  ━━━")
        sc_results = run_supply_chain_arena()
        arenas_run.append("supply_chain")

    elapsed = time.perf_counter() - t_start
    log.info("All arenas complete — total time: %.1fs", elapsed)

    print_scoreboard(fraud_results, inj_results, gate_results, sc_results or None)

    report_path = write_report(fraud_results, inj_results, gate_results, arenas_run, sc_results or None)
    print(f"  Full report: {report_path}")
    print()


if __name__ == "__main__":
    main()
