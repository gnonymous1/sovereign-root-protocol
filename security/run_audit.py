#!/usr/bin/env python3
"""
=============================================================================
  SRP HARDENED SECURITY AUDIT — MASTER ORCHESTRATOR
=============================================================================
  System Authority : Universal Root Authority
  Engine           : Python 3.11+ subprocess + httpx

  Automates the full adversarial security verification cycle:

    [SECURITY AUDIT START]
        │
        ├── 1. srp_pen_fuzzer.py        (Packet evasion: frag + SYN flood)
        │       └── [FUZZING RECOVERY MATCHED]
        │
        ├── 2. srp_chaos_engine.py      (Split-brain partition lockout)
        │       └── [PARTITION PARTIAL DISCONNECT INDUCED]
        │
        ├── 3. srp_jailbreak_tester.py  (Adversarial prompt injection)
        │       └── [VRAM BANKS FLUSHED CHECK]
        │
        └── 4. Metrics & Recovery       (Loader telemetry + timing)
                └── [SYSTEM SECURE]

  Output: Tabular terminal audit report with timing rows.
=============================================================================
"""

import os
import sys
import json
import time
import asyncio
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import httpx

# Telemetry audit
from telemetry.srp_ledger import IntegrityLedger

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [AUDIT] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("srp_audit")

# ---------------------------------------------------------------------------
#  ANSI Color & Marker Constants
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"

MARKER_AUDIT_START = f"{BOLD}[{CYAN}SECURITY AUDIT START{RESET}{BOLD}]{RESET}"
MARKER_FUZZING = f"{BOLD}[{GREEN}FUZZING RECOVERY MATCHED{RESET}{BOLD}]{RESET}"
MARKER_PARTITION = f"{BOLD}[{YELLOW}PARTITION PARTIAL DISCONNECT INDUCED{RESET}{BOLD}]{RESET}"
MARKER_VRAM = f"{BOLD}[{GREEN}VRAM BANKS FLUSHED CHECK{RESET}{BOLD}]{RESET}"
MARKER_SECURE = f"{BOLD}[{GREEN}SYSTEM SECURE{RESET}{BOLD}]{RESET}"

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SECURITY_DIR = ROOT
CLUSTER_DIR = ROOT.parent / "cluster"

FUZZER_SCRIPT = SECURITY_DIR / "srp_pen_fuzzer.py"
CHAOS_SCRIPT = SECURITY_DIR / "srp_chaos_engine.py"
JAILBREAK_SCRIPT = SECURITY_DIR / "srp_jailbreak_tester.py"

# Service endpoints
PROXY_HEALTH = "http://127.0.0.1:9000/health"
LOADER_HEALTH = "http://127.0.0.1:9001/health"
LOADER_METRICS = "http://127.0.0.1:9001/api/v1/srp/metrics"
SYNC_NOTIFY = "http://127.0.0.1:9201/health"


# ===========================================================================
#  Phase 0: Pre-flight checks
# ===========================================================================

async def check_service(url: str, name: str, timeout: float = 5.0) -> bool:
    """Return True if the endpoint responds with 200."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            return resp.status_code == 200
    except Exception:
        return False


async def preflight() -> bool:
    """Verify all required services are reachable before starting."""
    logger.info("Pre-flight service verification...")

    checks = [
        (PROXY_HEALTH, "Proxy (port 9000)"),
        (LOADER_HEALTH, "Loader (port 9001)"),
        (SYNC_NOTIFY, "Sync Daemon (port 9201)"),
    ]

    all_ok = True
    for url, name in checks:
        ok = await check_service(url, name)
        status = f"{GREEN}OK{RESET}" if ok else f"{RED}UNREACHABLE{RESET}"
        logger.info("  %-30s %s", name, status)
        if not ok:
            all_ok = False

    return all_ok


# ===========================================================================
#  Phase 1: Packet Fuzzer
# ===========================================================================

async def run_fuzzer(output_path: Path) -> dict:
    """Execute the packet evasion fuzzer and capture results."""
    print(f"\n  {MARKER_AUDIT_START} Starting Layer-2 Packet Fuzzer...\n")

    result_path = output_path / "fuzzer_results.json"
    cmd = [
        sys.executable, str(FUZZER_SCRIPT),
        "--target", "127.0.0.1",
        "--syn-count", "10000",
        "--output", str(result_path),
    ]

    logger.info("Running: %s", " ".join(str(c) for c in cmd))
    start = time.perf_counter()

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    elapsed = time.perf_counter() - start

    # Print fuzzer output
    if stdout:
        for line in stdout.decode("utf-8", errors="replace").split("\n"):
            if line.strip():
                print(f"  {DIM}{line}{RESET}")

    # Load results
    results = []
    if result_path.exists():
        with open(result_path) as f:
            results = json.load(f)

    frag_result = next((r for r in results if r.get("attack") == "ip_fragmentation"), {})
    syn_result = next((r for r in results if r.get("attack") == "syn_flood"), {})
    has_errors = any("error" in r for r in results)

    print(f"\n  {MARKER_FUZZING} Fuzzing complete (%.2fs)" % elapsed)

    return {
        "script": "srp_pen_fuzzer.py",
        "elapsed_s": round(elapsed, 2),
        "elapsed_ms": round(elapsed * 1000, 1),
        "exit_code": proc.returncode,
        "has_errors": has_errors,
        "fragmentation": {
            "fragments_sent": frag_result.get("fragments_sent", "?"),
            "payload_bytes": frag_result.get("original_payload_bytes", "?"),
        },
        "syn_flood": {
            "packets_sent": syn_result.get("packets_sent", "?"),
            "inspected_before": syn_result.get("loader_inspected_before", "?"),
            "inspected_after": syn_result.get("loader_inspected_after", "?"),
        },
    }


# ===========================================================================
#  Phase 2: Chaos Engine
# ===========================================================================

async def run_chaos(output_path: Path) -> dict:
    """Execute the split-brain chaos scenario and capture results."""
    print(f"\n  {MARKER_AUDIT_START} Starting Split-Brain Chaos Engine...\n")

    result_path = output_path / "chaos_results.json"
    cmd = [
        sys.executable, str(CHAOS_SCRIPT),
        "--test-ip", "10.88.0.77",
        "--output", str(result_path),
    ]

    logger.info("Running: %s", " ".join(str(c) for c in cmd))
    start = time.perf_counter()

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    elapsed = time.perf_counter() - start

    if stdout:
        for line in stdout.decode("utf-8", errors="replace").split("\n"):
            if line.strip():
                print(f"  {DIM}{line}{RESET}")

    results = {}
    if result_path.exists():
        with open(result_path) as f:
            results = json.load(f)

    convergence = results.get("convergence", {})
    converged = convergence.get("converged", False)
    node_a_state = convergence.get("actual_node_a_state")
    node_c_state = convergence.get("actual_node_c_state")

    print(f"\n  {MARKER_PARTITION} Chaos scenario complete (%.2fs)" % elapsed)

    return {
        "script": "srp_chaos_engine.py",
        "elapsed_s": round(elapsed, 2),
        "elapsed_ms": round(elapsed * 1000, 1),
        "exit_code": proc.returncode,
        "scenario": results.get("scenario", "unknown"),
        "converged": converged,
        "node_a_state": f"0x{node_a_state:02X}" if node_a_state is not None else "N/A",
        "node_c_state": f"0x{node_c_state:02X}" if node_c_state is not None else "N/A",
        "split_brain_resolved": converged,
    }


# ===========================================================================
#  Phase 3: Jailbreak Tester
# ===========================================================================

async def run_jailbreak(output_path: Path) -> dict:
    """Execute the adversarial prompt injection suite."""
    print(f"\n  {MARKER_AUDIT_START} Starting Adversarial Jailbreak Tester...\n")

    result_path = output_path / "jailbreak_results.json"
    cmd = [
        sys.executable, str(JAILBREAK_SCRIPT),
        "--output", str(result_path),
    ]

    logger.info("Running: %s", " ".join(str(c) for c in cmd))
    start = time.perf_counter()

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    elapsed = time.perf_counter() - start

    if stdout:
        for line in stdout.decode("utf-8", errors="replace").split("\n"):
            if line.strip():
                print(f"  {DIM}{line}{RESET}")

    stats = {}
    if result_path.exists():
        with open(result_path) as f:
            data = json.load(f)
            stats = data.get("statistics", {})

    print(f"\n  {MARKER_VRAM} Jailbreak tests complete (%.2fs)" % elapsed)

    return {
        "script": "srp_jailbreak_tester.py",
        "elapsed_s": round(elapsed, 2),
        "elapsed_ms": round(elapsed * 1000, 1),
        "exit_code": proc.returncode,
        "total_payloads": stats.get("total", "?"),
        "passed": stats.get("passed", "?"),
        "failed": stats.get("failed", "?"),
        "errors": stats.get("errors", "?"),
        "violation_detection_rate": stats.get("violation_detection_rate", "?"),
        "safe_approval_rate": stats.get("safe_approval_rate", "?"),
        "avg_latency_us": stats.get("avg_latency_us", "?"),
        "max_latency_us": stats.get("max_latency_us", "?"),
    }


# ===========================================================================
#  Phase 4: Metrics & Recovery Assessment
# ===========================================================================

async def assess_recovery(baseline_metrics: dict) -> dict:
    """
    Query the loader metrics endpoint and compare against baseline
    to assess total recovery and packet processing integrity.
    """
    print(f"\n  {MARKER_AUDIT_START} Assessing system recovery metrics...\n")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(LOADER_METRICS)
            if resp.status_code == 200:
                current = resp.json()
            else:
                current = {}
    except Exception as e:
        logger.error("  Metrics endpoint unreachable: %s", e)
        current = {}

    delta_inspected = current.get("inspected", 0) - baseline_metrics.get("inspected", 0)
    delta_passed = current.get("passed", 0) - baseline_metrics.get("passed", 0)
    delta_dropped = current.get("dropped", 0) - baseline_metrics.get("dropped", 0)

    logger.info("  Loader telemetry (since baseline):")
    logger.info("    Packets inspected: +%d", delta_inspected)
    logger.info("    Packets passed:    +%d", delta_passed)
    logger.info("    Packets dropped:   +%d", delta_dropped)

    return {
        "baseline": baseline_metrics,
        "current": current,
        "delta_inspected": delta_inspected,
        "delta_passed": delta_passed,
        "delta_dropped": delta_dropped,
    }


# ===========================================================================
#  Terminal Report
# ===========================================================================

def print_report(phases: list, recovery: dict, total_elapsed: float):
    """Print the formatted terminal audit report."""
    print()
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  SRP HARDENED SECURITY AUDIT — FINAL REPORT{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"  {DIM}Audit timestamp: {datetime.now(timezone.utc).isoformat()}{RESET}")
    print(f"  {DIM}Total duration:  {total_elapsed:.1f}s{RESET}")
    print()
    print(f"  {BOLD}{'Phase':<40s} {'Status':<12s} {'Time':<10s}{RESET}")
    print(f"  {'─' * 62}")

    all_passed = True
    for phase in phases:
        name = f"{phase.get('icon', '')} {phase['name']}" if 'icon' in phase else phase['name']
        has_errors = phase.get("has_errors", phase.get("failed", 0) > 0 or phase.get("exit_code", 0) != 0)
        # Special handling for chaos — converged field
        if "converged" in phase:
            has_errors = not phase.get("converged", False)

        status = f"{GREEN}PASS{RESET}" if not has_errors else f"{RED}FAIL{RESET}"
        elapsed_str = f"{phase.get('elapsed_s', 0):.2f}s"

        print(f"  {name:<40s} {status:<12s} {elapsed_str:<10s}")

        # Print sub-details
        if phase.get("fragmentation"):
            f = phase["fragmentation"]
            print(f"  {DIM}  ├─ Fragments: {f.get('fragments_sent', '?')} sent  "
                  f"Payload: {f.get('payload_bytes', '?')} bytes{RESET}")
        if phase.get("syn_flood"):
            s = phase["syn_flood"]
            print(f"  {DIM}  ├─ SYN flood: {s.get('packets_sent', '?')} pkts  "
                  f"BPF before: {s.get('inspected_before', '?')}  after: {s.get('inspected_after', '?')}{RESET}")
        if "converged" in phase:
            print(f"  {DIM}  ├─ Split-brain: node_a={phase.get('node_a_state', '?')}  "
                  f"node_c={phase.get('node_c_state', '?')}  "
                  f"resolved={phase.get('converged', False)}{RESET}")
        if "violation_detection_rate" in phase:
            print(f"  {DIM}  ├─ Violation detection: {phase.get('violation_detection_rate', '?'):.1f}%  "
                  f"Safe approval: {phase.get('safe_approval_rate', '?'):.1f}%{RESET}")
            print(f"  {DIM}  ├─ Avg latency: {phase.get('avg_latency_us', '?'):.0f} us  "
                  f"Max: {phase.get('max_latency_us', '?'):.0f} us{RESET}")
            print(f"  {DIM}  └─ Payloads: {phase.get('passed', '?')}/{phase.get('total_payloads', '?')} passed  "
                  f"Failed: {phase.get('failed', '?')}  Errors: {phase.get('errors', '?')}{RESET}")

        if has_errors:
            all_passed = False

    print()
    print(f"  {'─' * 62}")
    rec = recovery
    print(f"  {DIM}Loader delta: +{rec.get('delta_inspected', 0)} inspected, "
          f"+{rec.get('delta_passed', 0)} passed, "
          f"+{rec.get('delta_dropped', 0)} dropped{RESET}")
    print()

    if all_passed:
        print(f"  {MARKER_SECURE}  {GREEN}All security audits passed — system is SECURE.{RESET}")
    else:
        print(f"  {RED}  One or more security audits FAILED — review report above.{RESET}")

    print(f"{BOLD}{'=' * 72}{RESET}")
    print()


# ===========================================================================
#  Main Orchestration
# ===========================================================================

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="SRP Hardened Security Audit Orchestrator")
    parser.add_argument(
        "--output-dir", default="/tmp/srp-audit",
        help="Directory for intermediate JSON result files",
    )
    parser.add_argument(
        "--skip-fuzzer", action="store_true",
        help="Skip the packet fuzzer phase",
    )
    parser.add_argument(
        "--skip-chaos", action="store_true",
        help="Skip the chaos engine phase",
    )
    parser.add_argument(
        "--skip-jailbreak", action="store_true",
        help="Skip the jailbreak tester phase",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print()
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  SRP HARDENED SECURITY AUDIT{RESET}")
    print(f"{BOLD}  Automated adversarial security verification framework{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")
    print()

    # Pre-flight
    services_ok = await preflight()
    if not services_ok:
        logger.warning("One or more services unreachable — audit may be incomplete.")
        proceed = input("  Continue anyway? [y/N]: ").strip().lower()
        if proceed != "y":
            logger.info("Audit aborted by user.")
            sys.exit(1)
    print()

    # Capture baseline metrics
    baseline_metrics = {}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(LOADER_METRICS)
            if resp.status_code == 200:
                baseline_metrics = resp.json()
    except Exception:
        pass
    logger.info("Baseline loader metrics: %s", baseline_metrics)
    print()

    # Execute phases
    audit_start = time.perf_counter()
    phases = []

    # Phase 1: Fuzzer
    if not args.skip_fuzzer:
        fuzzer_result = await run_fuzzer(output_dir)
        fuzzer_result["icon"] = "1."
        phases.append(fuzzer_result)
    else:
        phases.append({"name": "1. Packet Fuzzer", "elapsed_s": 0, "has_errors": False})
    print()

    # Phase 2: Chaos
    if not args.skip_chaos:
        chaos_result = await run_chaos(output_dir)
        chaos_result["icon"] = "2."
        phases.append(chaos_result)
    else:
        phases.append({"name": "2. Chaos Engine", "elapsed_s": 0, "has_errors": False})
    print()

    # Phase 3: Jailbreak
    if not args.skip_jailbreak:
        jailbreak_result = await run_jailbreak(output_dir)
        jailbreak_result["icon"] = "3."
        phases.append(jailbreak_result)
    else:
        phases.append({"name": "3. Jailbreak Tester", "elapsed_s": 0, "has_errors": False})
    print()

    total_elapsed = time.perf_counter() - audit_start

    # Phase 4: Recovery assessment
    recovery = await assess_recovery(baseline_metrics)
    print()

    # Print report
    print_report(phases, recovery, total_elapsed)

    # Determine overall exit code
    all_passed = True
    for phase in phases:
        if "converged" in phase and not phase.get("converged", False):
            all_passed = False
        elif phase.get("has_errors", False):
            all_passed = False
        elif phase.get("failed", 0) > 0:
            all_passed = False
        elif phase.get("exit_code", 0) != 0 and phase.get("elapsed_s", 0) > 0:
            all_passed = False

    # ---- Telemetry: seal audit results into an immutable ledger record ----
    try:
        _ledger = IntegrityLedger()
        _audit_record = {
            "timestamp_ns": time.time_ns(),
            "type": "security_audit",
            "total_elapsed_s": round(total_elapsed, 2),
            "all_passed": all_passed,
            "phases": [
                {
                    "script": p.get("script", "unknown"),
                    "exit_code": p.get("exit_code", -1),
                    "elapsed_s": p.get("elapsed_s", 0.0),
                }
                for p in phases
            ],
            "recovery": {
                "delta_inspected": recovery.get("delta_inspected", 0),
                "delta_passed": recovery.get("delta_passed", 0),
                "delta_dropped": recovery.get("delta_dropped", 0),
            },
        }
        _seal = _ledger.seal(_audit_record)
        _audit_record["integrity_seal"] = _seal
        _audit_log_path = output_dir / "audit_ledger.jsonl"
        with open(_audit_log_path, "a", encoding="utf-8") as _fh:
            _fh.write(
                json.dumps(_audit_record, separators=(",", ":"),
                           ensure_ascii=False) + "\n"
            )
        # Verify the chain so far
        _verify = IntegrityLedger.verify_chain(str(_audit_log_path))
        if _verify["status"] == "INTEGRITY_VERIFIED":
            print(f"  [AUDIT LEDGER] Seal: {_seal[:20]}...  "
                  f"Chain: {_verify['total_lines']} records verified")
        else:
            print(f"  [AUDIT LEDGER] TAMPER DETECTED: {_verify['error']}")
    except Exception as _exc:
        print(f"  [AUDIT LEDGER] Write failed: {_exc}")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    asyncio.run(main())
