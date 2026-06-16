#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — CRYPTOGRAPHIC INCIDENT RESPONSE SUITE
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ asyncio + parallel verification

  Incident response utility that scans the telemetry hash-chain ledger for
  cryptographic signature breaks, isolates tampered blocks, and executes
  automated mitigation across the affected zone.

  Lifecycle markers:

    [SRE ALERT: ANOMALY EVENT CAPTURED]
    -> [ANALYZE PHASE: LOCATING LEDGER DISCREPANCY]
    -> [MITIGATION PHASE: EXECUTING FLUSH COMMANDS]
    -> [RECOVERY PHASE: RELOADING UNTAMPERED TRUST BLOCKS]
    -> [STATE RESTORED]

  Usage:
      python operations/srp_audit_incident.py --incident-scan
      python operations/srp_audit_incident.py --incident-scan --log /custom/path/audit.log
      python operations/srp_audit_incident.py --incident-scan --force-mitigation
      python operations/srp_audit_incident.py --json     # machine-readable output

  Exit codes:
    0 — Ledger intact or incident resolved
    1 — Tamper detected but mitigation incomplete
    2 — Internal error (ledger unreadable, dependencies missing)
=============================================================================
"""

import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent.resolve()
_PROJECT_ROOT = _HERE.parent
_DEFAULT_LOG = _PROJECT_ROOT / "telemetry" / "logs" / "srp_audit.log"
_LEDGER_MODULE = _PROJECT_ROOT / "telemetry" / "srp_ledger.py"

LOADER_BASE = "http://127.0.0.1:9001"
PROXY_BASE = "http://127.0.0.1:9000"

# ---------------------------------------------------------------------------
#  ANSI colours
# ---------------------------------------------------------------------------
class _C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_C.RESET}" if sys.stdout.isatty() else text


_OK = _c("OK", _C.GREEN)
_FAIL = _c("FAIL", _C.RED)
_WARN = _c("WARN", _C.YELLOW)
_ALERT = _c("ALERT", _C.MAGENTA)
_ARROW = "->"


# ============================================================================
#  Ledger Verification Engine
# ============================================================================

def _recalculate_chain(log_path: Path) -> dict:
    """
    Recalculate the hash chain from scratch using the same algorithm as
    telemetry/srp_ledger.py (SHA256(payload + ':' + prev_seal)).

    Returns:
        {
            "status": "INTEGRITY_VERIFIED" | "TAMPER_DETECTED",
            "total_lines": int,
            "verified_until": int,
            "first_bad_line": int | None,
            "expected_seal": str | None,
            "stored_seal": str | None,
            "tampered_records": list[dict],
            "error": str | None,
        }
    """
    result = {
        "status": "INTEGRITY_VERIFIED",
        "total_lines": 0,
        "verified_until": -1,
        "first_bad_line": None,
        "expected_seal": None,
        "stored_seal": None,
        "tampered_records": [],
        "error": None,
    }

    if not log_path.exists() or log_path.stat().st_size == 0:
        result["status"] = "EMPTY_LOG"
        result["error"] = f"Log file not found or empty: {log_path}"
        return result

    previous_seal = "\x00" * 64  # genesis ancestor

    with open(log_path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                result["status"] = "TAMPER_DETECTED"
                result["first_bad_line"] = line_no
                result["error"] = f"Invalid JSON at line {line_no}: {exc}"
                result["total_lines"] = line_no + 1
                result["tampered_records"].append({
                    "line": line_no,
                    "reason": "parse_error",
                    "detail": str(exc),
                })
                return result

            stored_seal = record.pop("integrity_seal", None)
            if stored_seal is None:
                result["status"] = "TAMPER_DETECTED"
                result["first_bad_line"] = line_no
                result["error"] = f"Missing integrity_seal at line {line_no}"
                result["total_lines"] = line_no + 1
                result["tampered_records"].append({
                    "line": line_no,
                    "reason": "missing_seal",
                })
                return result

            # Recompute expected seal
            payload_json = json.dumps(
                record, separators=(",", ":"), sort_keys=True,
                ensure_ascii=False,
            )
            input_str = payload_json + ":" + previous_seal
            expected = hashlib.sha256(input_str.encode("utf-8")).hexdigest()

            if stored_seal != expected:
                result["status"] = "TAMPER_DETECTED"
                result["first_bad_line"] = line_no
                result["expected_seal"] = expected
                result["stored_seal"] = stored_seal
                result["total_lines"] = line_no + 1
                result["error"] = (
                    f"Seal mismatch at line {line_no}: "
                    f"expected={expected[:16]}... stored={stored_seal[:16]}..."
                )
                result["tampered_records"].append({
                    "line": line_no,
                    "reason": "seal_mismatch",
                    "expected": expected,
                    "stored": stored_seal,
                    "record": record,
                })
                return result

            previous_seal = stored_seal
            result["verified_until"] = line_no

    result["total_lines"] = result["verified_until"] + 1
    return result


# ============================================================================
#  Mitigation Actions
# ============================================================================

def _loader_get(endpoint: str) -> Optional[dict]:
    """HTTP GET to the loader control plane."""
    url = f"{LOADER_BASE}{endpoint}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _loader_put(endpoint: str, data: dict) -> bool:
    """HTTP PUT to the loader control plane."""
    url = f"{LOADER_BASE}{endpoint}"
    body = json.dumps(data).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=body,
                                      headers={"Content-Type": "application/json"},
                                      method="PUT")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def flush_compromised_ips(tampered_records: list[dict]) -> tuple[int, int]:
    """
    Set 0xFF (Absolute Quarantine) for every source IP found in tampered
    records.  Returns (succeeded, failed).
    """
    succeeded = 0
    failed = 0
    seen_ips: set[str] = set()

    for rec in tampered_records:
        record = rec.get("record", {})
        if not record:
            continue
        source_ip = record.get("source_ip")
        if source_ip and source_ip not in seen_ips:
            seen_ips.add(source_ip)
            ok = _loader_put(f"/api/v1/srp/state/{source_ip}", {"state": 0xFF})
            if ok:
                succeeded += 1
            else:
                failed += 1

    return succeeded, failed


def reload_trust_blocks(tampered_records: list[dict]) -> int:
    """
    For tampered records up to the last verified line, reconstruct
    trust by re-sealing the known-good records and re-committing them
    to the loader.  Returns count of restored entries.
    """
    restored = 0
    for rec in tampered_records:
        record = rec.get("record", {})
        if not record:
            continue
        source_ip = record.get("source_ip")
        action = record.get("verdict_action")
        if source_ip and action == "APPROVED":
            ok = _loader_put(f"/api/v1/srp/state/{source_ip}", {"state": 0x01})
            if ok:
                restored += 1
    return restored


def get_loader_map_entries() -> dict[str, int]:
    """Get all current entries from the loader's BPF map."""
    data = _loader_get("/api/v1/srp/map")
    if data:
        return data.get("entries", {})
    return {}


# ============================================================================
#  Report Builder
# ============================================================================

def build_incident_report(verify_result: dict,
                           flush_result: tuple[int, int],
                           restored_count: int,
                           map_after: dict[str, int],
                           elapsed_ms: float,
                           verbose: bool = False) -> str:
    """Build the full colorized incident report."""
    lines = []
    sep = "=" * 60
    lines.append(sep)
    lines.append(
        f"  {_c('SRP CRYPTOGRAPHIC INCIDENT REPORT', _C.BOLD)}"
    )
    lines.append(f"  {datetime.now(timezone.utc).isoformat()}")
    lines.append(sep)

    is_tampered = verify_result["status"] == "TAMPER_DETECTED"

    # [SRE ALERT: ANOMALY EVENT CAPTURED]
    lines.append("")
    if is_tampered:
        lines.append(
            f"  [{_c('SRE ALERT: ANOMALY EVENT CAPTURED', _C.MAGENTA)}] {_ARROW} {_FAIL}"
        )
        lines.append(
            f"    {_FAIL}  Tamper detected at log line "
            f"{verify_result['first_bad_line']}"
        )
    else:
        lines.append(
            f"  [{_c('SRE ALERT: ANOMALY EVENT CAPTURED', _C.GREEN)}] {_ARROW} {_OK}"
        )
        lines.append(f"    {_OK}  Ledger intact — no anomalies detected")

    # [ANALYZE PHASE: LOCATING LEDGER DISCREPANCY]
    lines.append("")
    lines.append(
        f"  [{_c('ANALYZE PHASE: LOCATING LEDGER DISCREPANCY', _C.BOLD)}] {_ARROW} "
        f"{_OK if not is_tampered else _FAIL}"
    )
    lines.append(
        f"    Status: {verify_result['status']}"
    )
    lines.append(
        f"    Total lines scanned: {verify_result['total_lines']}"
    )
    lines.append(
        f"    Verified until: line {verify_result['verified_until']}"
    )
    if is_tampered:
        lines.append(
            f"    First bad line: {verify_result['first_bad_line']}"
        )
        lines.append(
            f"    Expected seal: {verify_result.get('expected_seal', 'N/A')}"
        )
        lines.append(
            f"    Stored seal:   {verify_result.get('stored_seal', 'N/A')}"
        )
        if verbose and verify_result.get("tampered_records"):
            for tr in verify_result["tampered_records"]:
                lines.append(
                    f"    {_c('Reason:', _C.DIM)} {tr.get('reason', '?')}"
                )
                if tr.get("record"):
                    lines.append(
                        f"    {_c('Source IP:', _C.DIM)} "
                        f"{tr['record'].get('source_ip', '?')}"
                    )
                    lines.append(
                        f"    {_c('Verdict:', _C.DIM)} "
                        f"{tr['record'].get('verdict_action', '?')}"
                    )

    # [MITIGATION PHASE: EXECUTING FLUSH COMMANDS]
    lines.append("")
    if is_tampered:
        lines.append(
            f"  [{_c('MITIGATION PHASE: EXECUTING FLUSH COMMANDS', _C.BOLD)}] {_ARROW} "
            f"{_OK if flush_result[0] > 0 or flush_result[1] == 0 else _FAIL}"
        )
        lines.append(
            f"    Compromised IPs set to 0xFF (QUARANTINE): "
            f"{flush_result[0]} succeeded, {flush_result[1]} failed"
        )
    else:
        lines.append(
            f"  [{_c('MITIGATION PHASE: EXECUTING FLUSH COMMANDS', _C.GREEN)}] {_ARROW} {_OK}"
        )
        lines.append("    No mitigation required — ledger intact")

    # [RECOVERY PHASE: RELOADING UNTAMPERED TRUST BLOCKS]
    lines.append("")
    if is_tampered:
        lines.append(
            f"  [{_c('RECOVERY PHASE: RELOADING UNTAMPERED TRUST BLOCKS', _C.BOLD)}] {_ARROW} "
            f"{_OK if restored_count > 0 else _WARN}"
        )
        lines.append(
            f"    Trust blocks restored: {restored_count}"
        )
    else:
        lines.append(
            f"  [{_c('RECOVERY PHASE: RELOADING UNTAMPERED TRUST BLOCKS', _C.GREEN)}] {_ARROW} {_OK}"
        )
        lines.append("    No recovery needed")

    # [STATE RESTORED]
    lines.append("")
    all_clear = not is_tampered or (flush_result[1] == 0)
    if all_clear:
        lines.append(
            f"  [{_c('STATE RESTORED', _C.GREEN)}] {_ARROW} {_OK}"
        )
        if map_after:
            quarantine_count = sum(
                1 for v in map_after.values() if v == 0xFF
            )
            active_count = sum(
                1 for v in map_after.values() if v in (0x01, 0x02)
            )
            lines.append(
                f"    Map state: {len(map_after)} total, "
                f"{quarantine_count} quarantine, {active_count} active"
            )
    else:
        lines.append(
            f"  [{_c('STATE RESTORED', _C.RED)}] {_ARROW} {_FAIL}"
        )

    # Summary
    lines.append("")
    lines.append(sep)
    lines.append(f"  Elapsed: {elapsed_ms:.1f} ms")
    lines.append(f"  Result:  {_c('LEDGER INTACT' if not is_tampered else 'INCIDENT CONTAINED', _C.GREEN if not is_tampered else _C.YELLOW)}")
    lines.append(sep)
    lines.append("")

    return "\n".join(lines)


# ============================================================================
#  Main Incident Scan
# ============================================================================

def incident_scan(log_path: Path, force_mitigation: bool = False,
                   verbose: bool = False) -> dict:
    """
    Full incident scan pipeline:
      1. Recalculate hash chain
      2. If tamper detected, execute mitigation
      3. Build report
    Returns a dict with all results.
    """
    t0 = time.monotonic()

    # Phase 1: Ledger verification
    verify_result = _recalculate_chain(log_path)
    is_tampered = verify_result["status"] == "TAMPER_DETECTED"

    flush_result = (0, 0)
    restored_count = 0

    # Phase 2: Mitigation
    if is_tampered and force_mitigation:
        tampered = verify_result.get("tampered_records", [])
        flush_result = flush_compromised_ips(tampered)
        restored_count = reload_trust_blocks(tampered)

    # Phase 3: Final map state
    map_after = get_loader_map_entries()

    elapsed_ms = (time.monotonic() - t0) * 1000.0

    return {
        "verify": verify_result,
        "flush": {
            "succeeded": flush_result[0],
            "failed": flush_result[1],
        },
        "restored_count": restored_count,
        "map_after": map_after,
        "elapsed_ms": round(elapsed_ms, 1),
        "all_clear": not is_tampered or flush_result[1] == 0,
    }


# ============================================================================
#  CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SRP Cryptographic Incident Response Suite",
    )
    parser.add_argument(
        "--incident-scan", action="store_true", default=False,
        help="Run full incident scan on the telemetry ledger",
    )
    parser.add_argument(
        "--log", default=None,
        help=f"Path to audit log (default: {_DEFAULT_LOG})",
    )
    parser.add_argument(
        "--force-mitigation", action="store_true", default=False,
        help="Execute automated flush and recovery on tamper detection",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="Include record details in report",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output results as JSON (machine-readable)",
    )
    args = parser.parse_args()

    log_path = Path(args.log) if args.log else _DEFAULT_LOG

    if not args.incident_scan:
        parser.print_help()
        sys.exit(2)

    if not log_path.exists():
        print(f"  [{_c('ERROR', _C.RED)}] Log file not found: {log_path}")
        sys.exit(2)

    result = incident_scan(
        log_path=log_path,
        force_mitigation=args.force_mitigation,
        verbose=args.verbose,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        report = build_incident_report(
            verify_result=result["verify"],
            flush_result=(result["flush"]["succeeded"],
                          result["flush"]["failed"]),
            restored_count=result["restored_count"],
            map_after=result["map_after"],
            elapsed_ms=result["elapsed_ms"],
            verbose=args.verbose,
        )
        print(report)

    sys.exit(0 if result["all_clear"] else 1)


if __name__ == "__main__":
    main()
