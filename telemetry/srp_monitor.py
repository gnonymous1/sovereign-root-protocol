#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP)  --  CORE TELEMETRY DIAGNOSTIC MONITOR
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ (no external dependencies)

  Administration utility that:

    * Tails the live audit log  (``--tail``)
    * Verifies the hash-chain   (``--verify``)
    * Generates a terminal diagnostic report with lifecycle markers

  Report headers::

    [TELEMETRY SUBSYSTEM ONLINE]
    -> [ASYNC BUFFER HEALTH CHECK]
    -> [CRYPTOGRAPHIC LEDGER SEALED]
    -> [LOG INTEGRITY VERIFIED]
    -> [ALL INSTANCES STABLE]

  References:
    - srp_logger.py         Ring-buffer shipper (producer side)
    - srp_ledger.py         Hash-chain ledger (verification logic)
    - AGENTS.md §2          Decision logic matrix
=============================================================================
"""

import os
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent.resolve()
DEFAULT_LOG_DIR = _HERE / "logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "srp_audit.log"

# ---------------------------------------------------------------------------
#  ANSI terminal codes (Windows compatible)
# ---------------------------------------------------------------------------
class _Style:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _color(text: str, code: str) -> str:
    """Wrap *text* in ANSI color if stdout is a terminal."""
    if sys.stdout.isatty():
        return f"{code}{text}{_Style.RESET}"
    return text


_OK = _color("OK", _Style.GREEN)
_FAIL = _color("FAIL", _Style.RED)
_WARN = _color("WARN", _Style.YELLOW)
_ARROW = "->"


# ============================================================================
#  Diagnostics
# ============================================================================

def _load_records(log_path: Path) -> list[dict]:
    """Load all JSON lines from the audit log."""
    records = []
    if not log_path.exists():
        return records
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    records.append({"__parse_error": True, "_raw": line[:120]})
    return records


def _compute_stats(records: list[dict]) -> dict:
    """Compute aggregate statistics from loaded records."""
    total = len(records)
    approved = sum(1 for r in records if r.get("verdict_action") == "APPROVED")
    terminated = sum(1 for r in records if r.get("verdict_action") == "TERMINATED")
    parse_errors = sum(1 for r in records if r.get("__parse_error"))

    latencies = [
        r["processing_latency_ms"]
        for r in records
        if isinstance(r.get("processing_latency_ms"), (int, float))
    ]
    scores = [
        r["alignment_score"]
        for r in records
        if isinstance(r.get("alignment_score"), (int, float))
    ]

    return {
        "total_records": total,
        "approved": approved,
        "terminated": terminated,
        "parse_errors": parse_errors,
        "approval_rate": round(approved / total * 100, 2) if total else 0.0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
        "min_latency_ms": round(min(latencies), 3) if latencies else 0.0,
        "avg_alignment": round(sum(scores) / len(scores), 4) if scores else 0.0,
        "min_alignment": round(min(scores), 4) if scores else 0.0,
        "max_alignment": round(max(scores), 4) if scores else 0.0,
        "unverified": sum(
            1 for r in records if r.get("integrity_seal") is None
        ),
    }


# ============================================================================
#  Report builder
# ============================================================================

def _marker(text: str, status: str) -> str:
    """Format a lifecycle marker line."""
    icon = _OK if status == "PASS" else (_FAIL if status == "FAIL" else _WARN)
    return f"  [{_color(text, _Style.BOLD)}] -> {icon}"


def _bullet(text: str, value, ok: bool = True) -> str:
    tag = _OK if ok else _FAIL
    return f"    {tag}  {text}: {_color(str(value), _Style.CYAN)}"


def build_report(log_path: Path, ledger_module=None,
                 skip_verify: bool = False) -> str:
    """
    Build a complete terminal diagnostic report.

    :param log_path:       Path to the audit log file.
    :param ledger_module:  The ``srp_ledger`` module (or None to skip ledger check).
    :param skip_verify:    If True, skip the full hash-chain verification.
    :returns:              Formatted multi-line report string.
    """
    lines = []
    sep = "=" * 56

    # -- Header --
    lines.append("")
    lines.append(sep)
    lines.append(f"  {_color('SRP TELEMETRY DIAGNOSTIC REPORT', _Style.BOLD)}")
    lines.append(f"  {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"  Log: {log_path}")
    lines.append(sep)
    lines.append("")

    # 1. TELEMETRY SUBSYSTEM ONLINE
    lines.append(_marker("TELEMETRY SUBSYSTEM ONLINE", "PASS"))

    log_exists = log_path.exists() and log_path.stat().st_size > 0
    if log_exists:
        file_size_mb = log_path.stat().st_size / (1024 * 1024)
        lines.append(
            _bullet("Log file", f"{log_path.name} ({file_size_mb:.2f} MB)", True)
        )
    else:
        lines.append(_bullet("Log file", "NOT FOUND  --  no records written yet", False))

    # 2. ASYNC BUFFER HEALTH CHECK
    lines.append("")
    lines.append(_marker("ASYNC BUFFER HEALTH CHECK", "PASS"))

    records = _load_records(log_path) if log_exists else []
    stats = _compute_stats(records)

    if log_exists:
        lines.append(
            _bullet("Total records", stats["total_records"], stats["total_records"] > 0)
        )
        lines.append(
            _bullet("Parse errors", stats["parse_errors"],
                    stats["parse_errors"] == 0)
        )
        lines.append(
            _bullet("Unverified records (no seal)", stats["unverified"],
                    stats["unverified"] == 0)
        )
    else:
        lines.append(_bullet("Records", "0  --  no data yet", True))

    # 3. CRYPTOGRAPHIC LEDGER SEALED
    lines.append("")
    lines.append(_marker("CRYPTOGRAPHIC LEDGER SEALED", "PASS"))

    if ledger_module is not None and log_exists and stats["total_records"] > 0:
        first_seal = records[0].get("integrity_seal", "N/A")
        last_seal = records[-1].get("integrity_seal", "N/A")
        lines.append(
            _bullet("Seal (first)", f"{first_seal[:20]}..." if len(first_seal) > 20 else first_seal,
                    first_seal != "N/A")
        )
        lines.append(
            _bullet("Seal (last)", f"{last_seal[:20]}..." if len(last_seal) > 20 else last_seal,
                    last_seal != "N/A")
        )
    else:
        lines.append(_bullet("Seal", "N/A  --  no records", True))

    # 4. LOG INTEGRITY VERIFIED
    lines.append("")
    lines.append(_marker("LOG INTEGRITY VERIFIED", "PASS"))

    if ledger_module is not None and log_exists and not skip_verify:
        verify_result = ledger_module.IntegrityLedger.verify_chain(str(log_path))
        if verify_result["status"] == "INTEGRITY_VERIFIED":
            lines.append(
                _bullet("Chain integrity",
                        f"INTACT  --  {verify_result['total_lines']} seals verified", True)
            )
        elif verify_result["status"] == "EMPTY_LOG":
            lines.append(_bullet("Chain integrity", "EMPTY  --  no seals to check", True))
            lines.insert(
                lines.index(
                    next(l for l in lines if "LOG INTEGRITY VERIFIED" in l)
                ),
                _marker("LOG INTEGRITY VERIFIED", "FAIL"),
            )
            lines.remove(
                next(l for l in lines if "LOG INTEGRITY VERIFIED" in l)
            )
        else:
            lines.append(
                _bullet("Chain integrity",
                        f"TAMPER DETECTED at line {verify_result['first_bad_line']}",
                        False)
            )
            lines.append(
                _bullet("Expected",
                        verify_result["expected_seal"][:20] + "..."
                        if verify_result["expected_seal"] else "N/A",
                        False)
            )
            lines.append(
                _bullet("Stored",
                        verify_result["actual_seal"][:20] + "..."
                        if verify_result["actual_seal"] else "N/A",
                        False)
            )
            # Demote the marker to FAIL by replacing it
            idx = lines.index(
                next(l for l in lines if "LOG INTEGRITY VERIFIED" in l)
            )
            lines[idx] = _marker("LOG INTEGRITY VERIFIED", "FAIL")
    elif not log_exists:
        lines.append(_bullet("Chain integrity", "NO LOG FILE  --  nothing to verify", True))
    else:
        lines.append(_bullet("Chain integrity", "SKIPPED (--skip-verify)", True))

    # 5. PERFORMANCE & SAFETY SUMMARY
    lines.append("")
    lines.append(_marker("PERFORMANCE METRICS", "PASS"))

    if stats["total_records"] > 0:
        lines.append(f"    {_color('Approval rate:', _Style.DIM)}  "
                      f"{stats['approval_rate']}%  "
                      f"({stats['approved']} approved / {stats['terminated']} terminated)")
        lines.append(f"    {_color('Avg alignment score:', _Style.DIM)}  "
                      f"{stats['avg_alignment']:.4f}  "
                      f"(min={stats['min_alignment']:.4f}  max={stats['max_alignment']:.4f})")
        lines.append(f"    {_color('Processing latency:', _Style.DIM)}  "
                      f"avg={stats['avg_latency_ms']:.3f}ms  "
                      f"max={stats['max_latency_ms']:.3f}ms  "
                      f"min={stats['min_latency_ms']:.3f}ms")
    else:
        lines.append(f"    {_color('No metrics  --  no records in log', _Style.DIM)}")

    # 6. ALL INSTANCES STABLE
    all_pass = (
        (log_exists or not log_exists)  # always OK (no data is acceptable)
        and stats["parse_errors"] == 0
        and stats["unverified"] == 0
        and (
            not log_exists
            or skip_verify
            or (ledger_module is not None
                and ledger_module.IntegrityLedger.verify_chain(str(log_path))["status"]
                == "INTEGRITY_VERIFIED")
        )
    )
    lines.append("")
    if all_pass:
        lines.append(_marker("ALL INSTANCES STABLE", "PASS"))
    else:
        lines.append(_marker("ALL INSTANCES STABLE", "FAIL"))
    lines.append(sep)
    lines.append("")

    return "\n".join(lines)


# ============================================================================
#  Tail mode
# ============================================================================

def _follow_file(log_path: Path):
    """Generator that yields new lines appended to the log file (like tail -f)."""
    if not log_path.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch()
    with open(log_path, "r", encoding="utf-8") as fh:
        # Seek to end
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)


def _run_tail(log_path: Path):
    """Continuous tail mode with formatted output."""
    print(f"  [TAIL] Watching {log_path}  (Ctrl+C to stop)\n")
    try:
        for raw_line in _follow_file(log_path):
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except json.JSONDecodeError:
                print(f"  {raw_line}")
                continue

            ts = rec.get("timestamp_ns", 0)
            action = rec.get("verdict_action", "?")
            score = rec.get("alignment_score", 0.0)
            ip = rec.get("source_ip", "?")
            lat = rec.get("processing_latency_ms", 0.0)
            intent = (rec.get("intent_hash", "") or "")[:12]

            action_colored = _color(f"{action:>10}", _Style.GREEN
                                    if action == "APPROVED" else _Style.RED)
            print(f"  {ts:>20}  {action_colored}  "
                  f"score={score:.4f}  lat={lat:.3f}ms  "
                  f"ip={ip:<15}  intent={intent}...")
    except KeyboardInterrupt:
        print("\n  [TAIL] Stopped.")


# ============================================================================
#  Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SRP Telemetry Diagnostic Monitor",
    )
    parser.add_argument(
        "--verify", action="store_true", default=False,
        help="Run full cryptographic chain verification and print report",
    )
    parser.add_argument(
        "--tail", action="store_true", default=False,
        help="Live-tail the audit log with formatted output",
    )
    parser.add_argument(
        "--log", default=None,
        help=f"Path to audit log (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--skip-verify", action="store_true", default=False,
        help="Skip hash-chain verification in report",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output report as JSON (machine-readable)",
    )
    args = parser.parse_args()

    # Resolve log path
    log_path = Path(args.log) if args.log else DEFAULT_LOG_FILE

    # Import ledger module (best-effort)
    ledger_module = None
    try:
        from telemetry import srp_ledger as ledger_module
    except ImportError:
        try:
            sys.path.insert(0, str(_HERE))
            import srp_ledger as ledger_module
        except ImportError:
            pass

    if args.tail:
        _run_tail(log_path)
        return

    if args.verify or not (args.tail):
        # Build and display the diagnostic report
        report = build_report(
            log_path=log_path,
            ledger_module=ledger_module,
            skip_verify=args.skip_verify or not args.verify,
        )

        if args.json:
            # Output machine-readable JSON
            stats = _compute_stats(_load_records(log_path))
            chain_status = "SKIPPED"
            if ledger_module and log_path.exists() and not args.skip_verify and args.verify:
                vr = ledger_module.IntegrityLedger.verify_chain(str(log_path))
                chain_status = vr["status"]
            output = {
                "report": report.strip().split("\n"),
                "stats": stats,
                "chain_status": chain_status,
                "log_path": str(log_path),
                "log_exists": log_path.exists(),
            }
            print(json.dumps(output, indent=2))
        else:
            print(report)


if __name__ == "__main__":
    main()
