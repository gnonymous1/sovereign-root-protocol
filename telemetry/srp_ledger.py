#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — IMMUTABLE INTEGRITY LEDGER (HASH CHAIN)
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ hashlib SHA256

  Implements a zero-allocation Merkle-style hash chain that guarantees
  non-repudiation for the structured audit log::

      Seal_n = SHA256( CanonicalJSON(Record_n) + Seal_{n-1} )

  Every audit record carries an ``integrity_seal`` field that chains it
  irrevocably to the preceding record.  If a single byte is altered,
  deleted, or reordered anywhere in the log file, a full-chain
  verification will detect the tamper immediately.

  Genesis seal (block zero):

      Seal_0 = SHA256( CanonicalJSON(Record_0) + '\x00' * 64 )

  References:
    - srp_logger.py         Consumer appends seal via ledger.seal()
    - srp_monitor.py        --verify mode recalculates and asserts chain
    - AGENTS.md §2          Non-repudiation requirement
=============================================================================
"""

import json
import hashlib
from typing import Optional
from pathlib import Path

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
_GENESIS_ANCESTOR = "\x00" * 64  # 64 zero-bytes string for block 0 ancestry
_SEPARATOR = ":"  # delimiter between JSON payload and ancestor hash


# ============================================================================
#  IntegrityLedger — Running hash-chain state machine
# ============================================================================

class IntegrityLedger:
    """
    Thread-safe (single-consumer) hash-chain ledger.

    Typical usage::

        ledger = IntegrityLedger()

        # Called for each record by the consumer:
        seal = ledger.seal(record_dict)   # returns hex digest
        record_dict["integrity_seal"] = seal

        # Verify the entire log file:
        result = IntegrityLedger.verify_chain("telemetry/logs/srp_audit.log")
        print(result["status"])  # "INTEGRITY_VERIFIED" | "TAMPER_DETECTED"
    """

    __slots__ = ("_last_seal", "_count")

    def __init__(self, initial_seal: Optional[str] = None):
        """
        :param initial_seal: If provided, resume the chain from this hash
            (e.g., after a daemon restart, read the last seal from the log).
            Defaults to the genesis ancestor (64 zero bytes).
        """
        self._last_seal: str = initial_seal if initial_seal else _GENESIS_ANCESTOR
        self._count: int = 0

    # -- Properties --------------------------------------------------------

    @property
    def last_seal(self) -> str:
        """The most recently computed seal hex digest."""
        return self._last_seal

    @property
    def sealed_count(self) -> int:
        """Number of records sealed so far in this session."""
        return self._count

    @property
    def is_genesis(self) -> bool:
        """True if no records have been sealed yet."""
        return self._last_seal == _GENESIS_ANCESTOR

    # -- Core sealing API --------------------------------------------------

    def seal(self, record: dict) -> str:
        """
        Compute the integrity hash for *record* and update the internal
        chain state.

        The seal is computed over the canonical JSON of the record dict
        (excluding any existing ``integrity_seal`` key, then re-serialised
        with sorted keys for deterministic output) concatenated with the
        previous seal hash via an ASCII colon separator::

            payload_json = json.dumps(record, separators=(',',':'), sort_keys=True)
            input_string = payload_json + ':' + previous_seal
            new_seal = SHA256( input_string.encode('utf-8') ).hexdigest()

        :param record:  Dict of the audit record (may or may not already
                        contain an ``integrity_seal`` key — it is stripped
                        before hashing).
        :returns:       64-character hex-encoded SHA-256 digest.
        """
        # Strip any existing seal to avoid double-sealing
        payload = {k: v for k, v in record.items() if k != "integrity_seal"}

        # Canonical JSON with sorted keys, no whitespace
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True,
                                  ensure_ascii=False)

        # Build the input: payload + ':' + previous_seal
        input_str = payload_json + _SEPARATOR + self._last_seal

        # Compute SHA-256
        digest = hashlib.sha256(input_str.encode("utf-8")).hexdigest()

        # Update internal state
        self._last_seal = digest
        self._count += 1

        return digest

    def reset(self, initial_seal: Optional[str] = None):
        """
        Reset the chain to a clean state (e.g., for a new log file after
        rotation).  If *initial_seal* is None, starts from genesis.
        """
        self._last_seal = initial_seal if initial_seal else _GENESIS_ANCESTOR
        self._count = 0

    # -- Static verification -----------------------------------------------

    @staticmethod
    def verify_chain(log_path: str) -> dict:
        """
        Full sequential verification of an audit log file.

        Reads every JSON line, recalculates the hash chain from block zero,
        and reports the first discrepancy (if any).  Returns a summary dict.

        :param log_path:  Path to the ``srp_audit.log`` file.
        :returns::

            {
                "status":        "INTEGRITY_VERIFIED" | "TAMPER_DETECTED",
                "total_lines":   int,
                "verified_until": int,   # 0-indexed line number of last OK seal
                "first_bad_line": int | None,
                "expected_seal": str | None,
                "actual_seal":   str | None,
                "error":         str | None,
            }
        """
        result = {
            "status": "INTEGRITY_VERIFIED",
            "total_lines": 0,
            "verified_until": -1,
            "first_bad_line": None,
            "expected_seal": None,
            "actual_seal": None,
            "error": None,
        }

        path = Path(log_path)
        if not path.exists() or path.stat().st_size == 0:
            result["status"] = "EMPTY_LOG"
            result["error"] = f"Log file not found or empty: {log_path}"
            return result

        previous_seal = _GENESIS_ANCESTOR

        with open(path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    result["status"] = "TAMPER_DETECTED"
                    result["total_lines"] = line_no + 1
                    result["first_bad_line"] = line_no
                    result["error"] = f"Invalid JSON at line {line_no}: {exc}"
                    result["actual_seal"] = line[:80]
                    return result

                stored_seal = record.pop("integrity_seal", None)
                if stored_seal is None:
                    result["status"] = "TAMPER_DETECTED"
                    result["total_lines"] = line_no + 1
                    result["first_bad_line"] = line_no
                    result["error"] = f"Missing integrity_seal at line {line_no}"
                    return result

                # Recompute expected seal
                payload_json = json.dumps(
                    record, separators=(",", ":"), sort_keys=True,
                    ensure_ascii=False,
                )
                input_str = payload_json + _SEPARATOR + previous_seal
                expected_seal = hashlib.sha256(
                    input_str.encode("utf-8")
                ).hexdigest()

                if stored_seal != expected_seal:
                    result["status"] = "TAMPER_DETECTED"
                    result["total_lines"] = line_no + 1
                    result["first_bad_line"] = line_no
                    result["expected_seal"] = expected_seal
                    result["actual_seal"] = stored_seal
                    result["error"] = (
                        f"Seal mismatch at line {line_no}: "
                        f"expected={expected_seal[:16]}... "
                        f"stored={stored_seal[:16]}..."
                    )
                    return result

                previous_seal = stored_seal
                result["verified_until"] = line_no

        result["total_lines"] = result["verified_until"] + 1
        return result

    # -- Utility: recover last seal from a log file ------------------------

    @staticmethod
    def read_last_seal(log_path: str) -> Optional[str]:
        """
        Read the integrity_seal of the last complete JSON line in the log.

        Useful when restarting a daemon — pass this value as
        ``IntegrityLedger(initial_seal=...)`` to resume the chain where it
        left off.

        Returns ``None`` if the log is empty or unreadable.
        """
        path = Path(log_path)
        if not path.exists() or path.stat().st_size == 0:
            return None

        last_seal = None
        with open(path, "rb") as fh:
            # Seek near the end for efficiency
            try:
                fh.seek(-4096, 2)  # last 4 KB
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", errors="replace")
            for line in reversed(tail.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    seal = rec.get("integrity_seal")
                    if seal and len(seal) == 64:
                        last_seal = seal
                        break
                except json.JSONDecodeError:
                    continue
        return last_seal


# ============================================================================
#  Standalone CLI demo / self-test
# ============================================================================

def _demo():
    """Push sample records through the ledger and verify the chain."""
    import tempfile
    import os

    ledger = IntegrityLedger()
    records = [
        {"timestamp_ns": 1000, "node_hardware_id": "a1b2", "verdict_action": "APPROVED"},
        {"timestamp_ns": 2000, "node_hardware_id": "c3d4", "verdict_action": "TERMINATED"},
        {"timestamp_ns": 3000, "node_hardware_id": "e5f6", "verdict_action": "APPROVED"},
    ]

    print("  [LEDGER DEMO] Sealing 3 records...")
    for i, rec in enumerate(records):
        seal = ledger.seal(rec)
        rec["integrity_seal"] = seal
        print(f"    Record {i}: seal={seal[:20]}...  count={ledger.sealed_count}")

    # Write to temp file and verify
    tmp = os.path.join(tempfile.gettempdir(), "srp_ledger_demo.jsonl")
    with open(tmp, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")

    result = IntegrityLedger.verify_chain(tmp)
    print(f"    Verify: {result['status']} ({result['total_lines']} lines)")

    # Corrupt a byte and re-verify
    data = open(tmp, "rb").read()
    data = data.replace(b"APPROVED", b"APPR0VED")  # tamper
    open(tmp, "wb").write(data)

    result2 = IntegrityLedger.verify_chain(tmp)
    print(f"    Verify after tamper: {result2['status']} (line {result2['first_bad_line']})")

    os.unlink(tmp)
    print("  [LEDGER DEMO] Done.")


if __name__ == "__main__":
    _demo()
