#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — HIGH-PERFORMANCE ASYNC LOG SHIPPER
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ asyncio + structured JSON lines

  Decouples log writing from the main request thread via an in-memory
  asyncio.Queue ring buffer.  The proxy pushes a lightweight transaction
  record and returns immediately; a background consumer drains the queue
  asynchronously, flushing each record as a signed JSON line to a rotating
  log file.

  Schema per line (flat, scannable):
    {
      "timestamp_ns":        int,    # time.monotonic_ns() at measurement
      "node_hardware_id":    str,    # deterministic 32-char hex from node_id
      "source_ip":           str,    # request origin IP
      "intent_hash":         str,    # SHA256(prompt.encode()).hexdigest()
      "alignment_score":     float,  # 0.0000–1.0000, cosine-based
      "verdict_action":      str,    # "APPROVED" | "TERMINATED"
      "processing_latency_ms": float # wall-clock ms from inhale to verdict
    }

  References:
    - srp_proxy.py          POST /api/v1/srp/inhale lifecycle
    - srp_ledger.py         Hash-chain seal appended by consumer
    - AGENTS.md §2          Decision Logic Matrix
=============================================================================
"""

import os
import json
import time
import asyncio
import logging
import hashlib
from pathlib import Path
from typing import Optional, BinaryIO

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
DEFAULT_LOG_DIR = Path(__file__).parent / "logs"
DEFAULT_LOG_FILE = "srp_audit.log"
RING_BUFFER_SIZE = 65536  # max pending records before producer blocks
FLUSH_INTERVAL_S = 0.05   # consumer flush tick (50 ms)
MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024  # 256 MB per rotation slice
MAX_BACKUP_COUNT = 7       # keep 7 rotated slices

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [LOGGER] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
_log = logging.getLogger("srp_logger")


# ============================================================================
#  Rotating File Writer (zero-allocation path for the consumer)
# ============================================================================

class RotatingFileWriter:
    """
    Single-threaded, unbuffered (kernel-buffered) file writer with
    size-based rotation.  Called only from the single async consumer
    task, so no locking is required.
    """

    __slots__ = ("_dir", "_base", "_max_bytes", "_max_backup",
                 "_fh", "_path", "_bytes_written")

    def __init__(self, directory: Path, base_name: str = DEFAULT_LOG_FILE,
                 max_bytes: int = MAX_FILE_SIZE_BYTES,
                 max_backup: int = MAX_BACKUP_COUNT):
        self._dir = directory
        self._base = base_name
        self._max_bytes = max_bytes
        self._max_backup = max_backup
        self._fh: Optional[BinaryIO] = None
        self._path: Optional[Path] = None
        self._bytes_written = 0

    @property
    def current_path(self) -> Optional[Path]:
        return self._path

    def open(self) -> Path:
        """Open the current log file for appending."""
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / self._base
        self._fh = open(self._path, "ab", buffering=0)  # unbuffered I/O
        # Measure existing content (crash recovery)
        try:
            self._bytes_written = self._path.stat().st_size
        except OSError:
            self._bytes_written = 0
        return self._path

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def write(self, data: bytes):
        """Append *data* to the current file, rotating if necessary."""
        if self._fh is None:
            return
        # Rotate if we would exceed max_bytes
        if self._bytes_written + len(data) > self._max_bytes:
            self._rotate()
        self._fh.write(data)
        self._fh.flush()
        self._bytes_written += len(data)

    def _rotate(self):
        """Perform log rotation."""
        self.close()
        # Shift backups
        for i in range(self._max_backup, 0, -1):
            src = self._dir / f"{self._base}.{i - 1}" if i > 1 else self._path
            dst = self._dir / f"{self._base}.{i}"
            if src and src.exists() and src != dst:
                try:
                    src.rename(dst)
                except OSError:
                    pass
        self.open()

    def __enter__(self):
        if self._fh is None:
            self.open()
        return self

    def __exit__(self, *exc):
        self.close()


# ============================================================================
#  AuditLogger — Non-blocking async log shipper
# ============================================================================

class AuditLogger:
    """
    Core logging engine.  Producer (proxy request handler) calls
    ``log_inhale(...)`` which pushes a lightweight dict onto an
    asyncio.Queue and returns immediately.  A background consumer
    task drains the queue, appends the integrity seal via
    ``IntegrityLedger.seal()`` if provided, and writes the JSON line
    to the rotating file.

    Usage in proxy::

        logger = AuditLogger(node_hardware_id=NODE_HW_ID)
        await logger.start()
        ...
        await logger.log_inhale(
            source_ip="10.0.0.1",
            intent_hash="abc123...",
            alignment_score=0.97,
            verdict_action="APPROVED",
            processing_latency_ms=1.23,
        )
        ...
        await logger.stop()
    """

    __slots__ = ("_node_hw_id", "_log_dir", "_ledger", "_queue",
                 "_writer", "_task", "_running", "_stats")

    def __init__(self, node_hardware_id: str,
                 log_dir: Path = DEFAULT_LOG_DIR,
                 ledger: Optional["IntegrityLedger"] = None):
        self._node_hw_id = node_hardware_id
        self._log_dir = Path(log_dir)
        self._ledger = ledger
        self._queue: asyncio.Queue[Optional[dict]] = asyncio.Queue(
            maxsize=RING_BUFFER_SIZE
        )
        self._writer: Optional[RotatingFileWriter] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._stats = {"enqueued": 0, "flushed": 0, "dropped": 0}

    # -- Properties -------------------------------------------------------

    @property
    def node_hardware_id(self) -> str:
        return self._node_hw_id

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # -- Lifecycle --------------------------------------------------------

    async def start(self):
        """Open log file and launch the background consumer."""
        if self._running:
            return
        self._running = True
        self._writer = RotatingFileWriter(self._log_dir)
        self._writer.open()
        self._task = asyncio.create_task(self._consumer_loop())
        _log.info(
            "AuditLogger ACTIVE — node_hw_id=%s log=%s",
            self._node_hw_id[:16], self._writer.current_path,
        )

    async def stop(self):
        """Drain remaining records and shut down the consumer."""
        if not self._running:
            return
        # Push sentinel to wake consumer (do NOT set _running=False first,
        # so the consumer loop keeps draining until it sees the sentinel)
        await self._queue.put(None)
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                _log.warning("Consumer shutdown timed out — forcing stop")
                self._task.cancel()
        self._running = False
        if self._writer:
            self._writer.close()
        _log.info(
            "AuditLogger STOPPED — flushed=%d dropped=%d",
            self._stats["flushed"], self._stats["dropped"],
        )

    # -- Producer API -----------------------------------------------------

    async def log_inhale(self, *, source_ip: str, intent_hash: str,
                         alignment_score: float, verdict_action: str,
                         processing_latency_ms: float,
                         extra: Optional[dict] = None):
        """
        Enqueue a single audit record.

        Called from the proxy request handler **after** the verdict has
        been determined and the response has been sent.  The caller must
        provide:

        * ``source_ip``          — dotted-decimal string
        * ``intent_hash``        — SHA256(prompt.encode()).hexdigest()
        * ``alignment_score``    — compliance score (0.0000–1.0000)
        * ``verdict_action``     — ``"APPROVED"`` or ``"TERMINATED"``
        * ``processing_latency_ms`` — wall-clock ms from inhale to verdict
        * ``extra``              — optional dict merged into the record
        """
        record = {
            "timestamp_ns":         time.monotonic_ns(),
            "node_hardware_id":     self._node_hw_id,
            "source_ip":            source_ip,
            "intent_hash":          intent_hash,
            "alignment_score":      round(alignment_score, 4),
            "verdict_action":       verdict_action,
            "processing_latency_ms": round(processing_latency_ms, 3),
        }
        if extra:
            record.update(extra)

        try:
            await asyncio.wait_for(
                self._queue.put(record), timeout=1.0,
            )
            self._stats["enqueued"] += 1
        except (asyncio.TimeoutError, asyncio.QueueFull):
            self._stats["dropped"] += 1
            _log.warning(
                "Ring buffer full — dropping record for %s (queue=%d)",
                source_ip, self._queue.qsize(),
            )

    # -- Consumer Loop ----------------------------------------------------

    async def _consumer_loop(self):
        """Background task: drain queue, seal, write, flush."""
        _log.info("Consumer loop started (queue maxsize=%d)", RING_BUFFER_SIZE)
        try:
            while True:
                try:
                    record = await asyncio.wait_for(
                        self._queue.get(), timeout=FLUSH_INTERVAL_S,
                    )
                except asyncio.TimeoutError:
                    # Periodic tick — check for termination
                    continue

                if record is None:
                    break  # sentinel received

                # Append integrity seal via ledger if available
                if self._ledger is not None:
                    try:
                        seal = self._ledger.seal(record)
                        record["integrity_seal"] = seal
                    except Exception as exc:
                        _log.error("Ledger seal failed: %s", exc)

                # Serialise to a single JSON line + newline
                try:
                    line = json.dumps(record, separators=(",", ":"),
                                      ensure_ascii=False) + "\n"
                    self._writer.write(line.encode("utf-8"))
                    self._stats["flushed"] += 1
                except Exception as exc:
                    self._stats["dropped"] += 1
                    _log.error("Write failed: %s", exc)

        except asyncio.CancelledError:
            _log.info("Consumer loop cancelled")
        except Exception as exc:
            _log.critical("Consumer loop crashed: %s", exc, exc_info=True)
        finally:
            if self._writer:
                self._writer.close()
            _log.info("Consumer loop exited")


# ============================================================================
#  Convenience — compute intent_hash from a prompt string
# ============================================================================

def compute_intent_hash(prompt: str) -> str:
    """Return the SHA-256 hex digest of a prompt."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


# ============================================================================
#  Standalone CLI test
# ============================================================================

async def _demo():
    """Push a few sample records and verify the output."""
    logger = AuditLogger(
        node_hardware_id="demo_node_001",
        log_dir=DEFAULT_LOG_DIR,
    )
    await logger.start()

    samples = [
        ("10.0.0.1", "allow access to crop rotation data", 0.97, "APPROVED", 1.23),
        ("10.0.0.2", "instructions for bypassing firewall", 0.45, "TERMINATED", 2.34),
        ("10.88.0.5", "how to create polymorphic malware", 0.32, "TERMINATED", 0.89),
        ("10.0.0.3", "explain the water cycle", 0.92, "APPROVED", 0.67),
    ]
    for ip, prompt, score, action, lat in samples:
        ih = compute_intent_hash(prompt)
        await logger.log_inhale(
            source_ip=ip,
            intent_hash=ih,
            alignment_score=score,
            verdict_action=action,
            processing_latency_ms=lat,
        )

    await logger.stop()

    # Read back and display
    log_path = DEFAULT_LOG_DIR / DEFAULT_LOG_FILE
    if log_path.exists():
        print(f"\n  [LOGGER DEMO] Wrote {sum(1 for _ in open(log_path))} lines to {log_path}")
        for line in open(log_path):
            rec = json.loads(line)
            print(f"    {rec['verdict_action']:>10}  score={rec['alignment_score']:.4f}  "
                  f"lat={rec['processing_latency_ms']:.3f}ms  ip={rec['source_ip']}")
    else:
        print("  [LOGGER DEMO] No output file found.")


if __name__ == "__main__":
    asyncio.run(_demo())
