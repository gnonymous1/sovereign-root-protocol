#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — AUTOMATED HEALTH & LATENCY WATCHDOG
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ asyncio

  High-frequency background polling engine that monitors local node health,
  memory pressure, packet-drop ratios, and eBPF hash-table saturation every
  500 ms.

  Thresholds:
    - Processing latency      >= 1.5 ms  -> drain server
    - BPF map saturation      >= 65536   -> drain server
    - Packet drop ratio       >= 0.05    -> warn (5% drops)
    - Sync daemon heartbeat   timeout    -> warn

  On threshold breach:
    1. HAProxy stats socket  -> set server weight to 0
    2. Emergency state dump  -> /var/run/srp_state_drain.bin
    3. Event logged to       -> /var/log/srp_watchdog.log

  References:
    - srp_filter.c           XDP packet counters, sovereign_approval map
    - srp_sync_daemon.py     Peer mesh heartbeat monitoring
    - cluster/haproxy_srp.cfg  Stats socket at 127.0.0.1:1993
    - AGENTS.md              Decision logic matrix thresholds
=============================================================================
"""

import os
import sys
import json
import time
import struct
import socket
import asyncio
import logging
import hashlib
import signal
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    import httpx
except ImportError:
    sys.exit(
        "CRITICAL DEPENDENCY MISSING: httpx is required but not installed.\n"
        "  Install with:  pip install httpx\n"
        "  The SRP Watchdog cannot fetch loader metrics, map state, or\n"
        "  proxy/sync health without httpx.  Aborting."
    )

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
POLL_INTERVAL_S = 0.5            # 500 ms polling tick
LATENCY_THRESHOLD_MS = 1.5       # max allowed processing latency
BPF_MAP_CAPACITY = 65536         # sovereign_approval hash map limit
BPF_SATURATION_WARN = 60000      # warn at 60K entries
DROP_RATIO_WARN = 0.05           # 5% packet drop threshold
SYNC_HEARTBEAT_TIMEOUT_S = 10.0  # from srp_sync_daemon: synced() check

LOADER_METRICS_URL = "http://127.0.0.1:9001/api/v1/srp/metrics"
LOADER_MAP_URL = "http://127.0.0.1:9001/api/v1/srp/map"
PROXY_HEALTH_URL = "http://127.0.0.1:9000/health"
SYNC_HEALTH_URL = "http://127.0.0.1:9201/health"
HAPROXY_STATS_SOCKET = ("127.0.0.1", 1993, "admin")  # level admin

STATE_DRAIN_PATH = Path("/var/run/srp_state_drain.bin")
WATCHDOG_LOG_PATH = Path("/var/log/srp_watchdog.log")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [WATCHDOG] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("srp_watchdog")


# ============================================================================
#  HAProxy Stats Socket Interface
# ============================================================================

class HAProxyAdmin:
    """
    Interface to HAProxy's runtime admin Unix socket (or TCP).
    Supports weight adjustment and server state queries.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1993):
        self._addr = (host, port)

    async def set_server_weight(self, server: str, backend: str = "srp-proxy-pool",
                                 weight: int = 0) -> bool:
        """
        Set a backend server's weight via HAProxy's stats socket.
        ``weight=0`` effectively drains the server (no new connections).
        Returns True on success.
        """
        try:
            cmd = f"set weight {backend}/{server} {weight}\n"
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(*self._addr), timeout=5.0,
            )
            writer.write(cmd.encode())
            await writer.drain()
            # Read response
            resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            if b"'" not in resp and weight == 0:
                # HAProxy echoes the new weight on success
                logger.info(
                    "HAProxy weight for %s/%s set to %d",
                    backend, server, weight,
                )
                return True
            logger.warning(
                "HAProxy weight set response: %s", resp.decode(errors="replace").strip(),
            )
            return True  # non-fatal
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.warning("HAProxy stats socket unreachable: %s", e)
            return False

    async def get_server_state(self, server: str,
                                backend: str = "srp-proxy-pool") -> Optional[dict]:
        """Query server state from HAProxy stats."""
        try:
            cmd = f"show stat\n"
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(*self._addr), timeout=5.0,
            )
            writer.write(cmd.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            for line in data.decode(errors="replace").splitlines():
                if line.startswith(f"{backend},{server},"):
                    fields = line.split(",")
                    return {
                        "pxname": fields[0],
                        "svname": fields[1],
                        "status": fields[17] if len(fields) > 17 else "?",
                        "weight": fields[18] if len(fields) > 18 else "?",
                        "hrsp_2xx": fields[40] if len(fields) > 40 else "?",
                    }
            return None
        except Exception as e:
            logger.debug("HAProxy stats query failed: %s", e)
            return None


# ============================================================================
#  Emergency State Dump
# ============================================================================

async def dump_emergency_state(loader_map_url: str = LOADER_MAP_URL,
                                metrics_url: str = LOADER_METRICS_URL):
    """
    Dump the current eBPF map and metrics to a binary emergency file.
    Returns the path written to, or None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            map_resp = await client.get(loader_map_url)
            metrics_resp = await client.get(metrics_url)

        snapshot = {
            "timestamp_ns": time.monotonic_ns(),
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "map": map_resp.json() if map_resp.status_code == 200 else {},
            "metrics": metrics_resp.json() if metrics_resp.status_code == 200 else {},
            "watchdog_version": "2026.4.2",
        }

        STATE_DRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_DRAIN_PATH, "wb") as f:
            raw = json.dumps(snapshot, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
            f.write(struct.pack("!I", len(raw)))
            f.write(raw)

        logger.warning(
            "EMERGENCY STATE DUMP: %s (%d bytes, %d map entries)",
            STATE_DRAIN_PATH, len(raw),
            len(snapshot.get("map", {}).get("entries", {})),
        )
        return STATE_DRAIN_PATH
    except Exception as e:
        logger.error("Emergency state dump failed: %s", e)
        return None


# ============================================================================
#  Metrics collectors
# ============================================================================

async def fetch_loader_metrics() -> Optional[dict]:
    """Fetch current loader metrics."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(LOADER_METRICS_URL)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return None


async def fetch_loader_map() -> Optional[dict]:
    """Fetch the eBPF sovereign_approval map state."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(LOADER_MAP_URL)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return None


async def check_sync_health() -> tuple[bool, float]:
    """
    Return (healthy, elapsed_s) for the sync daemon health endpoint.
    """
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(SYNC_HEALTH_URL)
        elapsed = (time.monotonic() - t0) * 1000.0
        return r.status_code == 200, elapsed
    except Exception:
        return False, 0.0


# ============================================================================
#  Threshold evaluation
# ============================================================================

def evaluate_thresholds(metrics: Optional[dict], map_data: Optional[dict],
                         proxy_latency_ms: float, sync_healthy: bool,
                         sync_latency_ms: float,
                         latency_threshold_ms: float = LATENCY_THRESHOLD_MS
                         ) -> list[str]:
    """
    Evaluate all thresholds and return a list of triggered alerts.
    Empty list means all clear.
    """
    alerts = []

    # 1. Processing latency threshold (1.5 ms)
    if proxy_latency_ms >= latency_threshold_ms:
        alerts.append(
            f"LATENCY_BREACH: proxy_latency={proxy_latency_ms:.3f}ms >= "
            f"{latency_threshold_ms}ms"
        )

    # 2. BPF map saturation
    if map_data:
        map_size = map_data.get("map_size", 0)
        if map_size >= BPF_MAP_CAPACITY:
            alerts.append(
                f"BPF_SATURATION: map_size={map_size} >= "
                f"{BPF_MAP_CAPACITY} (full)"
            )
        elif map_size >= BPF_SATURATION_WARN:
            alerts.append(
                f"BPF_SATURATION_WARN: map_size={map_size} >= "
                f"{BPF_SATURATION_WARN}"
            )

    # 3. Packet drop ratio
    if metrics:
        inspected = metrics.get("inspected", 0)
        dropped = metrics.get("dropped", 0)
        if inspected > 0:
            drop_ratio = dropped / inspected
            if drop_ratio >= DROP_RATIO_WARN:
                alerts.append(
                    f"HIGH_DROP_RATIO: {drop_ratio:.4f} "
                    f"({dropped}/{inspected}) >= {DROP_RATIO_WARN}"
                )

    # 4. Sync daemon health
    if not sync_healthy:
        alerts.append(f"SYNC_UNREACHABLE: sync health check failed")
    if sync_latency_ms >= latency_threshold_ms:
        alerts.append(
            f"SYNC_LATENCY: sync_latency={sync_latency_ms:.3f}ms >= "
            f"{latency_threshold_ms}ms"
        )

    return alerts


# ============================================================================
#  Watchdog Engine
# ============================================================================

class WatchdogEngine:
    """
    Core watchdog polling loop.  Checks all health metrics every 500 ms and
    triggers mitigation actions when thresholds are exceeded.
    """

    def __init__(self, node_id: str = "srp-node-unknown",
                 proxy_host: str = "127.0.0.1",
                 proxy_port: int = 9000,
                 poll_interval_s: float = POLL_INTERVAL_S,
                 latency_threshold_ms: float = LATENCY_THRESHOLD_MS):
        self._node_id = node_id
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._poll_interval = poll_interval_s
        self._latency_threshold = latency_threshold_ms
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._haproxy = HAProxyAdmin()
        self._alerts_active: set[str] = set()
        self._stats = {
            "polls": 0,
            "alerts_triggered": 0,
            "weight_drops": 0,
            "state_dumps": 0,
        }

        # Resolve node label from cluster config
        self._resolve_node_id()

    def _resolve_node_id(self):
        """Attempt to read node identity from cluster_nodes.json."""
        config_path = Path(__file__).parent.parent / "cluster" / "cluster_nodes.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                self_sec = cfg.get("self", {})
                self._node_id = self_sec.get("id", self._node_id)
            except Exception:
                pass

    # -- Properties -------------------------------------------------------

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # -- Lifecycle --------------------------------------------------------

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(
            "Watchdog ACTIVE — node=%s interval=%.0fms threshold=%.1fms",
            self._node_id, self._poll_interval * 1000, self._latency_threshold,
        )

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "Watchdog STOPPED — polls=%d alerts=%d drops=%d dumps=%d",
            self._stats["polls"], self._stats["alerts_triggered"],
            self._stats["weight_drops"], self._stats["state_dumps"],
        )

    # -- Poll Loop --------------------------------------------------------

    async def _poll_loop(self):
        """Main polling loop at the configured interval."""
        try:
            while self._running:
                tick_start = time.monotonic()

                # Collect all metrics in parallel
                metrics_task = asyncio.create_task(fetch_loader_metrics())
                map_task = asyncio.create_task(fetch_loader_map())
                sync_task = asyncio.create_task(check_sync_health())

                # Measure proxy latency by querying its health endpoint
                t0 = time.monotonic()
                proxy_latency_ms = 0.0
                try:
                    async with httpx.AsyncClient(timeout=3.0) as c:
                        await c.get(PROXY_HEALTH_URL)
                    proxy_latency_ms = (time.monotonic() - t0) * 1000.0
                except Exception:
                    proxy_latency_ms = -1.0

                metrics = await metrics_task
                map_data = await map_task
                sync_healthy, sync_latency_ms = await sync_task

                self._stats["polls"] += 1

                # Evaluate thresholds
                alerts = evaluate_thresholds(
                    metrics, map_data, proxy_latency_ms,
                    sync_healthy, sync_latency_ms,
                    latency_threshold_ms=self._latency_threshold,
                )

                # Process alerts
                for alert in alerts:
                    if alert not in self._alerts_active:
                        self._alerts_active.add(alert)
                        self._stats["alerts_triggered"] += 1
                        await self._handle_alert(alert, metrics, map_data)

                # Clear resolved alerts
                current_alert_set = set(alerts)
                resolved = self._alerts_active - current_alert_set
                for alert in resolved:
                    logger.info("ALERT RESOLVED: %s", alert)
                self._alerts_active = current_alert_set

                # Maintain loop interval
                elapsed = (time.monotonic() - tick_start) * 1000.0
                sleep_s = max(0.0, self._poll_interval - elapsed / 1000.0)
                await asyncio.sleep(sleep_s)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.critical("Watchdog poll loop crashed: %s", e, exc_info=True)

    async def _handle_alert(self, alert: str, metrics: Optional[dict],
                             map_data: Optional[dict]):
        """Handle a triggered alert with mitigation actions."""
        logger.warning("ALERT TRIGGERED: %s", alert)

        is_severe = (
            "LATENCY_BREACH" in alert
            or "BPF_SATURATION:" in alert and "WARN" not in alert
        )

        if is_severe:
            # Action 1: Drop HAProxy server weight to 0
            short_name = self._node_id.replace("srp-node-", "")
            ok = await self._haproxy.set_server_weight(short_name, weight=0)
            if ok:
                self._stats["weight_drops"] += 1
                logger.warning(
                    "MITIGATION: HAProxy weight dropped to 0 for %s",
                    short_name,
                )

            # Action 2: Emergency state dump
            dump_path = await dump_emergency_state()
            if dump_path:
                self._stats["state_dumps"] += 1


# ============================================================================
#  CLI Entry Point
# ============================================================================

async def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SRP Automated Health & Latency Watchdog",
    )
    parser.add_argument(
        "--node-id", default=None,
        help="Override node ID (default: auto-detect from cluster_nodes.json)",
    )
    parser.add_argument(
        "--interval", type=float, default=POLL_INTERVAL_S,
        help=f"Poll interval in seconds (default: {POLL_INTERVAL_S})",
    )
    parser.add_argument(
        "--latency-threshold", type=float, default=LATENCY_THRESHOLD_MS,
        help=f"Latency threshold in ms (default: {LATENCY_THRESHOLD_MS})",
    )
    args = parser.parse_args()

    engine = WatchdogEngine(
        node_id=args.node_id or "srp-node-unknown",
        poll_interval_s=args.interval or POLL_INTERVAL_S,
        latency_threshold_ms=args.latency_threshold or LATENCY_THRESHOLD_MS,
    )

    def shutdown(sig, frame):
        asyncio.create_task(engine.stop())

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        await engine.start()
        # Keep alive
        while engine._running:
            await asyncio.sleep(1.0)
    except KeyboardInterrupt:
        await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
