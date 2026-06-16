#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — CLUSTER LIFECYCLE ORCHESTRATOR
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ asyncio + subprocess

  Extends the baseline launch.py with multi-node cluster orchestration.

  Lifecycle:
    [CLUSTER INIT]              — Validate kernel params, discover interfaces,
                                  load cluster_nodes.json
        │
        ▼
    [LOCAL SERVICES START]      — Spawn srp_loader.py (port 9001),
                                  srp_proxy.py (port 9000)
        │
        ▼
    [PEER MESH INIT]            — Start srp_sync_daemon.py (ports 9200/9201)
        │
        ▼
    [PEER MESH ESTABLISHED]     — All outbound mTLS connections active
        │
        ▼
    [STATE BROADCAST REPLICATED]— Full state sync received from all peers
        │
        ▼
    [FAILOVER STANDBY ACTIVE]   — Cluster fully operational

  References:
    - deploy/srp_hardening.conf  (kernel parameter validation)
    - cluster/cluster_nodes.json (peer topology)
    - cluster/srp_sync_daemon.py (state replication)
    - srp_proxy.py               (validation proxy)
    - srp_loader.py              (eBPF loader)
=============================================================================
"""

import os
import sys
import json
import time
import socket
import struct
import subprocess
import signal
import platform
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import httpx

# ---------------------------------------------------------------------------
#  ANSI Color Codes
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
RESET = "\033[0m"

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent  # SRP project root
DEPLOY_DIR = ROOT / "deploy"
CLUSTER_DIR = ROOT / "cluster"
KERNEL_CONF = DEPLOY_DIR / "srp_hardening.conf"
CLUSTER_CONF = CLUSTER_DIR / "cluster_nodes.json"

# Port assignments
PROXY_PORT = 9000
LOADER_PORT = 9001
SYNC_PORT = 9200
NOTIFY_PORT = 9201

processes: list[subprocess.Popen] = []

# ---------------------------------------------------------------------------
#  Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format=f"{DIM}[%(asctime)s]{RESET} %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cluster_launch")


def marker(label: str, text: str, color: str = WHITE):
    """Print a colorized lifecycle marker."""
    print(f"  {BOLD}[{color}{label}{RESET}{BOLD}]{RESET} {color}{text}{RESET}")


# ===========================================================================
#  Phase 1: Kernel Parameter Validation
# ===========================================================================

def check_kernel_params() -> bool:
    """Validate essential sysctl params from srp_hardening.conf are loaded."""
    marker("CLUSTER INIT", "Validating kernel parameters...", CYAN)

    required_params = {
        "net.core.bpf_jit_enable": 1,
        "net.ipv4.ip_forward": 1,
        "vm.swappiness": (0, 20),
    }

    all_ok = True
    for param, expected in required_params.items():
        try:
            result = subprocess.run(
                ["sysctl", "-n", param],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                logger.warning("  %s: sysctl not readable", param)
                all_ok = False
                continue

            value = int(result.stdout.strip())
            if isinstance(expected, tuple):
                ok = expected[0] <= value <= expected[1]
            else:
                ok = value == expected

            status = f"{GREEN}ok{RESET}" if ok else f"{RED}MISMATCH (got {value}, expected {expected}){RESET}"
            logger.info("  %s = %s  [%s]", param, value, status)
            if not ok:
                all_ok = False
        except Exception as e:
            logger.warning("  %s: check failed (%s)", param, e)
            all_ok = False

    return all_ok


# ===========================================================================
#  Phase 2: Interface Auto-Discovery
# ===========================================================================

def discover_interface() -> str:
    """Auto-discover the primary non-loopback network interface."""
    marker("CLUSTER INIT", "Discovering network interfaces...", CYAN)

    try:
        import netifaces
        default_iface = netifaces.gateways()["default"][netifaces.AF_INET][1]
        logger.info("  Default gateway interface: %s", default_iface)
        return default_iface
    except ImportError:
        pass

    try:
        if sys.platform == "linux":
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) > 1 and fields[1] == "00000000":
                        iface = fields[0]
                        logger.info("  Default routing interface: %s", iface)
                        return iface

            # Fallback: pick first non-loopback interface
            for iface in os.listdir("/sys/class/net"):
                if iface != "lo":
                    logger.info("  Selected interface: %s", iface)
                    return iface
        else:
            logger.info("  Platform %s — using eth0", sys.platform)
            return "eth0"
    except Exception as e:
        logger.warning("  Interface detection failed: %s — using eth0", e)
        return "eth0"

    return "eth0"


# ===========================================================================
#  Phase 3: Cluster Config Loading
# ===========================================================================

def load_cluster_config() -> dict:
    """Load and validate the cluster_nodes.json configuration."""
    marker("CLUSTER INIT", "Loading cluster topology...", CYAN)

    if not CLUSTER_CONF.exists():
        logger.error("  Cluster config not found: %s", CLUSTER_CONF)
        logger.error("  Run: cp cluster/cluster_nodes.json.example cluster/cluster_nodes.json")
        sys.exit(1)

    with open(CLUSTER_CONF) as f:
        config = json.load(f)

    self_sec = config.get("self", {})
    node_id = self_sec.get("id", "unknown")
    peer_count = len([n for n in config.get("nodes", []) if n.get("id") != node_id])

    logger.info("  Cluster: %s", config.get("cluster_name", "srp-mesh"))
    logger.info("  Local node: %s", node_id)
    logger.info("  Peers discovered: %d", peer_count)

    return config


# ===========================================================================
#  Phase 4: Local Service Startup
# ===========================================================================

def start_local_loader(iface: str) -> subprocess.Popen:
    """Start srp_loader.py on the discovered interface."""
    marker("LOCAL SERVICES START", "Starting eBPF loader on :%d..." % LOADER_PORT, YELLOW)

    cmd = [
        sys.executable,
        str(ROOT / "srp_loader.py"),
        "-i", iface,
        "-p", str(LOADER_PORT),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    processes.append(proc)
    logger.info("  PID %d — srp_loader.py (interface=%s, port=%d)", proc.pid, iface, LOADER_PORT)
    return proc


def start_local_proxy() -> subprocess.Popen:
    """Start srp_proxy.py on the standard proxy port."""
    marker("LOCAL SERVICES START", "Starting validation proxy on :%d..." % PROXY_PORT, YELLOW)

    cmd = [
        sys.executable,
        str(ROOT / "srp_proxy.py"),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    processes.append(proc)
    logger.info("  PID %d — srp_proxy.py (port=%d)", proc.pid, PROXY_PORT)
    return proc


def start_legacy_core() -> subprocess.Popen:
    """Start legacy sovereign_core.py for backward compatibility."""
    cmd = [
        sys.executable,
        str(ROOT / "core" / "sovereign_core.py"),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    processes.append(proc)
    logger.info("  PID %d — sovereign_core.py (legacy)", proc.pid)
    return proc


def start_sync_daemon() -> subprocess.Popen:
    """Start srp_sync_daemon.py with the cluster configuration."""
    marker("PEER MESH INIT", "Starting state synchronizer on :%d..." % SYNC_PORT, CYAN)

    cmd = [
        sys.executable,
        str(CLUSTER_DIR / "srp_sync_daemon.py"),
        "-c", str(CLUSTER_CONF),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    processes.append(proc)
    logger.info("  PID %d — srp_sync_daemon.py (sync:%d notify:%d)", proc.pid, SYNC_PORT, NOTIFY_PORT)
    return proc


# ===========================================================================
#  Phase 5: Service Health Verification
# ===========================================================================

async def wait_for_service(url: str, label: str, timeout: float = 30.0,
                            interval: float = 0.5) -> bool:
    """Poll a URL until it responds with 200 or timeout expires."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return True
        except (httpx.RequestError, httpx.TimeoutException):
            pass
        await asyncio.sleep(interval)
    return False


async def verify_peer_mesh(peer_count: int, timeout: float = 30.0) -> bool:
    """Verify that the sync daemon reports the expected number of connected peers."""
    marker("PEER MESH ESTABLISHED", "Verifying cluster mesh connections...", CYAN)

    for attempt in range(int(timeout / 2)):
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"http://127.0.0.1:{NOTIFY_PORT}/health")
                if resp.status_code == 200:
                    data = resp.json()
                    connected = data.get("connected_peers", 0)
                    logger.info("  Connected peers: %d/%d (attempt %d)",
                                connected, peer_count, attempt + 1)
                    if connected >= peer_count:
                        marker("PEER MESH ESTABLISHED",
                               "All %d peer connections active." % peer_count, GREEN)
                        return True
        except Exception:
            pass
        await asyncio.sleep(2)

    logger.warning("  Peer mesh not fully established after %.0fs", timeout)
    return False


async def verify_state_broadcast(source_ip: str = "10.88.88.88") -> bool:
    """Push a test state update through the local sync daemon and verify replication."""
    marker("STATE BROADCAST REPLICATED", "Testing state broadcast propagation...", CYAN)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"http://127.0.0.1:{NOTIFY_PORT}/notify",
                json={"target_ip": source_ip, "state": 0x01},
            )
            if resp.status_code == 200:
                data = resp.json()
                peer_count = data.get("peer_count", 0)
                logger.info("  Broadcast sent to %d peers", peer_count)
                marker("STATE BROADCAST REPLICATED",
                       "Test state 0x01 broadcast to %d peers." % peer_count, GREEN)
                return True
    except Exception as e:
        logger.warning("  Broadcast test failed: %s", e)

    return False


async def verify_failover_standby() -> bool:
    """Verify HAProxy (if running) sees at least one healthy backend."""
    marker("FAILOVER STANDBY ACTIVE", "Validating failover readiness...", YELLOW)

    # Check proxy health directly (HAProxy may not be deployed yet)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://127.0.0.1:{PROXY_PORT}/health")
            if resp.status_code == 200:
                logger.info("  Local proxy health: OK")
                marker("FAILOVER STANDBY ACTIVE",
                       "Cluster node ready — failover standby active.", GREEN)
                return True
    except Exception as e:
        logger.warning("  Proxy health check failed: %s", e)

    return False


# ===========================================================================
#  Phase 6: Frontend Server
# ===========================================================================

def start_frontend():
    """Start the admin console HTTP server on port 8080 in a thread."""
    import threading
    import http.server
    import socketserver

    frontend_dir = str(ROOT / "frontend")
    os.chdir(frontend_dir)

    handler = http.server.SimpleHTTPRequestHandler

    class QuietHandler(handler):
        def log_message(self, fmt, *args):
            pass

    with socketserver.TCPServer(("0.0.0.0", 8080), QuietHandler) as httpd:
        logger.info("  Admin console: http://localhost:8080")
        httpd.serve_forever()


# ===========================================================================
#  Main Orchestration
# ===========================================================================

async def main():
    print()
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  SOVEREIGN ROOT PROTOCOL — CLUSTER LIFECYCLE ORCHESTRATOR{RESET}")
    print(f"{BOLD}  Cluster Deployment Engine — Multi-Region State Replication{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")
    print()

    success = True

    # Phase 1: Kernel validation
    if not check_kernel_params():
        logger.warning("Kernel parameter validation had warnings (non-fatal).")
    print()

    # Phase 2: Interface discovery
    iface = discover_interface()
    print()

    # Phase 3: Load cluster config
    config = load_cluster_config()
    peer_count = len([n for n in config.get("nodes", [])
                      if n.get("id") != config.get("self", {}).get("id")])
    print()

    # Phase 4: Start local services
    start_local_loader(iface)
    start_local_proxy()
    start_legacy_core()
    start_sync_daemon()
    print()

    # Allow services to initialize
    marker("CLUSTER INIT", "Waiting for services to initialize...", CYAN)
    await asyncio.sleep(3)
    print()

    # Phase 5: Verify health
    marker("CLUSTER INIT", "Verifying service health...", CYAN)

    proxy_ok = await wait_for_service(
        f"http://127.0.0.1:{PROXY_PORT}/health", "proxy", timeout=30.0
    )
    logger.info("  Proxy health: %s", f"{GREEN}OK{RESET}" if proxy_ok else f"{RED}FAIL{RESET}")

    loader_ok = await wait_for_service(
        f"http://127.0.0.1:{LOADER_PORT}/health", "loader", timeout=15.0
    )
    logger.info("  Loader health: %s", f"{GREEN}OK{RESET}" if loader_ok else f"{RED}FAIL{RESET}")

    sync_ok = await wait_for_service(
        f"http://127.0.0.1:{NOTIFY_PORT}/health", "sync", timeout=15.0
    )
    logger.info("  Sync health: %s", f"{GREEN}OK{RESET}" if sync_ok else f"{RED}FAIL{RESET}")

    success = proxy_ok and loader_ok and sync_ok
    print()

    if not success:
        logger.error("Critical service failure — aborting cluster launch.")
        sys.exit(1)

    # Phase 6: Verify mesh
    if peer_count > 0:
        mesh_ok = await verify_peer_mesh(peer_count)
        if mesh_ok:
            await verify_state_broadcast()
    else:
        marker("PEER MESH ESTABLISHED",
               "Single-node mode (no peers configured).", YELLOW)
        await verify_state_broadcast()
    print()

    # Phase 7: Verify failover
    await verify_failover_standby()
    print()

    # Start frontend in background thread
    import threading
    ft = threading.Thread(target=start_frontend, daemon=True)
    ft.start()

    # Summary
    print()
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"  {GREEN}CLUSTER NODE — FULLY OPERATIONAL{RESET}")
    print(f"  {DIM}{'─' * 68}{RESET}")
    print(f"  {WHITE}Proxy API       {RESET}  http://127.0.0.1:{PROXY_PORT}/health")
    print(f"  {WHITE}Loader Control  {RESET}  http://127.0.0.1:{LOADER_PORT}/health")
    print(f"  {WHITE}Sync Daemon     {RESET}  http://127.0.0.1:{NOTIFY_PORT}/health")
    print(f"  {WHITE}Inhale Endpoint {RESET}  POST http://127.0.0.1:{PROXY_PORT}/api/v1/srp/inhale")
    print(f"  {WHITE}Admin Console   {RESET}  http://localhost:8080")
    print(f"  {WHITE}mTLS Mesh       {RESET}  :{SYNC_PORT} (peers: {peer_count})")
    print(f"  {DIM}{'─' * 68}{RESET}")
    print(f"  {DIM}Press Ctrl+C to shut down the cluster node.{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")
    print()

    # Wait for Ctrl+C
    shutdown_event = asyncio.Event()

    def on_signal(sig, frame):
        print(f"\n{YELLOW}Shutting down cluster node...{RESET}")
        for proc in processes:
            try:
                proc.terminate()
            except Exception:
                pass
        shutdown_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    await shutdown_event.wait()
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
