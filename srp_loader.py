# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — MODULE 1: eBPF/XDP LOADER & CONTROLLER
# =============================================================================
#  System Authority : Universal Root Authority
#  Version          : 2026.4.2-Production
#  Engine           : BCC (BPF Compiler Collection) + Python 3.11+
#
#  Purpose:
#    Compiles and loads srp_filter.c as an XDP program attached to a specified
#    network interface. Resolves AI provider endpoints (OpenAI, Anthropic,
#    Google, Cohere) and pre-populates the sovereign_approval BPF hash map
#    with Dormant (0x01 / 0xFF) states.
#
#    Exposes an HTTP control plane on port 9001 allowing the sovereign proxy
#    (srp_proxy.py) to update gatekeeper states in real time without requiring
#    direct BPF syscall access from the proxy process.
#
#  Endpoints (Control Plane — port 9001):
#    PUT /api/v1/srp/state/<ip>     — Set gatekeeper state for an IP
#    GET  /api/v1/srp/state/<ip>    — Read current state for an IP
#    GET  /api/v1/srp/metrics       — Read aggregated packet counters
#    GET  /api/v1/srp/map           — Dump entire approval map snapshot
#    GET  /health                   — Health check
#
#  Architectural References:
#    - srp_filter.c   (kernel-space eBPF program)
#    - agents.md §1   (Sentry — DPI)
#    - workflow.md §1 (Inhale → Transit → Verdict → Exhale → Sync)
# =============================================================================

import os
import sys
import json
import time
import struct
import socket
import signal
import ctypes
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [LOADER:AL-MIR] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("srp_loader")

# ---------------------------------------------------------------------------
# Sovereign Constants
# ---------------------------------------------------------------------------
GATEKEEPER_ACTIVE     = 0x01  # Pass traffic
GATEKEEPER_QUARANTINE = 0xFF  # Drop traffic
GATEKEEPER_DORMANT    = 0x00  # Default unset state
CONTROL_PORT          = 9001
SOVEREIGN_CORE_PORT   = 9000

# AI provider endpoints to intercept
TARGET_AI_ENDPOINTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
]


# ============================================================================
#  BCC eBPF Controller (Linux + root only)
# ============================================================================
class SovereignBPFController:
    """Compiles and manages the srp_filter.c eBPF XDP program via BCC."""

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.bpf = None
        self.approval_map = None
        self.metrics_map = None
        self.endpoint_ips = {}  # hostname -> [ipv4 strings]
        self._lock = threading.Lock()

    def resolve_ai_endpoints(self) -> dict:
        """Resolve all target AI hostnames to their IPv4 addresses."""
        resolved = {}
        for hostname in TARGET_AI_ENDPOINTS:
            try:
                addr_info = socket.getaddrinfo(
                    hostname, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                ips = list(set(info[4][0] for info in addr_info))
                resolved[hostname] = ips
                logger.info("  Resolved %s -> %s", hostname, ips)
            except socket.gaierror as e:
                logger.warning("  DNS resolution failed for %s: %s", hostname, e)
                resolved[hostname] = []
        with self._lock:
            self.endpoint_ips = resolved
        return resolved

    def load_and_attach(self):
        """Compile srp_filter.c via BCC, attach XDP, populate the approval map."""
        from bcc import BPF

        filter_path = os.path.join(os.path.dirname(__file__), "srp_filter.c")
        if not os.path.exists(filter_path):
            raise FileNotFoundError(
                f"srp_filter.c not found at {filter_path}"
            )

        logger.info("Compiling srp_filter.c via BCC...")
        with open(filter_path, "r") as f:
            bpf_source = f.read()

        self.bpf = BPF(text=bpf_source)

        # Attach XDP hook to ingress
        ingress_fn = self.bpf.load_func("sovereign_xdp_ingress", BPF.XDP)
        self.bpf.attach_xdp(self.interface, ingress_fn, 0)
        logger.info("XDP ingress hook attached to '%s'", self.interface)

        # Optionally attach egress hook
        try:
            egress_fn = self.bpf.load_func("sovereign_xdp_egress", BPF.XDP)
            self.bpf.attach_xdp(self.interface, egress_fn, 0)
            logger.info("XDP egress hook attached to '%s'", self.interface)
        except Exception:
            logger.info("Egress hook not attached (optional)")

        # Get reference to the approval hash map
        self.approval_map = self.bpf.get_table("sovereign_approval")
        self.metrics_map = self.bpf.get_table("sovereign_metrics")

        # Pre-populate with resolved AI endpoints
        resolved = self.resolve_ai_endpoints()
        populated = 0
        for hostname, ips in resolved.items():
            for ip_str in ips:
                ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
                key = ctypes.c_uint32(ip_int)
                val = ctypes.c_uint32(GATEKEEPER_DORMANT)
                self.approval_map[key] = val
                populated += 1
                logger.debug(
                    "  Map: %s (%s) -> 0x%02X", ip_str, hostname, GATEKEEPER_DORMANT
                )

        logger.info(
            "Approval map populated: %d entries (%d endpoints)",
            populated, len(resolved),
        )

    def update_state(self, ip_str: str, state: int) -> bool:
        """Update the gatekeeper state for a given IP in the BPF hash map."""
        if self.approval_map is None:
            return False
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            key = ctypes.c_uint32(ip_int)
            val = ctypes.c_uint32(state)
            with self._lock:
                self.approval_map[key] = val
            state_names = {
                GATEKEEPER_DORMANT: "Dormant",
                GATEKEEPER_ACTIVE: "Active",
                GATEKEEPER_QUARANTINE: "Quarantine",
            }
            logger.info(
                "Gatekeeper: %s -> 0x%02X (%s)",
                ip_str, state, state_names.get(state, "Unknown"),
            )
            return True
        except Exception as e:
            logger.error("Failed to update state for %s: %s", ip_str, e)
            return False

    def read_state(self, ip_str: str) -> int:
        """Read the current gatekeeper state for a given IP."""
        if self.approval_map is None:
            return GATEKEEPER_DORMANT
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            key = ctypes.c_uint32(ip_int)
            with self._lock:
                val = self.approval_map.get(key, ctypes.c_uint32(GATEKEEPER_DORMANT))
            return val.value
        except Exception:
            return GATEKEEPER_DORMANT

    def read_metrics(self) -> dict:
        """Read and aggregate per-CPU packet counters."""
        if self.metrics_map is None:
            return {"inspected": 0, "passed": 0, "dropped": 0}
        labels = ["inspected", "passed", "dropped"]
        result = {}
        try:
            for idx, label in enumerate(labels):
                key = ctypes.c_uint32(idx)
                values = self.metrics_map[key]
                total = sum(v.value for v in values)
                result[label] = total
        except Exception as e:
            logger.error("Failed to read metrics: %s", e)
            result = {"inspected": 0, "passed": 0, "dropped": 0}
        return result

    def dump_map(self) -> dict:
        """Dump the entire sovereign_approval map (IP -> state)."""
        if self.approval_map is None:
            return {}
        snapshot = {}
        try:
            for key, val in self.approval_map.items():
                ip_int = key.value
                ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
                snapshot[ip_str] = val.value
        except Exception as e:
            logger.error("Failed to dump map: %s", e)
        return snapshot

    def detach_and_cleanup(self):
        """Detach XDP hook and release BPF resources."""
        if self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                logger.info("XDP hook detached from '%s'", self.interface)
            except Exception as e:
                logger.warning("Error detaching XDP: %s", e)


# ============================================================================
#  Userspace Simulation Controller (explicit opt-in only)
# ============================================================================
class UserspaceSimController:
    """In-memory dict simulation of the eBPF approval map.

    WARNING: This is NOT a real kernel hook. No XDP/eBPF program is loaded.
    No packets are intercepted. This exists ONLY for offline UI testing and
    requires the --enable-unsecure-userspace-simulation flag to activate.
    """

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self._map: dict[str, int] = {}
        self._metrics = {"inspected": 0, "passed": 0, "dropped": 0}
        self._lock = threading.Lock()
        self.endpoint_ips = {}
        logger.critical(
            "INSECURE USERSPACE SIMULATION ACTIVE — no eBPF kernel hooks loaded"
        )

    def resolve_ai_endpoints(self) -> dict:
        resolved = {}
        for hostname in TARGET_AI_ENDPOINTS:
            try:
                addr_info = socket.getaddrinfo(
                    hostname, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                ips = list(set(info[4][0] for info in addr_info))
                resolved[hostname] = ips
                logger.info("  Resolved %s -> %s", hostname, ips)
            except socket.gaierror:
                resolved[hostname] = []
        with self._lock:
            self.endpoint_ips = resolved
        return resolved

    def load_and_attach(self):
        resolved = self.resolve_ai_endpoints()
        with self._lock:
            for hostname, ips in resolved.items():
                for ip_str in ips:
                    self._map[ip_str] = GATEKEEPER_DORMANT
        logger.info(
            "Simulated map populated: %d entries (WARNING: no kernel enforcement)",
            sum(len(v) for v in resolved.values()),
        )

    def update_state(self, ip_str: str, state: int) -> bool:
        with self._lock:
            self._map[ip_str] = state
        state_names = {
            GATEKEEPER_DORMANT: "Dormant",
            GATEKEEPER_ACTIVE: "Active",
            GATEKEEPER_QUARANTINE: "Quarantine",
        }
        logger.info(
            "Gatekeeper (SIM): %s -> 0x%02X (%s) [NO KERNEL EFFECT]",
            ip_str, state, state_names.get(state, "Unknown"),
        )
        return True

    def read_state(self, ip_str: str) -> int:
        with self._lock:
            return self._map.get(ip_str, GATEKEEPER_DORMANT)

    def read_metrics(self) -> dict:
        with self._lock:
            return dict(self._metrics)

    def dump_map(self) -> dict:
        with self._lock:
            return dict(self._map)

    def detach_and_cleanup(self):
        logger.info("Userspace simulation controller cleaned up (no kernel state)")


# ============================================================================
#  HTTP Control Plane Handler
# ============================================================================
class ControlHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the control plane API on port 9001."""

    # Shared reference set by the server
    controller = None
    simulation_flag_active = False  # set True when --enable-unsecure-userspace-simulation used

    def log_message(self, format, *args):
        logger.debug("HTTP %s %s", self.command, self.path)

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length)
        return json.loads(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            mode = "real"
            if self.simulation_flag_active:
                mode = "INSECURE_USERSPACE_SIMULATION"
            return self._send_json(200, {
                "status": "srp_loader_active",
                "interface": self.controller.interface if self.controller else "unknown",
                "mode": mode,
            })

        if path == "/api/v1/srp/metrics":
            metrics = self.controller.read_metrics() if self.controller else {}
            return self._send_json(200, metrics)

        if path == "/api/v1/srp/map":
            snapshot = self.controller.dump_map() if self.controller else {}
            return self._send_json(200, {
                "map_size": len(snapshot),
                "entries": snapshot,
            })

        # GET /api/v1/srp/state/<ip>
        if path.startswith("/api/v1/srp/state/"):
            ip_str = path.split("/api/v1/srp/state/")[-1]
            try:
                socket.inet_aton(ip_str)
            except OSError:
                return self._send_json(400, {"error": "invalid_ip"})
            state = self.controller.read_state(ip_str) if self.controller else GATEKEEPER_DORMANT
            return self._send_json(200, {
                "ip": ip_str,
                "state": state,
                "state_hex": f"0x{state:02X}",
            })

        return self._send_json(404, {"error": "not_found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/v1/srp/state/"):
            ip_str = path.split("/api/v1/srp/state/")[-1]
            try:
                socket.inet_aton(ip_str)
            except OSError:
                return self._send_json(400, {"error": "invalid_ip"})

            body = self._read_body()
            state = body.get("state", GATEKEEPER_DORMANT)
            if state not in (GATEKEEPER_ACTIVE, GATEKEEPER_QUARANTINE, GATEKEEPER_DORMANT):
                return self._send_json(400, {
                    "error": "invalid_state",
                    "valid_states": [GATEKEEPER_ACTIVE, GATEKEEPER_QUARANTINE, GATEKEEPER_DORMANT],
                })

            ok = self.controller.update_state(ip_str, state) if self.controller else False
            if ok:
                return self._send_json(200, {
                    "ip": ip_str,
                    "state": state,
                    "state_hex": f"0x{state:02X}",
                    "updated": True,
                })
            return self._send_json(500, {"error": "state_update_failed"})

        return self._send_json(404, {"error": "not_found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class ControlServer:
    """Threaded HTTP server wrapping the control plane handler."""

    def __init__(self, controller, host: str = "127.0.0.1",
                 port: int = CONTROL_PORT,
                 simulation_active: bool = False):
        ControlHandler.controller = controller
        ControlHandler.simulation_flag_active = simulation_active
        self.server = HTTPServer((host, port), ControlHandler)
        self.host = host
        self.port = port
        self._thread = None

    def start(self):
        logger.info("Control plane listening on %s:%d", self.host, self.port)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        logger.info("Stopping control plane...")
        self.server.shutdown()


# ============================================================================
#  Custom Exception — Kernel Hook Not Available
# ============================================================================
class PlatformNotSupportedError(RuntimeError):
    """Raised when the host OS or environment cannot support real eBPF hooks."""


class KernelHookException(RuntimeError):
    """Raised when BCC/libbpf kernel compilation or attachment fails."""


# ============================================================================
#  Main entry point
# ============================================================================
def create_controller(interface: str = "eth0", allow_simulation: bool = False):
    """Factory: returns real BCC controller or raises on failure.

    The in-memory userspace simulation is ONLY available when
    ``allow_simulation=True`` (corresponding to the explicit CLI flag
    ``--enable-unsecure-userspace-simulation``).  Without that flag,
    any failure to initialise the real eBPF/XDP controller is fatal.
    """
    if sys.platform != "linux":
        if allow_simulation:
            logger.warning("Platform=%s, simulation explicitly allowed via flag",
                           sys.platform)
            return UserspaceSimController(interface=interface)
        raise PlatformNotSupportedError(
            f"Platform '{sys.platform}' does not support eBPF/XDP. "
            f"SRP kernel hooks require Linux. To run in userspace "
            f"simulation mode for offline testing, pass the "
            f"--enable-unsecure-userspace-simulation flag. "
            f"WARNING: simulation does NOT enforce any packet filtering."
        )

    try:
        from bcc import BPF  # noqa: F401
    except ImportError:
        if allow_simulation:
            logger.warning("BCC not installed, simulation explicitly allowed via flag")
            return UserspaceSimController(interface=interface)
        raise KernelHookException(
            "BCC (BPF Compiler Collection) is not installed. "
            f"Install it with your package manager (e.g., "
            f"apt install bpfcc-tools python3-bpfcc). "
            f"To run in userspace simulation mode, pass the "
            f"--enable-unsecure-userspace-simulation flag. "
            f"WARNING: simulation does NOT enforce any packet filtering."
        )

    if os.geteuid() != 0:
        if allow_simulation:
            logger.warning("Not root, simulation explicitly allowed via flag")
            return UserspaceSimController(interface=interface)
        raise KernelHookException(
            "Root privileges are required to attach XDP/eBPF programs. "
            f"Run with sudo. To run in userspace simulation mode, pass "
            f"the --enable-unsecure-userspace-simulation flag. "
            f"WARNING: simulation does NOT enforce any packet filtering."
        )

    logger.info("Linux + root + BCC detected — using real eBPF controller")
    return SovereignBPFController(interface=interface)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SRP eBPF/XDP Loader & Controller")
    parser.add_argument(
        "-i", "--interface", default="eth0",
        help="Network interface to attach XDP hook (default: eth0)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=CONTROL_PORT,
        help=f"Control plane HTTP port (default: {CONTROL_PORT})",
    )
    parser.add_argument(
        "--enable-unsecure-userspace-simulation", action="store_true",
        default=False,
        help="[INSECURE] Use an in-memory dict simulation instead of a real "
             "eBPF/XDP kernel hook. No traffic is actually filtered. "
             "For offline UI testing only.",
    )
    args = parser.parse_args()

    logger.info("=" * 72)
    logger.info("  SOVEREIGN ROOT PROTOCOL — eBPF/XDP LOADER & CONTROLLER")
    logger.info("  Sentry: Activating line-rate DPI")
    logger.info("=" * 72)

    allow_sim = args.enable_unsecure_userspace_simulation
    if allow_sim:
        logger.critical(
            "⚠  --enable-unsecure-userspace-simulation ACTIVATED  ⚠\n"
            "  No kernel-level eBPF hooks will be loaded.\n"
            "  This mode is for OFFLINE UI TESTING ONLY.\n"
            "  REAL-WORLD PACKET ENFORCEMENT IS DISABLED."
        )

    controller = create_controller(args.interface, allow_simulation=allow_sim)
    controller.load_and_attach()

    server = ControlServer(controller, port=args.port,
                           simulation_active=allow_sim)
    server.start()

    def shutdown(sig, frame):
        logger.info("Shutting down...")
        server.stop()
        controller.detach_and_cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Loader active. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
