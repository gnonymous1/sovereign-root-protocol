#!/usr/bin/env python3
"""
===============================================================================
 SOVEREIGN ROOT PROTOCOL (SRP) — MODULE 1: GATEWAY INTERCEPTOR
===============================================================================
 Version          : 2026.4.2-Production
 Engine           : BPF Compiler Collection (BCC) + Inline C eBPF/XDP
 Purpose          : Intercept configured AI endpoint traffic, route validation
                    requests to the SRP proxy on port 9000, and enforce
                    XDP_DROP / XDP_PASS via the sovereign_approval BPF hash map.

 Target AI Endpoints:
   - api.openai.com
   - api.anthropic.com
   - generativelanguage.googleapis.com
   - api.cohere.ai

 Architectural Reference:
   - architecture.md (software gateway topology and enforcement modes)
   - agents.md §1 Sentry (network enforcement layer)
   - workflow.md (request lifecycle)
===============================================================================
"""

import ctypes
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [GATEWAY:SENTRY] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("sovereign_gateway")

# ---------------------------------------------------------------------------
# Sovereign Constants (from architecture.md & agents.md)
# ---------------------------------------------------------------------------
SOVEREIGN_CORE_PORT = 9000
GATEKEEPER_DORMANT = 0x00  # No active validation window
GATEKEEPER_ACTIVE = 0x01  # Approved with audit visibility
GATEKEEPER_FULL = 0x02  # Full approval
GATEKEEPER_ISOLATE = 0xFF  # Quarantine

# AI Provider endpoints to intercept
TARGET_AI_ENDPOINTS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
]

# Compliance thresholds from agents.md Decision Logic Matrix
COMPLIANCE_HIGH = 0.85
COMPLIANCE_AUDIT = 0.60

# ---------------------------------------------------------------------------
# Inline C eBPF/XDP Program
# ---------------------------------------------------------------------------
# This is the raw C source compiled by BCC at runtime. It implements:
#   1. sovereign_approval  — BPF_MAP_TYPE_HASH for per-connection approval state
#   2. sovereign_sockmap   — BPF_MAP_TYPE_SOCKMAP for transparent socket redirect
#   3. sovereign_metrics   — BPF_MAP_TYPE_PERCPU_ARRAY for packet counters
#   4. XDP hook            — Line-rate DROP/PASS based on sovereign_approval map
#   5. Socket redirect     — Transparent proxy to port 9000
# ---------------------------------------------------------------------------

BPF_PROGRAM_SOURCE = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
#include <linux/version.h>

/* =========================================================================
 * SOVEREIGN ROOT PROTOCOL — eBPF MAPS
 * ========================================================================= */

/*
 * sovereign_approval: Per-destination approval state.
 * Key   = __u32 destination IPv4 address
 * Value = __u8  gatekeeper state:
 *           0x00 = Dormant / pending validation
 *           0x01 = Approved with audit visibility
 *           0x02 = Full approval (PASS through)
 *           0xFF = Quarantine (hard DROP)
 */
BPF_HASH(sovereign_approval, __u32, __u8, 1024);

/*
 * sovereign_sockmap: Socket redirection map for transparent proxy.
 * Used by sk_msg programs to redirect established TCP flows
 * to the Sovereign Heart Core listener on port 9000.
 */
BPF_SOCKMAP(sovereign_sockmap, 256);

/*
 * sovereign_metrics: Per-CPU packet counters.
 * Index 0 = total packets inspected
 * Index 1 = packets approved (XDP_PASS)
 * Index 2 = packets dropped (XDP_DROP)
 * Index 3 = packets redirected to Core
 */
BPF_PERCPU_ARRAY(sovereign_metrics, __u64, 4);

/* =========================================================================
 * SOVEREIGN XDP HOOK — LINE-RATE ENFORCEMENT (Sentry)
 * =========================================================================
 * Runs at the NIC driver level. Inspects every inbound/outbound packet,
 * checks the sovereign_approval map, and enforces:
 *   - XDP_DROP for 0xFF (Quarantine)
 *   - XDP_PASS for 0x01 or 0x02 (approved states)
 *   - XDP_TX for 0x00 where transparent validation routing is enabled
 * ========================================================================= */

int sovereign_xdp_hook(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Layer 2: Ethernet Header Validation --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* --- Layer 3: IP Header Validation --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process TCP traffic (AI APIs run over HTTPS/TCP) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* --- Layer 4: TCP Header Validation --- */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Increment total packets inspected */
    __u32 idx_total = 0;
    __u64 *counter = sovereign_metrics.lookup(&idx_total);
    if (counter) {
        (*counter)++;
    }

    /* --- Sentry Deep Packet Inspection: Port 443 targeting --- */
    __u16 dst_port = ntohs(tcp->dest);
    if (dst_port != 443)
        return XDP_PASS;

    /* --- Sovereign Approval Map Lookup --- */
    __u32 dst_ip = ip->daddr;
    __u8 *state = sovereign_approval.lookup(&dst_ip);

    if (state == NULL) {
        /*
         * Unknown destination not in approval map.
         * Default behavior: PASS (non-AI traffic).
         * AI endpoint IPs are pre-populated by userspace.
         */
        return XDP_PASS;
    }

    __u8 gatekeeper_bit = *state;

    if (gatekeeper_bit == 0xFF) {
        /*
         * Quarantine state — hard drop.
         * The gateway has flagged this connection for enforcement.
         */
        __u32 idx_drop = 2;
        __u64 *drop_ctr = sovereign_metrics.lookup(&idx_drop);
        if (drop_ctr) (*drop_ctr)++;
        return XDP_DROP;
    }

    if (gatekeeper_bit == 0x00) {
        /*
         * Dormant state — pending validation.
         * Redirect packet to the local validation proxy when transparent
         * validation routing is enabled.
         */
        __u32 idx_redir = 3;
        __u64 *redir_ctr = sovereign_metrics.lookup(&idx_redir);
        if (redir_ctr) (*redir_ctr)++;

        /*
         * Rewrite destination port to 9000 (SRP proxy)
         * and mark for local delivery via XDP_TX.
         */
        tcp->dest = htons(9000);

        /* Recalculate TCP checksum (simplified incremental) */
        __u32 old_port = htons(443);
        __u32 new_port = htons(9000);
        __u32 csum = (~ntohs(tcp->check) & 0xFFFF) + (~old_port & 0xFFFF) + new_port;
        csum = (csum >> 16) + (csum & 0xFFFF);
        csum += (csum >> 16);
        tcp->check = htons(~csum & 0xFFFF);

        return XDP_TX;
    }

    if (gatekeeper_bit == 0x01 || gatekeeper_bit == 0x02) {
        /*
         * Approved state — PASS.
         * Allow the packet through the gateway path.
         */
        __u32 idx_pass = 1;
        __u64 *pass_ctr = sovereign_metrics.lookup(&idx_pass);
        if (pass_ctr) (*pass_ctr)++;
        return XDP_PASS;
    }

    /* Default: PASS for unrecognized states */
    return XDP_PASS;
}

/* =========================================================================
 * SOVEREIGN SOCKET REDIRECT — TRANSPARENT PROXY HOOK
 * =========================================================================
 * Attached to cgroup/sock_ops and sk_msg to intercept established TCP
 * connections and transparently redirect them through the SOCKMAP to
 * the Sovereign Heart Core on port 9000.
 * ========================================================================= */

int sovereign_sock_ops(struct bpf_sock_ops *skops) {
    __u32 key = 0;

    switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            /*
             * On TCP handshake completion, insert the socket
             * into the sovereign_sockmap for later redirection.
             */
            if (skops->remote_port == htons(443)) {
                sovereign_sockmap.sock_map_update(skops, &key, BPF_ANY);
            }
            break;
    }
    return 0;
}

int sovereign_sk_msg(struct sk_msg_md *msg) {
    /*
     * Redirect all messages on intercepted sockets
     * through the sockmap to the SRP proxy listener.
     */
    __u32 key = 0;
    return sovereign_sockmap.msg_redirect_map(msg, &key, BPF_F_INGRESS);
}
"""

# ---------------------------------------------------------------------------
# Sovereign Gateway Controller (Userspace Python)
# ---------------------------------------------------------------------------


class SovereignGatewayController:
    """
    Userspace controller for the eBPF/XDP Gateway Interceptor.

    Responsibilities:
      1. Load and attach the eBPF XDP program to the target NIC.
      2. Resolve AI endpoint hostnames to IPv4 addresses and populate
         the sovereign_approval BPF hash map with initial Dormant (0x00) state.
      3. Expose a control interface for the SRP proxy
         to update approval states in real time.
      4. Continuously monitor sovereign_metrics for telemetry reporting.
    """

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.bpf = None
        self.running = False
        self.endpoint_ips = {}  # hostname -> [list of IPv4 addresses]
        self._metrics_thread = None
        self._resolve_lock = threading.Lock()

        logger.info("Sovereign Gateway Controller initialized")
        logger.info(f"  Target NIC Interface : {self.interface}")
        logger.info(f"  SRP Proxy Port       : {SOVEREIGN_CORE_PORT}")
        logger.info(f"  Target AI Endpoints  : {len(TARGET_AI_ENDPOINTS)}")

    def resolve_ai_endpoints(self) -> dict:
        """
        Resolve all target AI endpoint hostnames to IPv4 addresses.
        Returns a dict mapping hostname -> list of IPv4 addresses.
        """
        resolved = {}
        for hostname in TARGET_AI_ENDPOINTS:
            try:
                addr_info = socket.getaddrinfo(
                    hostname, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                ips = list(set(info[4][0] for info in addr_info))
                resolved[hostname] = ips
                logger.info(f"  Resolved {hostname} -> {ips}")
            except socket.gaierror as e:
                logger.warning(f"  DNS resolution failed for {hostname}: {e}")
                resolved[hostname] = []

        with self._resolve_lock:
            self.endpoint_ips = resolved
        return resolved

    def load_ebpf_program(self):
        """
        Compile and load the inline C eBPF program via BCC.
        Attaches the XDP hook to the target network interface.
        """
        try:
            from bcc import BPF

            logger.info("Compiling eBPF/XDP program via BCC...")
            self.bpf = BPF(text=BPF_PROGRAM_SOURCE)

            # Attach XDP hook to NIC
            xdp_fn = self.bpf.load_func("sovereign_xdp_hook", BPF.XDP)
            self.bpf.attach_xdp(self.interface, xdp_fn, 0)
            logger.info(f"XDP hook attached to interface '{self.interface}'")

            # Populate sovereign_approval map with resolved AI endpoint IPs
            approval_map = self.bpf.get_table("sovereign_approval")
            resolved = self.resolve_ai_endpoints()

            for hostname, ips in resolved.items():
                for ip_str in ips:
                    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
                    key = ctypes.c_uint32(ip_int)
                    # Initial state: dormant / pending validation (0x00)
                    val = ctypes.c_uint8(GATEKEEPER_DORMANT)
                    approval_map[key] = val
                    logger.info(
                        f"  Map entry: {ip_str} ({hostname}) -> "
                        f"0x{GATEKEEPER_DORMANT:02X} (Dormant)"
                    )

            logger.info(
                f"Sovereign approval map populated with "
                f"{sum(len(v) for v in resolved.values())} entries"
            )

        except ImportError:
            logger.error(
                "BCC library not found. Install with: "
                "apt-get install bpfcc-tools python3-bpfcc"
            )
            raise
        except Exception as e:
            logger.error(f"Failed to load eBPF program: {e}")
            raise

    def update_gatekeeper_state(self, ip_address: str, state: int):
        """
        Update the gateway state for a specific IP in the BPF approval map.

        States:
          0x00 = Dormant / pending validation
          0x01 = Approved with audit visibility
          0x02 = Full approval
          0xFF = Quarantine
        """
        if self.bpf is None:
            logger.error("eBPF program not loaded")
            return False

        try:
            approval_map = self.bpf.get_table("sovereign_approval")
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]
            key = ctypes.c_uint32(ip_int)
            val = ctypes.c_uint8(state)
            approval_map[key] = val

            state_names = {
                0x00: "Dormant",
                0x01: "Approved-Audit",
                0x02: "Approved",
                0xFF: "Quarantine",
            }
            logger.info(
                f"Gateway state update: {ip_address} -> "
                f"0x{state:02X} ({state_names.get(state, 'Unknown')})"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to update gateway state: {e}")
            return False

    def read_metrics(self) -> dict:
        """
        Read per-CPU packet counters from sovereign_metrics map.
        Returns aggregated totals across all CPUs.
        """
        if self.bpf is None:
            return {}

        try:
            metrics_map = self.bpf.get_table("sovereign_metrics")
            labels = ["inspected", "approved", "dropped", "redirected"]
            result = {}

            for idx, label in enumerate(labels):
                key = ctypes.c_uint32(idx)
                values = metrics_map[key]
                total = sum(v.value for v in values)
                result[label] = total

            return result

        except Exception as e:
            logger.error(f"Failed to read metrics: {e}")
            return {}

    def _metrics_reporter(self, interval: float = 5.0):
        """Background thread for periodic metrics telemetry reporting."""
        while self.running:
            metrics = self.read_metrics()
            if metrics:
                logger.info(
                    f"[TELEMETRY] Packets — "
                    f"Inspected: {metrics.get('inspected', 0)} | "
                    f"Approved: {metrics.get('approved', 0)} | "
                    f"Dropped: {metrics.get('dropped', 0)} | "
                    f"Redirected: {metrics.get('redirected', 0)}"
                )
            time.sleep(interval)

    def start(self):
        """
        Start the Sovereign Gateway Interceptor.
        Loads eBPF, attaches hooks, and begins metrics telemetry.
        """
        logger.info("=" * 72)
        logger.info("  SOVEREIGN ROOT PROTOCOL — GATEWAY INTERCEPTOR (THE LUNGS)")
        logger.info("  Sentry: Activating Deep Packet Inspection")
        logger.info("=" * 72)

        self.load_ebpf_program()
        self.running = True

        # Start background metrics reporter
        self._metrics_thread = threading.Thread(
            target=self._metrics_reporter,
            args=(5.0,),
            daemon=True,
        )
        self._metrics_thread.start()

        logger.info("Gateway Interceptor is ACTIVE — monitoring traffic...")

        # Block on signal
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """
        Gracefully shut down the gateway.
        Detach XDP hook and clean up BPF resources.
        """
        logger.info("Shutting down Sovereign Gateway...")
        self.running = False

        if self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                logger.info(f"XDP hook detached from '{self.interface}'")
            except Exception as e:
                logger.warning(f"Error detaching XDP hook: {e}")

        logger.info("Gateway Interceptor shutdown complete.")


# ---------------------------------------------------------------------------
# Simulation Mode (for Windows/non-Linux environments)
# ---------------------------------------------------------------------------


class SovereignGatewaySimulator:
    """
    Simulated Gateway Interceptor for local development on non-Linux systems.

    Emulates the eBPF sovereign_approval map and XDP packet flow using
    pure Python data structures. Provides identical API surface to the
    real SovereignGatewayController for Module 2 (Core) integration.

    The simulator resolves AI endpoints, maintains an in-memory approval
    map, and exposes a control socket on port 9001 for state updates
    from the Sovereign Heart Core.
    """

    def __init__(self):
        self.approval_map = {}  # ip_str -> gatekeeper_state (int)
        self.metrics = {
            "inspected": 0,
            "approved": 0,
            "dropped": 0,
            "redirected": 0,
        }
        self.endpoint_ips = {}
        self.running = False
        self._lock = threading.Lock()

        logger.info("Sovereign Gateway SIMULATOR initialized (non-eBPF mode)")

    def resolve_ai_endpoints(self) -> dict:
        """Resolve AI endpoint hostnames to IPv4 addresses."""
        resolved = {}
        for hostname in TARGET_AI_ENDPOINTS:
            try:
                addr_info = socket.getaddrinfo(
                    hostname, 443, socket.AF_INET, socket.SOCK_STREAM
                )
                ips = list(set(info[4][0] for info in addr_info))
                resolved[hostname] = ips
                logger.info(f"  Resolved {hostname} -> {ips}")
            except socket.gaierror:
                logger.warning(f"  DNS resolution failed for {hostname}")
                resolved[hostname] = []

        self.endpoint_ips = resolved

        # Initialize approval map with Dormant state
        with self._lock:
            for hostname, ips in resolved.items():
                for ip_str in ips:
                    self.approval_map[ip_str] = GATEKEEPER_DORMANT

        return resolved

    def update_gatekeeper_state(self, ip_address: str, state: int) -> bool:
        """Update gateway state for an IP address."""
        state_names = {
            0x00: "Dormant",
            0x01: "Approved-Audit",
            0x02: "Approved",
            0xFF: "Quarantine",
        }
        with self._lock:
            self.approval_map[ip_address] = state

        logger.info(
            f"Gateway state update: {ip_address} -> "
            f"0x{state:02X} ({state_names.get(state, 'Unknown')})"
        )
        return True

    def simulate_packet_inspection(self, dst_ip: str, dst_port: int = 443) -> str:
        """
        Simulate XDP packet inspection logic.

        Returns the XDP verdict: 'XDP_PASS', 'XDP_DROP', or 'XDP_TX'.
        """
        with self._lock:
            self.metrics["inspected"] += 1

            if dst_port != 443:
                self.metrics["approved"] += 1
                return "XDP_PASS"

            state = self.approval_map.get(dst_ip)

            if state is None:
                self.metrics["approved"] += 1
                return "XDP_PASS"

            if state == GATEKEEPER_ISOLATE:
                self.metrics["dropped"] += 1
                return "XDP_DROP"

            if state == GATEKEEPER_DORMANT:
                self.metrics["redirected"] += 1
                return "XDP_TX"

            if state in (GATEKEEPER_ACTIVE, GATEKEEPER_FULL):
                self.metrics["approved"] += 1
                return "XDP_PASS"

            self.metrics["approved"] += 1
            return "XDP_PASS"

    def read_metrics(self) -> dict:
        """Return current packet metrics."""
        with self._lock:
            return dict(self.metrics)

    def get_approval_map_snapshot(self) -> dict:
        """Return a snapshot of the current approval map state."""
        state_names = {
            0x00: "Dormant",
            0x01: "Approved-Audit",
            0x02: "Approved",
            0xFF: "Quarantine",
        }
        with self._lock:
            return {
                ip: {
                    "state_hex": f"0x{state:02X}",
                    "state_name": state_names.get(state, "Unknown"),
                }
                for ip, state in self.approval_map.items()
            }

    def start(self):
        """Start the gateway simulator."""
        logger.info("=" * 72)
        logger.info("  SOVEREIGN ROOT PROTOCOL — GATEWAY SIMULATOR")
        logger.info("  Sentry: Simulation Mode Active (no XDP hook attached)")
        logger.info("=" * 72)

        self.resolve_ai_endpoints()
        self.running = True
        logger.info("Gateway Simulator is ACTIVE — ready for Core integration")

    def stop(self):
        """Stop the gateway simulator."""
        self.running = False
        logger.info("Gateway Simulator shutdown complete.")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------


def create_gateway(interface: str = "eth0"):
    """
    Factory function: returns either the real eBPF controller (Linux + root)
    or the simulation controller (Windows / non-root).
    """
    if sys.platform == "linux" and os.geteuid() == 0:
        try:
            from bcc import BPF  # noqa: F401

            logger.info("Linux + root + BCC detected — using REAL eBPF gateway")
            return SovereignGatewayController(interface=interface)
        except ImportError:
            logger.warning("BCC not installed — falling back to simulator")
            return SovereignGatewaySimulator()
    else:
        logger.info(f"Platform: {sys.platform} — using Gateway Simulator")
        return SovereignGatewaySimulator()


if __name__ == "__main__":
    gateway = create_gateway()

    def signal_handler(sig, frame):
        gateway.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    gateway.start()

    if isinstance(gateway, SovereignGatewaySimulator):
        # Run a quick self-test in simulator mode
        logger.info("\n--- Running Simulator Self-Test ---")
        for hostname, ips in gateway.endpoint_ips.items():
            for ip in ips:
                verdict = gateway.simulate_packet_inspection(ip, 443)
                logger.info(f"  {hostname} ({ip}:443) -> {verdict}")

        # Simulate an approval cycle
        test_ips = []
        for ips in gateway.endpoint_ips.values():
            test_ips.extend(ips)

        if test_ips:
            test_ip = test_ips[0]
            logger.info(f"\n--- Simulating Approval Cycle for {test_ip} ---")
            gateway.update_gatekeeper_state(test_ip, GATEKEEPER_ACTIVE)
            verdict = gateway.simulate_packet_inspection(test_ip, 443)
            logger.info(f"  After ACTIVE: {verdict}")

            gateway.update_gatekeeper_state(test_ip, GATEKEEPER_ISOLATE)
            verdict = gateway.simulate_packet_inspection(test_ip, 443)
            logger.info(f"  After QUARANTINE: {verdict}")

            gateway.update_gatekeeper_state(test_ip, GATEKEEPER_DORMANT)
            verdict = gateway.simulate_packet_inspection(test_ip, 443)
            logger.info(f"  After DORMANT RESET: {verdict}")

        metrics = gateway.read_metrics()
        logger.info(f"\n--- Final Metrics ---")
        logger.info(f"  {json.dumps(metrics, indent=2)}")

        gateway.stop()
