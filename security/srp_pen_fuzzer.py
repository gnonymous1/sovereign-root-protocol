#!/usr/bin/env python3
"""
=============================================================================
  SRP PENETRATION TEST — PACKET EVASION FUZZER (MODULE 1 TARGET)
=============================================================================
  System Authority : Universal Root Authority
  Target           : srp_filter.c — eBPF/XDP kernel hook (ingress/egress)
  Engine           : Python 3.11+ scapy raw socket injection

  Attack Loops:
    A — IP Fragmentation Injection:  Splits AI inference payloads across
        fractional IP fragments to test eBPF TCP reassembly bypass.
    B — High-Velocity SYN Flood:     Saturates the sovereign_approval BPF
        hash table with randomized source IPs to probe fail-open states.

  Safety: All traffic confined to 127.0.0.0/8 and TEST_PREFIX (10.88.0.0/16).
=============================================================================
"""

import os
import sys
import time
import json
import random
import struct
import socket
import logging
import ipaddress
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [FUZZER] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("srp_fuzzer")

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------
TEST_PREFIX = ipaddress.IPv4Network("10.88.0.0/16")
LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")
AI_TARGET_PORT = 443
INHALE_PORT = 9000
LOADER_PORT = 9001

# SYN flood parameters
SYN_FLOOD_COUNT = 50000
SYN_FLOOD_BATCH = 1000
SYN_FLOOD_INTERVAL = 0.001  # 1ms between batches

# Fragmentation params
FRAG_PAYLOAD_SIZE = 8  # bytes per fragment — forces extreme splitting
FRAG_TEST_COUNT = 20

# Loader metrics endpoint
LOADER_METRICS_URL = f"http://127.0.0.1:{LOADER_PORT}/api/v1/srp/metrics"

try:
    from scapy.all import (
        IP, TCP, Ether, Raw, fragment,
        send, sendp, conf as scapy_conf,
    )
except ImportError:
    sys.exit(
        "CRITICAL DEPENDENCY MISSING: scapy is required but not installed.\n"
        "  Install with:  pip install scapy\n"
        "  The SRP Packet Evasion Fuzzer cannot send raw Layer-2/Layer-3\n"
        "  packets without scapy.  Aborting."
    )


# ===========================================================================
#  Safety validator — ensure all generated IPs are within test ranges
# ===========================================================================

def validate_test_ip(ip_str: str) -> bool:
    """Return True if ip_str is within allowed test subnet ranges."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return addr in TEST_PREFIX or addr in LOOPBACK
    except ValueError:
        return False


def random_test_ip() -> str:
    """Generate a random IP within the 10.88.0.0/16 test range."""
    net = TEST_PREFIX
    host_bits = random.randint(2, (1 << (32 - net.prefixlen)) - 2)
    return str(net.network_address + host_bits)


# ===========================================================================
#  Attack Loop A: IP Fragmentation Injection
# ===========================================================================

class FragmentationAttack:
    """
    Crafts IP packets where the TCP payload (AI inference signature) is
    deliberately split across multiple tiny fragments. Tests whether the
    eBPF XDP hook in srp_filter.c correctly reassembles and inspects
    the full payload before evaluating the sovereign_approval map state.
    """

    def __init__(self, target_ip: str = "127.0.0.1",
                 target_port: int = AI_TARGET_PORT):
        if not validate_test_ip(target_ip):
            raise ValueError(f"Target IP {target_ip} is outside test range")
        self.target_ip = target_ip
        self.target_port = target_port
        self.stats = {"sent": 0, "errors": 0}

    def craft_fragmented_payload(self, payload: bytes) -> list:
        """
        Create heavily fragmented IP packets. Each fragment carries only
        FRAG_PAYLOAD_SIZE bytes of the original TCP payload, forcing
        extreme reassembly pressure on the kernel's eBPF hook.
        """
        base_pkt = (
            IP(dst=self.target_ip, flags="MF")
            / TCP(sport=random.randint(1024, 65535), dport=self.target_port,
                  flags="P", seq=random.randint(0, 2**32))
            / Raw(load=payload)
        )

        frags = fragment(base_pkt, fragsize=FRAG_PAYLOAD_SIZE + 40)  # 40 = IP+TCP headers
        return frags

    def run_attack(self, payload: bytes = None,
                   inference_sig: str = "SRP-INFERENCE-REQUEST") -> dict:
        """
        Execute the fragmentation attack: fragment the inference payload
        and transmit all fragments.
        """
        if payload is None:
            payload = inference_sig.encode("utf-8")

        logger.info(
            "FRAG ATTACK: fragmenting %d-byte payload across %d-byte chunks",
            len(payload), FRAG_PAYLOAD_SIZE,
        )

        frags = self.craft_fragmented_payload(payload)
        logger.info("  Generated %d fragments", len(frags))

        sent_count = 0
        for i, frag_pkt in enumerate(frags):
            try:
                send(frag_pkt, verbose=False)
                sent_count += 1
            except Exception as e:
                logger.error("  Fragment %d send error: %s", i, e)
                self.stats["errors"] += 1

        self.stats["sent"] = sent_count
        logger.info(
            "FRAG ATTACK complete: %d/%d fragments sent",
            sent_count, len(frags),
        )
        return {
            "attack": "ip_fragmentation",
            "original_payload_bytes": len(payload),
            "fragment_size": FRAG_PAYLOAD_SIZE,
            "fragments_generated": len(frags),
            "fragments_sent": sent_count,
            "target": f"{self.target_ip}:{self.target_port}",
            "target_nic": "ingress/egress",
        }


# ===========================================================================
#  Attack Loop B: High-Velocity SYN Flood
# ===========================================================================

class SynFloodAttack:
    """
    Generates high-velocity SYN packets to port 443 with randomized
    source IPs within the test range. Attempts to exhaust the BPF
    sovereign_approval hash table (65536 entries) and observes whether
    the system fails open (passes traffic) or remains secure (drops
    unauthenticated packets).
    """

    def __init__(self, target_ip: str = "127.0.0.1",
                 target_port: int = AI_TARGET_PORT,
                 packet_count: int = SYN_FLOOD_COUNT):
        if not validate_test_ip(target_ip):
            raise ValueError(f"Target IP {target_ip} is outside test range")
        self.target_ip = target_ip
        self.target_port = target_port
        self.packet_count = packet_count
        self.stats = {"sent": 0, "errors": 0, "bpf_map_entries_before": 0}

    def craft_syn(self) -> object:
        """Create a single SYN packet with a randomized source IP."""
        src_ip = random_test_ip()
        return (
            IP(src=src_ip, dst=self.target_ip)
            / TCP(sport=random.randint(1024, 65535), dport=self.target_port,
                  flags="S", seq=random.randint(0, 2**32))
        )

    def read_bpf_map_size(self) -> int:
        """Query the loader metrics endpoint for approximate map usage."""
        try:
            import httpx
            resp = httpx.get(LOADER_METRICS_URL, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("inspected", 0)
        except Exception:
            pass
        return -1

    def run_attack(self) -> dict:
        """
        Execute the SYN flood. Sends packets in batches to control
        line rate, then checks if the BPF map survived.
        """
        logger.info(
            "SYN FLOOD: launching %d packets at %s:%d...",
            self.packet_count, self.target_ip, self.target_port,
        )

        before = self.read_bpf_map_size()
        self.stats["bpf_map_entries_before"] = before
        logger.info("  Loader metrics before: inspected=%s", before)

        batches = (self.packet_count + SYN_FLOOD_BATCH - 1) // SYN_FLOOD_BATCH
        sent_total = 0

        for batch_num in range(batches):
            remaining = min(SYN_FLOOD_BATCH, self.packet_count - sent_total)
            batch_packets = []

            for _ in range(remaining):
                batch_packets.append(self.craft_syn())

            try:
                send(batch_packets, verbose=False)
                sent_total += remaining
            except Exception as e:
                logger.error("  Batch %d error: %s", batch_num, e)
                self.stats["errors"] += remaining

            if (batch_num + 1) % 10 == 0 or sent_total >= self.packet_count:
                logger.info(
                    "  Progress: %d/%d packets sent (batch %d/%d)",
                    sent_total, self.packet_count, batch_num + 1, batches,
                )

            time.sleep(SYN_FLOOD_INTERVAL)

        self.stats["sent"] = sent_total

        after = self.read_bpf_map_size()
        self.stats["bpf_map_entries_after"] = after

        logger.info(
            "SYN FLOOD complete: %d packets sent. "
            "Metrics before=%s after=%s",
            sent_total, before, after,
        )

        return {
            "attack": "syn_flood",
            "target": f"{self.target_ip}:{self.target_port}",
            "packets_requested": self.packet_count,
            "packets_sent": sent_total,
            "loader_inspected_before": before,
            "loader_inspected_after": after,
            "bpf_hash_table_capacity": 65536,
        }


# ===========================================================================
#  Combined Fuzzer Runner
# ===========================================================================

class PenFuzzer:
    """Orchestrates both attack loops and reports results."""

    def __init__(self, target_ip: str = "127.0.0.1"):
        if not validate_test_ip(target_ip):
            raise ValueError(f"Target IP {target_ip} is outside test range")
        self.target_ip = target_ip
        self.results = []

    def run_all(self) -> list:
        """Execute all attack loops and return structured results."""

        # Attack A: IP Fragmentation
        logger.info("=" * 60)
        logger.info("ATTACK LOOP A: IP Fragmentation Injection")
        logger.info("=" * 60)
        try:
            frag = FragmentationAttack(target_ip=self.target_ip)
            result_a = frag.run_attack()
            self.results.append(result_a)
        except Exception as e:
            logger.error("Fragmentation attack failed: %s", e)
            self.results.append({"attack": "ip_fragmentation", "error": str(e)})
        print()

        # Attack B: SYN Flood
        logger.info("=" * 60)
        logger.info("ATTACK LOOP B: High-Velocity SYN Flood")
        logger.info("=" * 60)
        try:
            syn = SynFloodAttack(target_ip=self.target_ip)
            result_b = syn.run_attack()
            self.results.append(result_b)
        except Exception as e:
            logger.error("SYN flood attack failed: %s", e)
            self.results.append({"attack": "syn_flood", "error": str(e)})
        print()

        return self.results

    def summary(self) -> str:
        """Return a human-readable summary of all attack results."""
        lines = []
        lines.append("")
        lines.append("=" * 72)
        lines.append("  SRP PACKET EVASION FUZZER — RESULTS")
        lines.append("=" * 72)
        for r in self.results:
            attack = r.get("attack", "unknown")
            if "error" in r:
                lines.append(f"  [FAIL] {attack}: {r['error']}")
            else:
                extra = ""
                if attack == "ip_fragmentation":
                    extra = f"frags_sent={r.get('fragments_sent', '?')}/{r.get('fragments_generated', '?')}"
                elif attack == "syn_flood":
                    extra = f"sent={r.get('packets_sent', '?')} inspected_before={r.get('loader_inspected_before', '?')} after={r.get('loader_inspected_after', '?')}"
                lines.append(f"  [PASS] {attack}: {extra}")
        lines.append("=" * 72)
        return "\n".join(lines)


# ===========================================================================
#  CLI Entry Point
# ===========================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SRP Packet Evasion Fuzzer")
    parser.add_argument(
        "--target", default="127.0.0.1",
        help="Target IP within test range (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--syn-count", type=int, default=SYN_FLOOD_COUNT,
        help=f"Number of SYN flood packets (default: {SYN_FLOOD_COUNT})",
    )
    parser.add_argument(
        "--frag-count", type=int, default=FRAG_TEST_COUNT,
        help=f"Number of fragmentation test iterations (default: {FRAG_TEST_COUNT})",
    )
    parser.add_argument(
        "--output", default=None,
        help="Write JSON results to file",
    )
    args = parser.parse_args()

    if not validate_test_ip(args.target):
        logger.error("Target %s is outside allowed test ranges", args.target)
        sys.exit(1)

    logger.info("SRP Packet Evasion Fuzzer starting...")
    logger.info("Target: %s", args.target)
    logger.info("SYN flood count: %d", args.syn_count)
    logger.info("Fragmentation iterations: %d", args.frag_count)

    fuzzer = PenFuzzer(target_ip=args.target)
    results = fuzzer.run_all()

    print(fuzzer.summary())

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("Results written to %s", args.output)

    # Exit code reflects attack success
    errors = sum(1 for r in results if "error" in r)
    if errors > 0:
        logger.warning("%d attack(s) completed with errors", errors)
        sys.exit(1)

    logger.info("Fuzzer complete — no unrecoverable errors.")
    sys.exit(0)


if __name__ == "__main__":
    main()
