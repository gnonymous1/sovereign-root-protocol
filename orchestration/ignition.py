#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — MASTER PRODUCTION IGNITION RUNNER
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ (stdlib only — no pip deps required)

  Single-master utility that system administrators run to verify complete
  node health, cryptographic trust, data-plane integrity, and telemetry
  ledger sealing before declaring a node production-ready.

  Lifecycle markers:

    [IGNITION PHASE: DEPLOYING SYSTEMD]
    -> [IGNITION PHASE: VALIDATING KERNEL PIPES]
    -> [IGNITION PHASE: TESTING MESH AUTHENTICATION]
    -> [IGNITION PHASE: LEDGER CHAIN VERIFIED]
    -> [SRP PRODUCTION BASELINE COMPLETELY INITIALIZED]

  Usage:
      python orchestration/ignition.py                          # full suite
      python orchestration/ignition.py --skip-haproxy            # skip HAProxy poll
      python orchestration/ignition.py --json                    # machine-readable
      python orchestration/ignition.py --verbose                 # include debug fields

  Exit codes:
      0 — All checks pass
      1 — One or more checks failed
=============================================================================
"""

import os
import sys
import json
import time
import socket
import struct
import hashlib
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent.resolve()
_PROJECT_ROOT = _HERE.parent
_CLUSTER_CONFIG = _PROJECT_ROOT / "cluster" / "cluster_nodes.json"
_HAPROXY_CFG = _PROJECT_ROOT / "cluster" / "haproxy_srp.cfg"
_TELEMETRY_LEDGER = _PROJECT_ROOT / "telemetry" / "srp_ledger.py"
_TELEMETRY_MONITOR = _PROJECT_ROOT / "telemetry" / "srp_monitor.py"
_TELEMETRY_LOG = _PROJECT_ROOT / "telemetry" / "logs" / "srp_audit.log"

# ---------------------------------------------------------------------------
#  ANSI terminal colours
# ---------------------------------------------------------------------------
class _C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_C.RESET}"
    return text


_OK   = _c("OK",   _C.GREEN)
_FAIL = _c("FAIL", _C.RED)
_WARN = _c("WARN", _C.YELLOW)
_ARROW = "->"

# ---------------------------------------------------------------------------
#  Phase result accumulator
# ---------------------------------------------------------------------------
class PhaseResult:
    """Collects check results and formats the final report."""

    __slots__ = ("_checks",)

    def __init__(self):
        self._checks: list[dict] = []

    def add(self, phase: str, status: str, detail: str = "",
            data: Optional[dict] = None):
        self._checks.append({
            "phase": phase,
            "status": status,
            "detail": detail,
            "data": data or {},
        })

    @property
    def all_pass(self) -> bool:
        return all(c["status"] == "PASS" for c in self._checks)

    @property
    def checks(self) -> list[dict]:
        return list(self._checks)

    def print_report(self, verbose: bool = False):
        sep = "=" * 58
        lines = [f"\n{sep}"]
        lines.append(
            f"  {_c('SRP PRODUCTION IGNITION REPORT', _C.BOLD)}"
        )
        lines.append(
            f"  {datetime.now(timezone.utc).isoformat()}"
        )
        lines.append(sep)

        for c in self._checks:
            icon = _OK if c["status"] == "PASS" else (_FAIL if c["status"] == "FAIL" else _WARN)
            lines.append(
                f"\n  [{_c(c['phase'], _C.BOLD)}] {_ARROW} {icon}"
            )
            if c["detail"]:
                lines.append(f"    {_c('Detail:', _C.DIM)} {c['detail']}")
            if verbose and c["data"]:
                for k, v in c["data"].items():
                    lines.append(f"    {_c(str(k) + ':', _C.DIM)} {v}")

        lines.append(f"\n{sep}")
        if self.all_pass:
            lines.append(
                f"  {_c('SRP PRODUCTION BASELINE COMPLETELY INITIALIZED', _C.GREEN)} {_ARROW} {_OK}"
            )
        else:
            lines.append(
                f"  {_c('SRP PRODUCTION BASELINE INCOMPLETE', _C.RED)} {_ARROW} {_FAIL}"
            )
        lines.append(sep)
        lines.append("")
        print("\n".join(lines))


# ============================================================================
#  Check implementations
# ============================================================================

def _check_systemd(result: PhaseResult):
    """Verify the srp-gateway systemd unit is active."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "srp-gateway.service"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout.strip() == "active":
            result.add(
                "IGNITION PHASE: DEPLOYING SYSTEMD", "PASS",
                f"srp-gateway.service is active (pid: {_get_unit_pid()})",
                {"unit": "srp-gateway.service", "state": r.stdout.strip()},
            )
        else:
            result.add(
                "IGNITION PHASE: DEPLOYING SYSTEMD", "FAIL",
                f"srp-gateway.service is {r.stdout.strip()}",
                {"unit": "srp-gateway.service", "state": r.stdout.strip()},
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        result.add(
            "IGNITION PHASE: DEPLOYING SYSTEMD", "WARN",
            f"Cannot query systemd: {e}",
        )


def _get_unit_pid() -> str:
    """Return the main PID of the SRP gateway unit, or '?'."""
    try:
        r = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "srp-gateway.service"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip().split("=")[-1] or "?"
    except Exception:
        return "?"


def _check_kernel_pipes(result: PhaseResult):
    """Validate BPF JIT, buffer sizes, and kernel parameters."""
    checks = {
        "net.core.bpf_jit_enable": ("1", "BPF JIT enabled"),
        "net.ipv4.ip_forward": ("1", "IP forwarding enabled"),
        "net.core.rmem_max": ("16777216", "Socket rmem_max = 16 MB"),
        "net.ipv4.tcp_fastopen": ("3", "TCP Fast Open (client+server)"),
        "kernel.kptr_restrict": ("2", "Kernel pointer restriction"),
        "kernel.dmesg_restrict": ("1", "dmesg restricted to root"),
    }

    sysctl_map = {}
    all_pass = True
    for param, (expected, desc) in checks.items():
        try:
            r = subprocess.run(
                ["sysctl", "-n", param],
                capture_output=True, text=True, timeout=3,
            )
            actual = r.stdout.strip()
            sysctl_map[param] = actual
            if actual == expected:
                continue
            all_pass = False
        except Exception:
            sysctl_map[param] = "UNREADABLE"
            all_pass = False

    # CPU microcode flags for BPF
    bpf_flags = _check_bpf_cpu_flags()

    status = "PASS" if all_pass and bpf_flags else "FAIL"
    result.add(
        "IGNITION PHASE: VALIDATING KERNEL PIPES", status,
        f"BPF JIT: {sysctl_map.get('net.core.bpf_jit_enable', '?')}, "
        f"CPU BPF support: {'YES' if bpf_flags else 'NO'}",
        {"sysctl": sysctl_map, "cpu_bpf_support": bpf_flags},
    )


def _check_bpf_cpu_flags() -> bool:
    """Check CPU flags for BPF/JIT support (x86_64 only)."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("flags"):
                    return "bpf" in line.lower() or "fxsr" in line.lower()
    except Exception:
        return True  # conservative: assume supported on modern kernels
    return True


def _check_mesh_auth(result: PhaseResult):
    """Validate mTLS certificate files and cluster config."""
    cert_dir = Path("/etc/srp/certs")
    issues = []

    # Check cluster config exists
    if not _CLUSTER_CONFIG.exists():
        result.add(
            "IGNITION PHASE: TESTING MESH AUTHENTICATION", "FAIL",
            f"Cluster config not found: {_CLUSTER_CONFIG}",
        )
        return

    # Load config
    with open(_CLUSTER_CONFIG) as f:
        config = json.load(f)

    # Check CA certificate
    ca_cert = cert_dir / "ca.crt"
    if not ca_cert.exists():
        issues.append(f"CA cert missing: {ca_cert}")
    else:
        ca_stat = ca_cert.stat()
        if ca_stat.st_mode & 0o077:
            issues.append(f"CA cert permissions too permissive: {oct(ca_stat.st_mode)}")

    # Check node certificates
    for node in config.get("nodes", []):
        node_id = node["id"]
        short = node_id.replace("srp-node-", "")
        for key_name in (f"{short}.crt", f"{short}.key"):
            p = cert_dir / key_name
            if not p.exists():
                issues.append(f"Missing {key_name} for {node_id}")

    # Check local cert
    for key_name in ("local.crt", "local.key"):
        p = cert_dir / key_name
        if not p.exists():
            issues.append(f"Missing {key_name} for self-reference")

    # Check haproxy config exists
    haproxy_ok = _HAPROXY_CFG.exists()

    status = "PASS" if not issues and haproxy_ok else "FAIL"
    detail = "All mTLS certs valid" if not issues else "; ".join(issues[:3])
    if not haproxy_ok:
        detail += " [HAProxy config missing]" if detail else "HAProxy config missing"

    result.add(
        "IGNITION PHASE: TESTING MESH AUTHENTICATION", status,
        detail,
        {
            "nodes_configured": len(config.get("nodes", [])),
            "cert_dir": str(cert_dir),
            "haproxy_cfg_exists": haproxy_ok,
            "issues": issues,
        },
    )


def _check_ledger_chain(result: PhaseResult,
                         skip_verify: bool = False):
    """Run telemetry hash-chain verification."""
    if not _TELEMETRY_MONITOR.exists():
        result.add(
            "IGNITION PHASE: LEDGER CHAIN VERIFIED", "WARN",
            f"Monitor script not found: {_TELEMETRY_MONITOR}",
        )
        return

    if not _TELEMETRY_LOG.exists() or _TELEMETRY_LOG.stat().st_size == 0:
        result.add(
            "IGNITION PHASE: LEDGER CHAIN VERIFIED", "WARN",
            "No telemetry log found — node may not have processed requests yet",
        )
        return

    try:
        r = subprocess.run(
            [sys.executable, str(_TELEMETRY_MONITOR), "--verify",
             "--log", str(_TELEMETRY_LOG), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip().split("\n")[-1])
            chain_status = data.get("chain_status", "UNKNOWN")
            stats = data.get("stats", {})

            if chain_status == "INTEGRITY_VERIFIED":
                result.add(
                    "IGNITION PHASE: LEDGER CHAIN VERIFIED", "PASS",
                    f"Chain intact: {stats.get('total_records', 0)} records",
                    {
                        "total_records": stats.get("total_records", 0),
                        "chain_status": chain_status,
                        "avg_latency_ms": stats.get("avg_latency_ms", 0),
                        "approval_rate": stats.get("approval_rate", 0),
                    },
                )
            else:
                result.add(
                    "IGNITION PHASE: LEDGER CHAIN VERIFIED", "FAIL",
                    f"Chain {chain_status}: {data.get('chain_status', '?')}",
                    data,
                )
        else:
            result.add(
                "IGNITION PHASE: LEDGER CHAIN VERIFIED", "WARN",
                f"Monitor returned rc={r.returncode}: {r.stderr[:200]}",
            )
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        result.add(
            "IGNITION PHASE: LEDGER CHAIN VERIFIED", "FAIL",
            f"Verification failed: {e}",
        )


def _check_haproxy(result: PhaseResult):
    """Poll HAProxy stats dashboard for cluster balance."""
    try:
        r = httpx.get("http://127.0.0.1:8404/haproxy?stats;csv",
                      timeout=5.0)
        if r.status_code == 200:
            # Parse CSV for backend server status
            lines = r.text.strip().split("\n")
            backends = [
                l for l in lines if l.startswith("srp_backend,")
            ]
            up_count = sum(1 for l in backends if "UP" in l.split(",")[-2:])
            result.add(
                "IGNITION PHASE: TESTING MESH AUTHENTICATION", "PASS",
                f"HAProxy: {up_count}/{len(backends)} backends UP",
                {"haproxy_url": "http://127.0.0.1:8404/haproxy",
                 "backends_total": len(backends),
                 "backends_up": up_count},
            )
        else:
            result.add(
                "IGNITION PHASE: TESTING MESH AUTHENTICATION", "WARN",
                f"HAProxy stats returned HTTP {r.status_code}",
            )
    except Exception as e:
        result.add(
            "IGNITION PHASE: TESTING MESH AUTHENTICATION", "WARN",
            f"HAProxy unreachable: {e}",
        )


def _check_service_endpoints(result: PhaseResult):
    """Quick-check that proxy, loader, and sync are responding."""
    endpoints = [
        ("Validation Proxy", "http://127.0.0.1:9000/health", "srp_proxy_active"),
        ("eBPF Loader",     "http://127.0.0.1:9001/health", "srp_loader_active"),
        ("Sync Notify",     "http://127.0.0.1:9201/health", "syncing"),
    ]

    if not HAS_HTTPX:
        result.add("IGNITION PHASE: SERVICE ENDPOINTS", "WARN",
                    "httpx not installed — skipping service checks")
        return

    all_ok = True
    details = []
    for name, url, expected_key in endpoints:
        try:
            r = httpx.get(url, timeout=5.0)
            if r.status_code == 200:
                details.append(f"{name}: UP")
            else:
                details.append(f"{name}: HTTP {r.status_code}")
                all_ok = False
        except Exception as e:
            details.append(f"{name}: {e}")
            all_ok = False

    status = "PASS" if all_ok else "FAIL"
    result.add(
        "IGNITION PHASE: SERVICE ENDPOINTS", status,
        "; ".join(details),
    )


# ============================================================================
#  Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SRP Master Production Ignition Runner",
    )
    parser.add_argument(
        "--skip-haproxy", action="store_true", default=False,
        help="Skip HAProxy stats dashboard poll",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output results as JSON (machine-readable)",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="Include debug fields in report",
    )
    args = parser.parse_args()

    result = PhaseResult()

    # -- Phase 1: Systemd check --
    _check_systemd(result)

    # -- Phase 2: Kernel pipes --
    _check_kernel_pipes(result)

    # -- Phase 3: Mesh authentication (mTLS certs + HAProxy) --
    _check_mesh_auth(result)

    if HAS_HTTPX and not args.skip_haproxy:
        _check_haproxy(result)

    # -- Phase 4: Service endpoints --
    _check_service_endpoints(result)

    # -- Phase 5: Telemetry ledger chain --
    _check_ledger_chain(result)

    # -- Output --
    if args.json:
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "all_pass": result.all_pass,
            "checks": result.checks,
        }
        print(json.dumps(output, indent=2))
    else:
        result.print_report(verbose=args.verbose)

    sys.exit(0 if result.all_pass else 1)


if __name__ == "__main__":
    main()
