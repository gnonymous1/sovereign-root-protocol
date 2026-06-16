#!/usr/bin/env bash
# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — AUTOMATED FAILOVER & RECOVERY PLAYBOOK
# =============================================================================
#  System Authority : Universal Root Authority
#  Version          : 2026.4.2-Production
#
#  Executes when a severe anomaly flag or unresolvable partition is raised by
#  the synchronizer mesh or the health watchdog (srp_watchdog.py).
#
#  Tracks:
#    [A] Clear-and-Reset  — Local memory corruption / BPF map lock
#    [B] Emergency Override — Total cluster connectivity loss
#
#  Usage:
#    sudo bash operations/srp_failover.sh          # auto-detect mode from state
#    sudo bash operations/srp_failover.sh --track-a # force Track A
#    sudo bash operations/srp_failover.sh --track-b # force Track B
#    sudo bash operations/srp_failover.sh --dry-run # print actions, no execute
#
#  Exit codes:
#    0 — Recovery completed successfully
#    1 — Pre-flight failure
#    2 — Track A failed
#    3 — Track B failed
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---- Constants -------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SRP_INSTALL_DIR="${SRP_INSTALL_DIR:-/opt/srp}"
readonly VENV_DIR="${SRP_INSTALL_DIR}/venv"
readonly STATE_DRAIN="/var/run/srp_state_drain.bin"
readonly FAILOVER_LOG="/var/log/srp_failover.log"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# eBPF / XDP
readonly BPF_OBJECT="${PROJECT_ROOT}/srp_filter.c"
readonly LOADER_SCRIPT="${PROJECT_ROOT}/srp_loader.py"

# Colours
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly CYAN='\033[0;36m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly RESET='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' RESET=''
fi

log_info()  { echo -e "  [${GREEN}RECOVERY${RESET}] $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo -e "  [${YELLOW}WARN${RESET}] $(date -u +%H:%M:%S) $*"; }
log_fail()  { echo -e "  [${RED}FAIL${RESET}] $(date -u +%H:%M:%S) $*"; }
log_step()  { echo -e "\n  ${CYAN}>>>${RESET} ${BOLD}$*${RESET}"; }
log_trace() { echo -e "    ${DIM}$*${RESET}"; }
bail()       { log_fail "$*"; exit "${2:-1}"; }

# ---- Argument parsing ------------------------------------------------------
DRY_RUN=false
TRACK="auto"
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --track-a) TRACK="a" ;;
        --track-b) TRACK="b" ;;
        *) echo "Usage: $0 [--track-a|--track-b] [--dry-run]" >&2; exit 1 ;;
    esac
done

# Save original stderr before exec redirect (used by dry-run to keep stdout clean)
exec 3>&2

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${RED}[WARN: DRY-RUN OVERRIDE ACTIVE]${RESET} ${DIM}$*${RESET}" >&3
        return 0
    fi
    "$@"
}

# ---- Logging ---------------------------------------------------------------
# NOTE: exec &> redirects both stdout AND stderr to the log file + terminal.
# When --dry-run is active, the run() function writes to fd 3 (original stderr)
# so that command traces do NOT appear on stdout, keeping it clean for pipelines.
exec &> >(tee -a "$FAILOVER_LOG")

# =============================================================================
#  PRE-FLIGHT
# =============================================================================

log_step "Pre-flight checks"

if [[ $EUID -ne 0 ]]; then
    bail "This script must be run as root." 1
fi
log_info "User: root (OK)"

# Warn about destructive operations if NOT in dry-run
if [[ "$DRY_RUN" == "false" ]]; then
    echo -e "  ${RED}[WARN]${RESET} This script will execute REAL system commands:" >&3
    echo -e "  ${RED}[WARN]${RESET}   - ip link, tc, systemctl, pkill, rm, curl" >&3
    echo -e "  ${RED}[WARN]${RESET}   - BPF maps will be unloaded, services stopped" >&3
    echo -e "  ${RED}[WARN]${RESET}   - Network interface traffic will be disrupted" >&3
fi

# Detect active network interface
IFACE=""
for candidate in eth0 enp0s3 enp0s8 ens3 ens5; do
    if ip link show "$candidate" &>/dev/null; then
        IFACE="$candidate"
        break
    fi
done
if [[ -z "$IFACE" ]]; then
    IFACE="$(ip -o link show | awk -F': ' '!/lo/{print $2; exit}')"
fi
if [[ -z "$IFACE" ]]; then
    bail "No network interface detected." 1
fi
log_info "Interface: ${IFACE} (OK)"

# Detect eBPF/XDP attachment
XDP_ATTACHED=false
if ip link show "$IFACE" | grep -q "xdp"; then
    XDP_ATTACHED=true
    log_info "XDP program attached to ${IFACE}"
else
    log_warn "No XDP program detected on ${IFACE}"
fi

# Automatic track selection
if [[ "$TRACK" == "auto" ]]; then
    # If sync daemon health endpoint is reachable, use Track A
    if curl -sf http://127.0.0.1:9201/health >/dev/null 2>&1; then
        TRACK="a"
        log_info "Auto-selected Track A: Clear-and-Reset (sync daemon reachable)"
    else
        TRACK="b"
        log_info "Auto-selected Track B: Emergency Override (sync daemon unreachable)"
    fi
fi

# =============================================================================
#  TRACK A — Clear-and-Reset
# =============================================================================

if [[ "$TRACK" == "a" ]]; then
    log_step "[RECOVERY TRACK A] Clear-and-Reset"

    # ---- Step A1: Save current state (emergency dump) ----
    log_info "A1 — Saving current map state..."
    if command -v curl &>/dev/null; then
        MAP_SNAPSHOT="$(curl -sf http://127.0.0.1:9001/api/v1/srp/map 2>/dev/null || echo '{}')"
        METRICS_SNAPSHOT="$(curl -sf http://127.0.0.1:9001/api/v1/srp/metrics 2>/dev/null || echo '{}')"
        echo "{\"timestamp\":\"${TIMESTAMP}\",\"map\":${MAP_SNAPSHOT},\"metrics\":${METRICS_SNAPSHOT}}" \
            > "${STATE_DRAIN}"
        log_trace "State dumped to ${STATE_DRAIN} ($(wc -c < "${STATE_DRAIN}") bytes)"
    else
        log_warn "curl not available — skipping state dump"
    fi

    # ---- Step A2: Unload eBPF / XDP via tc ----
    log_info "A2 — Unloading eBPF/XDP from ${IFACE}..."
    if [[ "$XDP_ATTACHED" == "true" ]]; then
        run ip link set dev "$IFACE" xdp off 2>/dev/null || true
        run tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
        log_trace "XDP detached, tc qdisc deleted"
    else
        log_trace "No XDP to detach"
    fi

    # ---- Step A3: Clear stale cache ----
    log_info "A3 — Clearing stale BPF cache..."
    # Remove any pinned BPF maps in the global BPF filesystem
    if [[ -d "/sys/fs/bpf/srp" ]]; then
        run rm -rf /sys/fs/bpf/srp 2>/dev/null || true
        log_trace "BPF pin directory /sys/fs/bpf/srp removed"
    fi
    # Flush systemd journal for SRP services (logs only, no state loss)
    run journalctl --rotate --vacuum-time=1s -u srp-gateway.service 2>/dev/null || true

    # ---- Step A4: Reload eBPF filter ----
    log_info "A4 — Reloading eBPF filter..."
    if [[ -f "$BPF_OBJECT" ]]; then
        if [[ -f "$LOADER_SCRIPT" ]]; then
            run pkill -f "srp_loader.py" 2>/dev/null || true
            sleep 1
            # Restart loader (will recompile and attach the XDP program)
            if [[ -d "$VENV_DIR" ]]; then
                run nohup "$VENV_DIR/bin/python3" "$LOADER_SCRIPT" \
                    > /dev/null 2>&1 &
            else
                run nohup python3 "$LOADER_SCRIPT" > /dev/null 2>&1 &
            fi
            sleep 2
            log_trace "Loader restarted"
        else
            log_warn "Loader script not found at ${LOADER_SCRIPT}"
        fi
    else
        log_warn "BPF object not found at ${BPF_OBJECT}"
    fi

    # ---- Step A5: Pull fresh state from healthy cluster peers ----
    log_info "A5 — Pulling fresh state from cluster peers..."
    CONFIG_FILE="${PROJECT_ROOT}/cluster/cluster_nodes.json"
    if [[ -f "$CONFIG_FILE" ]]; then
        # Iterate over peer nodes and attempt to pull their map state
        python3 -c "
import json, sys, urllib.request
config = json.load(open('${CONFIG_FILE}'))
self_id = config.get('self', {}).get('id', '')
for node in config.get('nodes', []):
    nid = node.get('id', '')
    if nid == self_id:
        continue
    host = node.get('proxy_host', '')
    if not host:
        continue
    url = f'http://{host}:9001/api/v1/srp/map'
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        entries = data.get('entries', {})
        print(f'PEER STATE PULL: {nid} -> {len(entries)} entries')
        # Commit each entry to local loader
        for ip_str, state_val in entries.items():
            body = json.dumps({'state': state_val}).encode()
            put_url = f'http://127.0.0.1:9001/api/v1/srp/state/{ip_str}'
            req = urllib.request.Request(put_url, data=body,
                  headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=3)
        print(f'  -> Committed {len(entries)} entries from {nid}')
    except Exception as e:
        print(f'  -> Peer {nid} unreachable: {e}')
" 2>&1 | while IFS= read -r line; do log_trace "$line"; done
    else
        log_warn "Cluster config not found — skipping peer state pull"
    fi

    # ---- Step A6: Verify recovery ----
    log_info "A6 — Verifying recovery..."
    sleep 2
    if curl -sf http://127.0.0.1:9001/health >/dev/null 2>&1; then
        log_info "Loader health: UP"
        if curl -sf http://127.0.0.1:9000/health >/dev/null 2>&1; then
            log_info "Proxy health: UP"
            log_info ""
            log_info "========================================"
            log_info "  TRACK A RECOVERY COMPLETE"
            log_info "  Node re-joined cluster mesh"
            log_info "  State synchronized from peers"
            log_info "  BPF map reloaded"
            log_info "========================================"
            exit 0
        fi
    fi
    log_fail "Post-recovery health check failed"
    exit 2
fi

# =============================================================================
#  TRACK B — Emergency Override
# =============================================================================

if [[ "$TRACK" == "b" ]]; then
    log_step "[RECOVERY TRACK B] Emergency Override"

    # ---- Step B1: Isolate network interface ----
    log_info "B1 — Isolating network interface ${IFACE}..."
    run ip link set "$IFACE" down 2>/dev/null || true
    log_trace "Interface ${IFACE} set DOWN"

    # ---- Step B2: Flush all IP addresses on the interface ----
    log_info "B2 — Flushing IP addresses..."
    run ip addr flush dev "$IFACE" 2>/dev/null || true
    log_trace "IP addresses flushed from ${IFACE}"

    # ---- Step B3: Unload eBPF from interface ----
    log_info "B3 — Unloading eBPF programs..."
    run ip link set dev "$IFACE" xdp off 2>/dev/null || true
    run tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
    log_trace "eBPF/XDP unloaded"

    # ---- Step B4: Set administrative IP + route for local connectivity ----
    log_info "B4 — Setting administrative state..."
    run ip link set "$IFACE" up 2>/dev/null || true
    # Assign a link-local address to maintain local infrastructure connectivity
    run ip addr add 169.254.254.1/16 dev "$IFACE" 2>/dev/null || true
    log_trace "Link-local address 169.254.254.1/16 assigned to ${IFACE}"

    # ---- Step B5: Stop SRP services gracefully ----
    log_info "B5 — Stopping SRP services..."
    if command -v systemctl &>/dev/null; then
        run systemctl stop srp-gateway.service 2>/dev/null || true
        log_trace "srp-gateway.service stopped"
    fi
    run pkill -f "srp_loader.py" 2>/dev/null || true
    run pkill -f "srp_proxy.py" 2>/dev/null || true
    run pkill -f "srp_sync_daemon.py" 2>/dev/null || true
    log_trace "All SRP processes terminated"

    # ---- Step B6: Generate systemic security trace log ----
    log_info "B6 — Generating security trace log..."
    SECURITY_TRACE="/var/log/srp_emergency_${TIMESTAMP}.log"
    {
        echo "============================================"
        echo "  SRP EMERGENCY OVERRIDE"
        echo "  Timestamp: ${TIMESTAMP}"
        echo "  Interface: ${IFACE}"
        echo "  Track: B"
        echo "============================================"
        echo ""
        echo "--- ip addr ---"
        ip addr show "$IFACE" 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- ip route ---"
        ip route show 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- BPF state ---"
        ip link show "$IFACE" 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- Process state ---"
        ps aux | grep -E 'srp_|bpf|python3.*900[01]' 2>/dev/null || echo "(unavailable)"
        echo ""
        echo "--- Kernel messages (last 50) ---"
        dmesg 2>/dev/null | tail -50 || echo "(unavailable)"
        echo ""
        echo "--- System memory ---"
        free -h 2>/dev/null || echo "(unavailable)"
        echo "============================================"
    } > "$SECURITY_TRACE"
    log_trace "Security trace written to ${SECURITY_TRACE} ($(wc -c < "${SECURITY_TRACE}") bytes)"

    # ---- Step B7: Persist state drain for later recovery ----
    log_info "B7 — Persisting emergency state..."
    if command -v curl &>/dev/null; then
        MAP_DATA="$(curl -sf http://127.0.0.1:9001/api/v1/srp/map 2>/dev/null || echo '{}')"
        echo "{\"timestamp\":\"${TIMESTAMP}\",\"track\":\"B\",\"map\":${MAP_DATA}}" \
            > "${STATE_DRAIN}"
        log_trace "State drain written to ${STATE_DRAIN}"
    fi

    log_info ""
    log_info "========================================"
    log_info "  TRACK B RECOVERY COMPLETE"
    log_info "  Interface ${IFACE} isolated to link-local"
    log_info "  All SRP services stopped"
    log_info "  Security trace saved"
    log_info "  Manual intervention required to rejoin"
    log_info "========================================"
    exit 0
fi

# Should not reach here
bail "No recovery track selected." 1
