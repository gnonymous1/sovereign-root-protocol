#!/usr/bin/env bash
# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — UNIVERSAL ONE-TOUCH DEPLOYMENT
# =============================================================================
#  System Authority : Universal Root Authority
#  Version          : 2026.4.2-Production
#
#  Consolidates the entire multi-node SRP initialization sequence into a
#  single execution.  Hooks into software (eBPF/XDP) or hardware (HAProxy /
#  P4) firewall topologies automatically.
#
#  Usage:
#    sudo bash orchestration/deploy_all.sh --mode software
#    sudo bash orchestration/deploy_all.sh --mode hardware
#
#  Phases:
#    1. System validation & kernel hardening (sysctl --system)
#    2. Python virtual environment + dependency installation
#    3. ECDSA P-256 certificate authority trust chain
#    4. systemd service registration & enablement
#    5. Health verification & endpoint banner
#
#  Exit codes:
#    0 — Deploy completed successfully
#    1 — Pre-flight assertion failed
#    2 — Kernel hardening failed
#    3 — Virtual environment setup failed
#    4 — Certificate generation failed
#    5 — Service installation failed
#    6 — Health verification failed
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---- Constants -------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SRP_INSTALL_DIR="${SRP_INSTALL_DIR:-/opt/srp}"
readonly VENV_DIR="${SRP_INSTALL_DIR}/venv"
readonly CERT_DIR="${CERT_DIR:-${SRP_INSTALL_DIR}/certs}"

readonly HARDENING_CONF="${PROJECT_ROOT}/deploy/srp_hardening.conf"
readonly SYSTEMD_UNIT_SRC="${PROJECT_ROOT}/deploy/srp_gateway.service"
readonly SYSTEMD_UNIT_DST="/etc/systemd/system/srp-gateway.service"

readonly CERTS_SCRIPT="${PROJECT_ROOT}/cluster/generate_certs.py"
readonly CLUSTER_CONFIG="${PROJECT_ROOT}/cluster/cluster_nodes.json"
readonly HAPROXY_CFG_SRC="${PROJECT_ROOT}/cluster/haproxy_srp.cfg"
readonly REQUIREMENTS="${PROJECT_ROOT}/requirements.txt"
readonly BOOTSTRAP="${PROJECT_ROOT}/orchestration/bootstrap.sh"

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

log_info()  { echo -e "  [${GREEN}DEPLOY${RESET}] $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo -e "  [${YELLOW}WARN${RESET}] $(date -u +%H:%M:%S) $*"; }
log_fail()  { echo -e "  [${RED}FAIL${RESET}] $(date -u +%H:%M:%S) $*"; }
log_step()  { echo -e "\n  ${CYAN}>>>${RESET} ${BOLD}$*${RESET}"; }
bail()      { log_fail "$*"; exit "${2:-1}"; }

# ---- Argument parsing ------------------------------------------------------
MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode=software)        MODE="software"; shift 1 ;;
        --mode=hardware)        MODE="hardware"; shift 1 ;;
        --mode)                 shift 1
                                if [[ $# -gt 0 ]]; then
                                    MODE="$1"; shift 1
                                fi
                                ;;
        *)                      echo "Usage: $0 --mode <software|hardware>" >&2; exit 1 ;;
    esac
done
if [[ "$MODE" != "software" && "$MODE" != "hardware" ]]; then
    echo "Usage: $0 --mode <software|hardware>" >&2
    exit 1
fi

# =============================================================================
#  PHASE 1 — Pre-flight & system validation
# =============================================================================

log_step "[1/5] System validation & kernel hardening"

# 1a. Must be root
if [[ $EUID -ne 0 ]]; then
    bail "This script must be run as root (sudo)." 1
fi
log_info "User: root (OK)"

# 1b. Kernel version >= 5.10
kernel_ver="$(uname -r | cut -d- -f1 | cut -d. -f1-2)"
major="${kernel_ver%%.*}"
minor="${kernel_ver#*.}"
if [[ "$MODE" == "software" ]]; then
    if [[ "$major" -lt 5 ]] || { [[ "$major" -eq 5 && "$minor" -lt 10 ]]; }; then
        bail "Kernel ${kernel_ver} is too old.  eBPF/XDP requires >= 5.10." 1
    fi
    log_info "Kernel: ${kernel_ver} (eBPF/XDP capable — OK)"
else
    log_info "Kernel: ${kernel_ver} (hardware mode — BPF kernel check bypassed)"
fi

# 1c. Python 3.11+
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' \
    || bail "Python 3.11+ is required (found: $(python3 --version 2>&1))" 1
log_info "Python: $(python3 --version) (OK)"

# 1d. Detect active interface
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
    log_warn "No active network interface detected (proceeding anyway)"
else
    log_info "Interface: ${IFACE} (OK)"
fi

# 1e. Load kernel hardening parameters
if [[ -f "$HARDENING_CONF" ]]; then
    cp "$HARDENING_CONF" /etc/sysctl.d/99-srp-hardening.conf
    sysctl --system > /dev/null 2>&1
    log_info "Kernel hardening: /etc/sysctl.d/99-srp-hardening.conf loaded"
else
    log_warn "srp_hardening.conf not found — skipping kernel tuning"
fi

# =============================================================================
#  PHASE 2 — Python virtual environment
# =============================================================================

log_step "[2/5] Python virtual environment & dependencies"

mkdir -p "$SRP_INSTALL_DIR"

if command -v python3 &>/dev/null; then
    python3 -m venv "$VENV_DIR" || bail "Failed to create venv at ${VENV_DIR}" 3
    log_info "Virtual environment created at ${VENV_DIR}"
else
    bail "python3 not found" 3
fi

if [[ -f "$REQUIREMENTS" ]]; then
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip \
        || log_warn "pip upgrade failed (non-fatal)"
    "$VENV_DIR/bin/pip" install --quiet -r "$REQUIREMENTS" \
        || bail "pip install -r requirements.txt failed" 3
    log_info "Dependencies installed from ${REQUIREMENTS}"
else
    log_warn "requirements.txt not found — skipping pip install"
fi

# Copy project source into install prefix for systemd runtime
mkdir -p "${SRP_INSTALL_DIR}/src"
cp -r "${PROJECT_ROOT}"/* "${SRP_INSTALL_DIR}/src/" 2>/dev/null || true
# Remove unwanted artifacts in the copy
rm -rf "${SRP_INSTALL_DIR}/src/__pycache__" 2>/dev/null || true
log_info "Source copied to ${SRP_INSTALL_DIR}/src/"

# =============================================================================
#  PHASE 3 — Certificate authority trust chain
# =============================================================================

log_step "[3/5] ECDSA P-256 certificate authority trust chain"

if [[ -f "$CERTS_SCRIPT" ]]; then
    mkdir -p "$CERT_DIR"

    # The generate_certs.py script reads/writes cluster_nodes.json relative
    # to its own directory.  We run it from the source tree first, then copy.
    (
        cd "${PROJECT_ROOT}/cluster"
        python3 "$CERTS_SCRIPT" --output-dir "$CERT_DIR" \
            || bail "Certificate generation failed" 4
    ) || bail "Certificate generation sub-shell failed" 4

    log_info "ECDSA P-256 CA + node certificates generated at ${CERT_DIR}"
    ls -1 "$CERT_DIR"/*.pem 2>/dev/null \
        | while IFS= read -r c; do log_info "  Cert: $(basename "$c")"; done
else
    log_warn "generate_certs.py not found — skipping certificate generation"
fi

# =============================================================================
#  PHASE 4 — Service registration
# =============================================================================

log_step "[4/5] systemd service architecture"

if [[ -f "$SYSTEMD_UNIT_SRC" ]]; then
    cp "$SYSTEMD_UNIT_SRC" "$SYSTEMD_UNIT_DST"
    chmod 644 "$SYSTEMD_UNIT_DST"

    # Patch WorkingDirectory to point to install prefix
    sed -i "s|WorkingDirectory=/opt/srp|WorkingDirectory=${SRP_INSTALL_DIR}|g" \
        "$SYSTEMD_UNIT_DST"
    sed -i "s|ExecStart=/usr/bin/python3 /opt/srp/launch.py|ExecStart=${VENV_DIR}/bin/python3 ${SRP_INSTALL_DIR}/src/launch.py|g" \
        "$SYSTEMD_UNIT_DST"

    systemctl daemon-reload
    systemctl enable srp-gateway.service
    systemctl restart srp-gateway.service || log_warn "Service start had warnings"

    log_info "systemd unit: srp-gateway.service installed & enabled"
else
    log_warn "srp_gateway.service not found — skipping systemd installation"
fi

# If hardware mode and HAProxy config exists, install it
if [[ "$MODE" == "hardware" && -f "$HAPROXY_CFG_SRC" ]]; then
    cp "$HAPROXY_CFG_SRC" /etc/haproxy/haproxy.cfg
    if command -v haproxy &>/dev/null; then
        haproxy -c -f /etc/haproxy/haproxy.cfg \
            && log_info "HAProxy config validated" \
            || log_warn "HAProxy config validation had warnings"
        systemctl enable haproxy 2>/dev/null || true
        systemctl restart haproxy 2>/dev/null || log_warn "HAProxy restart failed"
    fi
    log_info "HAProxy configuration installed to /etc/haproxy/haproxy.cfg"
fi

# =============================================================================
#  PHASE 5 — Health verification & banner
# =============================================================================

log_step "[5/5] Health verification & endpoint banner"

sleep 3

# Collect active endpoints
PROXY_STATUS="stopped"
LOADER_STATUS="stopped"
SYNC_STATUS="stopped"

if command -v curl &>/dev/null; then
    curl -sf http://127.0.0.1:9000/health >/dev/null 2>&1 \
        && PROXY_STATUS="running" || true
    curl -sf http://127.0.0.1:9001/health >/dev/null 2>&1 \
        && LOADER_STATUS="running" || true
    curl -sf http://127.0.0.1:9201/health >/dev/null 2>&1 \
        && SYNC_STATUS="running" || true
fi

SERVICE_STATUS="inactive"
systemctl is-active srp-gateway.service &>/dev/null \
    && SERVICE_STATUS="active" || true

echo ""
echo -e "  ${GREEN}====================================================${RESET}"
echo -e "  ${GREEN}  SRP DEPLOYMENT COMPLETE — ${BOLD}NODE READY${RESET}"
echo -e "  ${GREEN}====================================================${RESET}"
echo ""
echo -e "  ${BOLD}Mode:${RESET}              ${MODE}"
echo -e "  ${BOLD}Interface:${RESET}         ${IFACE:-auto}"
echo -e "  ${BOLD}Install prefix:${RESET}    ${SRP_INSTALL_DIR}"
echo -e "  ${BOLD}Python venv:${RESET}       ${VENV_DIR}"
echo -e "  ${BOLD}Certificates:${RESET}      ${CERT_DIR}"
echo ""
echo -e "  ${BOLD}Active Endpoints:${RESET}"
echo -e "    Proxy (HTTP)        127.0.0.1:9000    [${PROXY_STATUS}]"
echo -e "    Loader (HTTP)       127.0.0.1:9001    [${LOADER_STATUS}]"
echo -e "    Sync Notify (HTTP)  127.0.0.1:9201    [${SYNC_STATUS}]"
echo -e "    Sync Mesh (mTLS)    0.0.0.0:9200"
echo -e "    HAProxy Stats       127.0.0.1:1993"
echo ""
echo -e "  ${BOLD}systemd:${RESET}           srp-gateway.service  [${SERVICE_STATUS}]"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "    sudo journalctl -u srp-gateway.service -f"
echo -e "    python3 ${PROJECT_ROOT}/telemetry/srp_monitor.py --verify"
echo -e "    python3 ${PROJECT_ROOT}/orchestration/ignition.py"
echo ""
echo -e "  ${GREEN}====================================================${RESET}"
echo ""

# Final exit code based on critical service health
if [[ "$PROXY_STATUS" != "running" ]]; then
    log_warn "Proxy health check failed — review logs with journalctl"
    exit 6
fi

exit 0
