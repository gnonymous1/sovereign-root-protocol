#!/usr/bin/env bash
# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — BARE-METAL BOOTSTRAP
# =============================================================================
#  System Authority : Universal Root Authority
#  Version          : 2026.4.2-Production
#
#  Lightweight, universal environment initialiser for Linux bare-metal SRP.
#  Designed to be run once on a clean OS installation.
#
#  Usage:
#    sudo bash orchestration/bootstrap.sh [--skip-certs] [--skip-venv]
#
#  Exit codes:
#    0  — Bootstrap completed successfully
#    1  — Pre-flight assertion failed (not root, wrong kernel, missing interface)
#    2  — Package installation failed
#    3  — Python virtual environment setup failed
#    4  — Certificate generation failed
#    5  — Service installation failed
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---- Constants -------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SRP_INSTALL_DIR="${SRP_INSTALL_DIR:-/opt/srp}"
readonly CERT_DIR="${CERT_DIR:-/etc/srp/certs}"
readonly VENV_DIR="${SRP_INSTALL_DIR}/venv"
readonly HARDENING_CONF="${PROJECT_ROOT}/deploy/srp_hardening.conf"
readonly SYSTEMD_UNIT="${PROJECT_ROOT}/deploy/srp_gateway.service"
readonly SYSTEMD_TARGET="/etc/systemd/system/srp-gateway.service"

# Colours
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

log_info()  { echo -e "  [${GREEN}BOOT${RESET}] $*"; }
log_warn()  { echo -e "  [${YELLOW}WARN${RESET}] $*"; }
log_fail()  { echo -e "  [${RED}FAIL${RESET}] $*"; }
log_step()  { echo -e "\n  ${CYAN}-->${RESET} ${BOLD}$*${RESET}"; }

# ---- Argument parsing ------------------------------------------------------
SKIP_CERTS=false
SKIP_VENV=false
for arg in "$@"; do
    case "$arg" in
        --skip-certs) SKIP_CERTS=true ;;
        --skip-venv)  SKIP_VENV=true  ;;
        *) echo "Usage: $0 [--skip-certs] [--skip-venv]"; exit 1 ;;
    esac
done

# =============================================================================
#  PRE-FLIGHT
# =============================================================================

log_step "Pre-flight checks"

# 1. Must be root
if [[ $EUID -ne 0 ]]; then
    log_fail "This script must be run as root (sudo)."
    exit 1
fi
log_info "User: root (OK)"

# 2. Kernel version >= 5.10 (BPF requirement)
kernel_ver="$(uname -r | cut -d- -f1 | cut -d. -f1-2)"
major="${kernel_ver%%.*}"
minor="${kernel_ver#*.}"
if [[ "$major" -lt 5 ]] || { [[ "$major" -eq 5 && "$minor" -lt 10 ]]; }; then
    log_fail "Kernel ${kernel_ver} is too old. BPF/XDP requires >= 5.10."
    exit 1
fi
log_info "Kernel: $(uname -r) (OK)"

# 3. Detect primary network interface
IFACE_CANDIDATES=("eth0" "enp0s3" "enp0s8" "enp1s0" "ens3" "ens5")
IFACE=""
for iface in "${IFACE_CANDIDATES[@]}"; do
    if ip link show "$iface" &>/dev/null; then
        IFACE="$iface"
        break
    fi
done

if [[ -z "$IFACE" ]]; then
    # Fallback: pick the first non-loopback interface
    IFACE=$(ip -o link show | awk -F': ' '!/lo/{print $2; exit}')
fi

if [[ -z "$IFACE" ]]; then
    log_fail "No suitable network interface found."
    exit 1
fi
log_info "Interface: ${IFACE} (OK)"

# 4. Detect OS family
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
else
    log_fail "Unsupported package manager (only apt/yum/dnf)."
    exit 1
fi
log_info "Package manager: ${PKG_MANAGER} (OK)"

# 5. Check that project source exists
if [[ ! -f "${PROJECT_ROOT}/srp_proxy.py" ]]; then
    log_fail "Project source not found at ${PROJECT_ROOT}. Aborting."
    exit 1
fi
log_info "Project root: ${PROJECT_ROOT} (OK)"

# =============================================================================
#  PHASE 1 — Kernel Hardening
# =============================================================================

log_step "[SYSCTL HARDENING APPLIED]"

if [[ -f "${HARDENING_CONF}" ]]; then
    cp "${HARDENING_CONF}" /etc/sysctl.d/99-srp-hardening.conf
    chmod 0644 /etc/sysctl.d/99-srp-hardening.conf
    sysctl --system
    log_info "Kernel parameters applied from ${HARDENING_CONF}"
else
    log_warn "Hardening profile not found at ${HARDENING_CONF} — skipping."
fi

# =============================================================================
#  PHASE 2 — System Packages
# =============================================================================

log_step "[BUILD TOOLCHAIN INSTALLED]"

PACKAGES=(
    clang
    llvm
    libelf-dev
    bpfcc-tools
    linux-headers-"$(uname -r)"
    python3
    python3-pip
    python3-venv
    build-essential
    curl
    ca-certificates
    openssl
    rsync
)

case "$PKG_MANAGER" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${PACKAGES[@]}" 2>&1 | tail -1 || {
            log_fail "apt installation failed (exit code $?)"
            exit 2
        }
        ;;
    yum|dnf)
        "$PKG_MANAGER" install -y -q clang llvm elfutils-libelf-devel \
            bcc-tools kernel-devel python3 python3-pip python3-virtualenv \
            gcc make curl ca-certificates openssl rsync 2>&1 | tail -1 || {
            log_fail "${PKG_MANAGER} installation failed (exit code $?)"
            exit 2
        }
        ;;
esac
log_info "System packages installed (${PKG_MANAGER})"

# =============================================================================
#  PHASE 3 — Python Virtual Environment
# =============================================================================

if [[ "$SKIP_VENV" == "true" ]]; then
    log_info "Python venv skipped (--skip-venv)"
else
    log_step "[PYTHON VENV INITIALISED]"

    mkdir -p "${SRP_INSTALL_DIR}"

    if [[ -d "${VENV_DIR}" ]]; then
        log_info "Virtual environment already exists at ${VENV_DIR}"
    else
        python3 -m venv "${VENV_DIR}"
        log_info "Virtual environment created at ${VENV_DIR}"
    fi

    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    PIP_DEPS=(
        fastapi
        uvicorn[standard]
        httpx
        sentence-transformers
        numpy
        scapy
        cryptography
        aiofiles
        bcc-python
    )

    pip install --no-cache-dir --upgrade pip setuptools wheel
    pip install --no-cache-dir "${PIP_DEPS[@]}" || {
        log_fail "pip install failed (exit code $?)"
        exit 3
    }
    log_info "Python dependencies installed (${#PIP_DEPS[@]} packages)"

    # Pre-cache sentence-transformers model
    python3 -c "
from sentence_transformers import SentenceTransformer
SentenceTransformer('all-MiniLM-L6-v2')
print('[BOOT] Sentence-transformers model pre-cached.')
" 2>&1 | tail -1
fi

# =============================================================================
#  PHASE 4 — Certificate Matrix
# =============================================================================

if [[ "$SKIP_CERTS" == "true" ]]; then
    log_info "Certificate generation skipped (--skip-certs)"
else
    log_step "[CERTIFICATE MATRIX DEPLOYED]"

    mkdir -p "${CERT_DIR}"
    chmod 0700 "${CERT_DIR}"

    if [[ -f "${CERT_DIR}/ca.crt" ]]; then
        log_info "CA certificate already exists at ${CERT_DIR}/ca.crt"
    else
        log_info "Generating mTLS certificate matrix..."

        python3 "${PROJECT_ROOT}/cluster/generate_certs.py" \
            --output-dir "${CERT_DIR}" \
            --no-config-update || {
            log_fail "Certificate generation failed (exit code $?)"
            exit 4
        }

        # Set strict permissions
        chmod 0600 "${CERT_DIR}"/*.key
        chmod 0644 "${CERT_DIR}"/*.crt
        chmod 0644 "${CERT_DIR}"/certs.md5 2>/dev/null || true

        # Verify
        openssl x509 -in "${CERT_DIR}/ca.crt" -noout -subject -dates
        log_info "Certificates deployed to ${CERT_DIR}"
    fi
fi

# =============================================================================
#  PHASE 5 — Service Installation
# =============================================================================

log_step "[SYSTEMD SERVICE ACTIVE]"

# Copy project source to install directory (if not already there)
if [[ "$(realpath "${PROJECT_ROOT}")" != "$(realpath "${SRP_INSTALL_DIR}")" ]]; then
    log_info "Copying project source to ${SRP_INSTALL_DIR}..."
    rsync -a --delete \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='venv' \
        --exclude='node_modules' \
        "${PROJECT_ROOT}/" "${SRP_INSTALL_DIR}/"
    log_info "Project source copied."
else
    log_info "Already running from ${SRP_INSTALL_DIR} — no copy needed."
fi

# Install systemd service
if [[ -f "${SYSTEMD_UNIT}" ]]; then
    cp "${SYSTEMD_UNIT}" "${SYSTEMD_TARGET}"
    chmod 0644 "${SYSTEMD_TARGET}"

    # Update WorkingDirectory in the unit file to match install dir
    sed -i "s|WorkingDirectory=/opt/srp|WorkingDirectory=${SRP_INSTALL_DIR}|g" \
        "${SYSTEMD_TARGET}"

    systemctl daemon-reload
    systemctl enable srp-gateway.service
    systemctl start srp-gateway.service

    log_info "Systemd unit installed: srp-gateway.service"
else
    log_warn "Systemd unit not found at ${SYSTEMD_UNIT} — skipping."
fi

# =============================================================================
#  PHASE 6 — Post-deployment Health Check
# =============================================================================

log_step "[SRP NODE OPERATIONAL]"

# Wait for services
MAX_RETRIES=15
RETRY_DELAY=2

check_endpoint() {
    local url="$1"
    local name="$2"
    for i in $(seq 1 "${MAX_RETRIES}"); do
        if curl -sf "${url}" >/dev/null 2>&1; then
            log_info "${name}: ${url} — UP"
            return 0
        fi
        sleep "${RETRY_DELAY}"
    done
    log_fail "${name}: ${url} — UNREACHABLE after ${MAX_RETRIES} retries"
    return 1
}

check_endpoint "http://127.0.0.1:9000/health" "Validation Proxy"
check_endpoint "http://127.0.0.1:9001/health" "eBPF Loader"

# Verify telemetry ledger
if [[ -f "${SRP_INSTALL_DIR}/telemetry/srp_ledger.py" ]]; then
    python3 "${SRP_INSTALL_DIR}/telemetry/srp_monitor.py" \
        --verify --skip-verify 2>/dev/null || true
    log_info "Telemetry subsystem available."
fi

log_info ""
log_info "========================================"
log_info "  SRP NODE BOOTSTRAP COMPLETE"
log_info "  Install dir: ${SRP_INSTALL_DIR}"
log_info "  Interface:   ${IFACE}"
log_info "  Certs:       ${CERT_DIR}"
log_info "  Proxy:       http://127.0.0.1:9000"
log_info "  Loader:      http://127.0.0.1:9001"
log_info "========================================"
