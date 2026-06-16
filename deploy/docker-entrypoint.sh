#!/bin/sh
# =============================================================================
#  SRP Docker Entrypoint — routes to the correct service based on $SRP_ROLE
# =============================================================================
set -e

SRP_ROLE="${SRP_ROLE:-proxy}"
cd /opt/srp

case "$SRP_ROLE" in
  proxy)
    exec python3 srp_proxy.py
    ;;
  loader)
    exec python3 srp_loader.py --interface "${SRP_INTERFACE:-eth0}" --port "${LOADER_CONTROL_PORT:-9001}"
    ;;
  sync)
    exec python3 cluster/srp_sync_daemon.py \
      --notify-port "${SRP_NOTIFY_PORT:-9201}" \
      --sync-port "${SRP_SYNC_PORT:-9200}"
    ;;
  telemetry)
    exec python3 telemetry/srp_ledger.py --daemon
    ;;
  init)
    exec python3 srp-node.py init
    ;;
  status)
    exec python3 srp-node.py status
    ;;
  shell)
    exec /bin/sh
    ;;
  *)
    echo "ERROR: Unknown SRP_ROLE='$SRP_ROLE'"
    echo "Valid roles: proxy, loader, sync, telemetry, init, status, shell"
    exit 1
    ;;
esac
