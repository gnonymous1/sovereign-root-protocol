#!/usr/bin/env python3
"""
SRP Node — Sovereign Root Protocol Node Controller

Single CLI tool to deploy, configure, and manage an SRP node.
Acts as the operator interface for the entire stack.

Usage:
    srp-node init          Interactive setup wizard
    srp-node start         Launch all node services
    srp-node status        Health check all endpoints
    srp-node stop          Graceful shutdown

    srp-node init --file config.json    Non-interactive from file
    srp-node start --mode software      Override mode on start
"""
import os, sys, json, time, signal, socket, subprocess, argparse, shutil, logging
from pathlib import Path
from datetime import datetime

# =========================================================================
#  Paths & Constants
# =========================================================================
ROOT = Path(__file__).parent.resolve()
CONFIG_PATH = ROOT / "srp-node.json"
PID_DIR = Path("/var/run/srp" if os.name == "posix" else ROOT / ".pids")
LOG_DIR = Path("/var/log/srp" if os.name == "posix" else ROOT / ".logs")

VERSION = "2026.4.2"
DEFAULTS = {
    "node_id": "srp-node-001",
    "mode": "software",
    "interface": "eth0",
    "proxy_port": 9000,
    "loader_port": 9001,
    "sync_port": 9200,
    "notify_port": 9201,
    "haproxy_stats_port": 1993,
    "tls_cert": "cluster/certs/local.crt",
    "tls_key": "cluster/certs/local.key",
    "tls_ca": "cluster/certs/ca.crt",
    "peers": [],
    "upstream_providers": [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.cohere.ai",
    ],
}

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
DIM = "\033[2m"

# =========================================================================
#  Helpers
# =========================================================================
def log_info(msg):  print(f"  [{GREEN}NODE{RESET}] {msg}")
def log_warn(msg):  print(f"  [{YELLOW}WARN{RESET}] {msg}")
def log_fail(msg):  print(f"  [{RED}FAIL{RESET}] {msg}")
def log_step(msg):  print(f"\n  {CYAN}>>>{RESET} {BOLD}{msg}{RESET}")
def bail(msg, code=1): log_fail(msg); sys.exit(code)


def prompt(text, default=None):
    """Interactive prompt with optional default."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {text}{suffix}: ").strip()
    return val if val else (default or "")


def prompt_choice(text, options, default=None):
    """Interactive multiple-choice prompt."""
    print(f"  {text}")
    for i, opt in enumerate(options, 1):
        marker = " *" if opt == default else ""
        print(f"    {i}. {opt}{marker}")
    while True:
        val = input(f"  Select [1-{len(options)}]{' [' + str(options.index(default)+1) + ']' if default else ''}: ").strip()
        if not val and default:
            return default
        try:
            idx = int(val) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            pass


def check_port(port):
    """Return True if port is free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def read_config(path=None):
    """Load and validate srp-node.json."""
    p = Path(path or CONFIG_PATH)
    if not p.exists():
        bail(f"Config not found at {p}. Run 'srp-node init' first.", 1)
    with open(p) as f:
        cfg = json.load(f)
    # Merge with defaults for missing keys
    merged = {**DEFAULTS, **cfg}
    return merged


def write_config(cfg, path=None):
    """Write config to JSON file."""
    p = Path(path or CONFIG_PATH)
    with open(p, "w") as f:
        json.dump(cfg, f, indent=2, sort_keys=False)
    log_info(f"Config written to {p}")


def pid_path(name):
    PID_DIR.mkdir(parents=True, exist_ok=True)
    return PID_DIR / f"{name}.pid"


def write_pid(name, pid):
    pid_path(name).write_text(str(pid))


def read_pid(name):
    p = pid_path(name)
    return int(p.read_text().strip()) if p.exists() else None


def remove_pid(name):
    p = pid_path(name)
    if p.exists():
        p.unlink()


def is_running(name):
    pid = read_pid(name)
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, PermissionError):
        remove_pid(name)
        return False


# =========================================================================
#  Subcommand: init
# =========================================================================
def cmd_init(args):
    """Interactive setup wizard — generates srp-node.json"""
    cfg = {}

    log_step("SRP Node Setup Wizard")
    print(f"  {DIM}Version {VERSION} | Creates srp-node.json for your deployment{RESET}\n")

    # ---- Node identity ----
    print(f"  {BOLD}Node Identity{RESET}")
    cfg["node_id"] = prompt("Node ID", DEFAULTS["node_id"])
    cfg["mode"] = prompt_choice("Deployment mode", ["software", "hardware"], DEFAULTS["mode"])

    if cfg["mode"] == "software":
        cfg["interface"] = prompt("Network interface for XDP", DEFAULTS["interface"])

    # ---- Ports ----
    print(f"\n  {BOLD}Service Ports{RESET}")
    ports = [
        ("proxy_port", "Proxy (HTTP)", DEFAULTS["proxy_port"]),
        ("loader_port", "Loader control plane (HTTP)", DEFAULTS["loader_port"]),
        ("sync_port", "Sync mesh (mTLS)", DEFAULTS["sync_port"]),
        ("notify_port", "Sync notify (HTTP)", DEFAULTS["notify_port"]),
    ]
    for key, label, default in ports:
        while True:
            val = prompt(f"{label} port", default)
            try:
                p = int(val)
                if p < 1 or p > 65535:
                    print(f"  {YELLOW}Port must be 1-65535{RESET}")
                    continue
                cfg[key] = p
                break
            except ValueError:
                print(f"  {YELLOW}Enter a valid number{RESET}")

    # ---- TLS ----
    print(f"\n  {BOLD}TLS Certificates{RESET}")
    use_defaults = prompt("Use auto-generated certs from cluster/certs/", "yes")
    if use_defaults.lower() in ("y", "yes"):
        cfg["tls_cert"] = "cluster/certs/local.crt"
        cfg["tls_key"] = "cluster/certs/local.key"
        cfg["tls_ca"] = "cluster/certs/ca.crt"
        print(f"  {DIM}Will use cluster/certs/*.crt / *.key{RESET}")
    else:
        cfg["tls_cert"] = prompt("TLS cert path", "")
        cfg["tls_key"] = prompt("TLS key path", "")
        cfg["tls_ca"] = prompt("TLS CA path", "")

    # ---- Peers ----
    print(f"\n  {BOLD}Cluster Peers{RESET}")
    cfg["peers"] = []
    add_peers = prompt("Add peer nodes?", "yes")
    if add_peers.lower() in ("y", "yes"):
        while True:
            print(f"  {DIM}--- Peer {len(cfg['peers'])+1} ---{RESET}")
            peer = {
                "node_id": prompt("Peer node ID"),
                "sync_host": prompt("Sync host (IP or hostname)"),
                "sync_port": int(prompt("Sync port", "9200")),
                "proxy_host": prompt("Proxy host"),
                "proxy_port": int(prompt("Proxy port", "9000")),
            }
            cfg["peers"].append(peer)
            more = prompt("Add another peer?", "no")
            if more.lower() not in ("y", "yes"):
                break

    # ---- Upstream providers ----
    print(f"\n  {BOLD}Upstream AI Providers{RESET}")
    add_providers = prompt("Configure upstream providers?", "no")
    if add_providers.lower() in ("y", "yes"):
        cfg["upstream_providers"] = []
        while True:
            host = prompt("Provider hostname (e.g., api.openai.com)")
            if host:
                cfg["upstream_providers"].append(host)
            more = prompt("Add another?", "no")
            if more.lower() not in ("y", "yes"):
                break

    # ---- Summary ----
    print(f"\n  {BOLD}Configuration Summary{RESET}")
    print(f"  {DIM}Node ID:    {cfg['node_id']}{RESET}")
    print(f"  {DIM}Mode:       {cfg['mode']}{RESET}")
    print(f"  {DIM}Proxy port: {cfg['proxy_port']}{RESET}")
    print(f"  {DIM}Sync port:  {cfg['sync_port']}{RESET}")
    print(f"  {DIM}Peers:      {len(cfg['peers'])}{RESET}")
    if cfg["peers"]:
        for p in cfg["peers"]:
            print(f"  {DIM}  - {p['node_id']} @ {p['sync_host']}:{p['sync_port']}{RESET}")

    confirm = prompt("\nWrite config?", "yes")
    if confirm.lower() in ("y", "yes"):
        write_config(cfg)
        print(f"\n  {GREEN}Ready. Run 'srp-node start' to launch.{RESET}")
    else:
        log_warn("Aborted — no config written")


# =========================================================================
#  Subcommand: start
# =========================================================================
def cmd_start(args):
    """Launch all node services as managed subprocesses."""
    cfg = read_config(args.config)
    mode = args.mode or cfg["mode"]

    log_step(f"Starting SRP Node: {cfg['node_id']} ({mode} mode)")

    # Ensure directories
    PID_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Check if already running
    for svc in ["proxy", "sync", "loader"]:
        if is_running(svc):
            log_warn(f"{svc} is already running (PID {read_pid(svc)})")

    # Check port availability
    port_checks = [
        ("Loader", cfg["loader_port"]),
        ("Proxy", cfg["proxy_port"]),
        ("Sync", cfg["sync_port"]),
        ("Notify", cfg["notify_port"]),
    ]
    for name, port in port_checks:
        if not check_port(port):
            log_warn(f"{name} port {port} is already in use")

    processes = []

    # 1. Start loader (software mode only — Linux + BCC required)
    if mode == "software" and not args.skip_loader:
        loader_script = ROOT / "srp_loader.py"
        if loader_script.exists():
            log_info("Starting eBPF/XDP loader...")
            lpath = LOG_DIR / "loader.log"
            with open(lpath, "w") as lf:
                proc = subprocess.Popen(
                    [sys.executable, str(loader_script),
                     "--interface", cfg.get("interface", "eth0"),
                     "--port", str(cfg["loader_port"])],
                    cwd=ROOT, stdout=lf, stderr=subprocess.STDOUT,
                )
            write_pid("loader", proc.pid)
            processes.append(("loader", proc))
            log_info(f"  Loader PID {proc.pid} — log: {lpath}")
        else:
            log_warn("srp_loader.py not found — skipping loader")
    elif mode == "hardware":
        log_info("Hardware mode — eBPF loader not started")

    # 2. Start proxy
    proxy_script = ROOT / "srp_proxy.py"
    if proxy_script.exists():
        log_info("Starting validation proxy...")
        ppath = LOG_DIR / "proxy.log"
        env = os.environ.copy()
        env["SRP_PROXY_PORT"] = str(cfg["proxy_port"])
        env["SRP_LOADER_PORT"] = str(cfg["loader_port"])
        with open(ppath, "w") as lf:
            proc = subprocess.Popen(
                [sys.executable, str(proxy_script)],
                cwd=ROOT, stdout=lf, stderr=subprocess.STDOUT, env=env,
            )
        write_pid("proxy", proc.pid)
        processes.append(("proxy", proc))
        log_info(f"  Proxy PID {proc.pid} — port {cfg['proxy_port']} — log: {ppath}")
    else:
        log_warn("srp_proxy.py not found — skipping proxy")

    # 3. Start sync daemon
    sync_script = ROOT / "cluster" / "srp_sync_daemon.py"
    if sync_script.exists():
        log_info("Starting cluster sync daemon...")
        spath = LOG_DIR / "sync.log"
        with open(spath, "w") as lf:
            proc = subprocess.Popen(
                [sys.executable, str(sync_script),
                 "--notify-port", str(cfg["notify_port"]),
                 "--sync-port", str(cfg["sync_port"])],
                cwd=ROOT, stdout=lf, stderr=subprocess.STDOUT,
            )
        write_pid("sync", proc.pid)
        processes.append(("sync", proc))
        log_info(f"  Sync PID {proc.pid} — ports {cfg['sync_port']}/{cfg['notify_port']} — log: {spath}")

    if not processes:
        log_warn("No services started")
        return

    log_info(f"\n  {len(processes)} service(s) launching. Use 'srp-node status' to verify.")
    log_info(f"  Logs: {LOG_DIR}")
    print()

    # Write PID file for the node controller itself
    write_pid("node", os.getpid())


# =========================================================================
#  Subcommand: status
# =========================================================================
def cmd_status(args):
    """Health check all endpoints and display a table."""
    cfg = read_config(args.config)

    log_step("SRP Node Status")

    services = [
        ("Proxy", "http://127.0.0.1", cfg["proxy_port"], "/health"),
        ("Loader", "http://127.0.0.1", cfg["loader_port"], "/health"),
        ("Sync", "http://127.0.0.1", cfg["notify_port"], "/health"),
    ]

    print(f"  {BOLD}{'Service':<12} {'Status':<14} {'Port':<8} {'Response':<30}{RESET}")
    print(f"  {DIM}{'-'*64}{RESET}")

    all_ok = True
    for name, base, port, path in services:
        proc_running = is_running(name.lower())

        if not proc_running:
            status = f"{RED}STOPPED{RESET}"
            detail = "no process"
            all_ok = False
        else:
            # Try HTTP health check
            try:
                import urllib.request
                t0 = time.monotonic()
                resp = urllib.request.urlopen(f"{base}:{port}{path}", timeout=3)
                elapsed = (time.monotonic() - t0) * 1000
                if resp.status == 200:
                    status = f"{GREEN}ACTIVE{RESET}"
                    body = resp.read().decode()
                    # Extract first meaningful field
                    try:
                        j = json.loads(body)
                        detail = json.dumps(j, separators=(",",":"))[:50]
                    except json.JSONDecodeError:
                        detail = body.strip()[:50]
                else:
                    status = f"{YELLOW}ERROR {resp.status}{RESET}"
                    detail = ""
                    all_ok = False
            except Exception as e:
                status = f"{YELLOW}UNREACHABLE{RESET}"
                detail = str(e)[:40]
                all_ok = False

        print(f"  {name:<12} {status:<20} {port:<8} {detail}")

    # Peers
    peer_count = len(cfg.get("peers", []))
    if peer_count > 0:
        print(f"\n  {BOLD}Peers: {peer_count} configured{RESET}")
        for peer in cfg["peers"]:
            peer_status = f"{DIM}no connection{RESET}"
            # Quick TCP check
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((peer["sync_host"], peer["sync_port"]))
                s.close()
                peer_status = f"{GREEN}reachable{RESET}"
            except Exception:
                peer_status = f"{YELLOW}unreachable{RESET}"
            print(f"    {peer['node_id']:<24} {peer['sync_host']}:{peer['sync_port']:<18} {peer_status}")

    # Certificates
    cert_path = ROOT / cfg.get("tls_cert", "")
    ca_path = ROOT / cfg.get("tls_ca", "")
    print(f"\n  {BOLD}Certificates:{RESET}")
    if cert_path.exists():
        print(f"    Node cert: {GREEN}{cert_path}{RESET}")
    else:
        print(f"    Node cert: {RED}MISSING — {cert_path}{RESET}")
        all_ok = False
    if ca_path.exists():
        print(f"    CA cert:   {GREEN}{ca_path}{RESET}")
    else:
        print(f"    CA cert:   {RED}MISSING — {ca_path}{RESET}")
        all_ok = False

    # Mode
    print(f"\n  {BOLD}Mode:{RESET} {cfg.get('mode', 'unknown')}")
    if cfg.get("mode") == "software":
        print(f"  {BOLD}Interface:{RESET} {cfg.get('interface', '?')}")

    if all_ok:
        print(f"\n  {GREEN}All systems operational{RESET}")
    else:
        print(f"\n  {YELLOW}Some checks failed — review above{RESET}")

    return 0 if all_ok else 1


# =========================================================================
#  Subcommand: stop
# =========================================================================
def cmd_stop(args):
    """Gracefully stop all managed services."""
    log_step("Stopping SRP Node")

    services = ["loader", "proxy", "sync"]
    stopped = 0
    for svc in services:
        pid = read_pid(svc)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait briefly for graceful shutdown
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        time.sleep(0.3)
                    except OSError:
                        break
                else:
                    os.kill(pid, signal.SIGKILL)
                remove_pid(svc)
                log_info(f"  {svc} (PID {pid}) stopped")
                stopped += 1
            except OSError:
                remove_pid(svc)
        else:
            log_info(f"  {svc} — not running")

    remove_pid("node")

    if stopped == 0:
        log_warn("No services were running")
    else:
        log_info(f"{stopped} service(s) stopped")


# =========================================================================
#  Main
# =========================================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"SRP Node Controller v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  srp-node init                        Interactive setup wizard
  srp-node start                       Launch all node services
  srp-node start --mode hardware       Override to hardware mode
  srp-node start --skip-loader         Start without eBPF loader
  srp-node status                      Health check all endpoints
  srp-node stop                        Graceful shutdown
        """,
    )
    parser.add_argument("--version", action="version", version=f"SRP Node v{VERSION}")

    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Interactive setup wizard")

    # start
    p_start = sub.add_parser("start", help="Start all node services")
    p_start.add_argument("--config", help="Path to srp-node.json")
    p_start.add_argument("--mode", choices=["software", "hardware"], help="Override mode")
    p_start.add_argument("--skip-loader", action="store_true", help="Skip eBPF loader")

    # status
    p_status = sub.add_parser("status", help="Check endpoint health")
    p_status.add_argument("--config", help="Path to srp-node.json")

    # stop
    sub.add_parser("stop", help="Stop all services")

    args = parser.parse_args()

    # Route to subcommand
    if args.command == "init":
        cmd_init(args)
    elif args.command == "start":
        cmd_start(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "stop":
        cmd_stop(args)


if __name__ == "__main__":
    main()
