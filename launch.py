"""
SRP Launch Script — Starts all Sovereign Root Protocol modules:
  Module 1: srp_loader.py  (eBPF/XDP controller, port 9001)
  Module 2: srp_proxy.py   (Validation proxy,         port 9000)
  Module 3: frontend/      (Admin console,             port 8080)

Legacy core (sovereign_core.py) started as well for backward compatibility.
"""
import subprocess, sys, os, time, threading, http.server, socketserver, signal

ROOT = os.path.dirname(os.path.abspath(__file__))
CORE_PORT = 9000
LOADER_PORT = 9001
FRONTEND_PORT = 8080

processes = []

def serve_frontend():
    os.chdir(os.path.join(ROOT, "frontend"))
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", FRONTEND_PORT), handler) as httpd:
        print(f"[FRONTEND] Admin Console serving at http://localhost:{FRONTEND_PORT}")
        httpd.serve_forever()

def main():
    print("=" * 68)
    print("  SOVEREIGN ROOT PROTOCOL — SYSTEM LAUNCHER")
    print("=" * 68)

    # Start Module 1: eBPF/XDP Loader (port 9001)
    loader_cmd = [sys.executable, os.path.join(ROOT, "srp_loader.py")]
    print(f"[LAUNCHER] Starting SRP eBPF Loader on port {LOADER_PORT}...")
    loader_proc = subprocess.Popen(loader_cmd, cwd=ROOT)
    processes.append(loader_proc)

    # Start Module 2: Validation Proxy (port 9000)
    proxy_cmd = [sys.executable, os.path.join(ROOT, "srp_proxy.py")]
    print(f"[LAUNCHER] Starting SRP Validation Proxy on port {CORE_PORT}...")
    proxy_proc = subprocess.Popen(proxy_cmd, cwd=ROOT)
    processes.append(proxy_proc)

    # Legacy Sovereign Core (backward compat)
    legacy_cmd = [sys.executable, os.path.join(ROOT, "core", "sovereign_core.py")]
    print(f"[LAUNCHER] Starting Legacy Sovereign Core on port {CORE_PORT}...")
    legacy_proc = subprocess.Popen(legacy_cmd, cwd=ROOT)
    processes.append(legacy_proc)

    # Start Frontend server (port 8080)
    print(f"[LAUNCHER] Starting Admin Console Frontend on port {FRONTEND_PORT}...")
    ft = threading.Thread(target=serve_frontend, daemon=True)
    ft.start()

    time.sleep(2)
    print(f"\n  ◈ Proxy API       : http://localhost:{CORE_PORT}/health")
    print(f"  ◈ Loader Control  : http://localhost:{LOADER_PORT}/health")
    print(f"  ◈ Admin Console   : http://localhost:{FRONTEND_PORT}")
    print(f"  ◈ WebSocket       : ws://localhost:{CORE_PORT}/ws")
    print(f"\n  Inhale endpoint   : POST http://localhost:{CORE_PORT}/api/v1/srp/inhale")
    print(f"\n  Press Ctrl+C to shutdown.\n")

    def shutdown(sig, frame):
        print("\n[LAUNCHER] Shutting down...")
        for p in processes:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    proxy_proc.wait()

if __name__ == "__main__":
    main()
