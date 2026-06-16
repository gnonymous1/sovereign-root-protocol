# Contributing to Sovereign Root Protocol (SRP)

Thank you for your interest in contributing to SRP! This document outlines the process for contributing code, documentation, or ideas.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Areas We Need Help With](#areas-we-need-help-with)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and constructive environment. Harassment, discrimination, or hostile behavior will not be tolerated.

---

## How to Contribute

### 🐛 Reporting Bugs

1. **Search existing issues** before opening a new one.
2. Use the **Bug Report** issue template.
3. Include:
   - OS, kernel version, Python version
   - Deployment mode (eBPF/XDP, HAProxy, userspace sim)
   - Exact error message and stack trace
   - Steps to reproduce

### 💡 Feature Requests

1. Open a **Feature Request** issue with a clear description of the problem it solves.
2. For major changes, **open an issue to discuss** before submitting a PR.

### 📖 Documentation

Documentation PRs are always welcome! Fix typos, clarify ambiguity, add examples.

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/sovereign-root-protocol.git
cd sovereign-root-protocol

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install httpx  # for test scripts

# 4. Copy environment template
cp .env.example .env
# Edit .env with any API keys you want to test (optional)

# 5. Generate TLS certificates (for cluster features)
python3 cluster/generate_certs.py --output-dir cluster/certs

# 6. Start the proxy
python3 srp_proxy.py

# 7. Run tests
python3 scripts/srp_local_test.py
```

---

## Pull Request Process

1. **Branch naming:**
   - `feature/your-feature-name`
   - `fix/issue-description`
   - `docs/what-you-documented`
   - `security/vulnerability-fix`

2. **Before submitting:**
   - Run the full test suite: `python3 scripts/srp_local_test.py`
   - Run the security audit: `python3 security/run_audit.py --json`
   - Verify the ledger chain: `python3 telemetry/srp_monitor.py --verify`
   - Ensure no secrets or API keys are committed (check `.gitignore`)

3. **PR description should include:**
   - What the change does
   - Why it is needed
   - How it was tested
   - Any breaking changes

4. All PRs require at least **one approving review** before merging.

5. PRs should target the `main` branch unless otherwise instructed.

---

## Coding Standards

- **Python 3.11+** — type hints encouraged, f-strings preferred
- **async/await** — all I/O-bound operations should be async (FastAPI/httpx pattern)
- **Error handling** — never swallow exceptions silently; log with context
- **Secrets** — API keys and credentials MUST be read from `os.environ.get()`, never hardcoded
- **Logging** — use structured log lines; avoid bare `print()` in production paths
- **Tests** — add a test case or verification step for any new behavior

### File naming convention

| Type | Convention |
|------|------------|
| Python modules | `srp_component_name.py` |
| Shell scripts | `srp_action.sh` |
| Config files | `cluster_nodes.json`, `haproxy_srp.cfg` |
| Documentation | `SCREAMING_SNAKE.md` or `lowercase.md` |

---

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Instead:
1. Email the maintainers directly (see repository contact info).
2. Include a detailed description and proof-of-concept steps.
3. Allow reasonable time for a fix before public disclosure.

Responsible disclosure is appreciated and will be acknowledged in release notes.

---

## Areas We Need Help With

Check the [Roadmap](README.md#-roadmap) section in the README for prioritized work. Current high-value areas:

- [ ] **eBPF map exhaustion benchmarking** under sustained attack traffic
- [ ] **HAProxy config validation** against live tc filter rules
- [ ] **Full Kubernetes deployment** testing via `ignition.py`
- [ ] **Dashboard UI** — real-time alignment score monitoring
- [ ] **Plugin system** for custom alignment models
- [ ] **More language bindings** for the proxy client SDK
- [ ] **Helm chart** for Kubernetes deployments

---

Thank you for helping make AI infrastructure safer and more auditable! 🛡️
