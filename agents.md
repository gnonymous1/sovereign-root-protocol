# Sovereign Root Protocol (SRP) — Enforcement Modules

**Scope:** Software components and operational responsibilities  
**Version:** 2026.4.2

---

## Overview

SRP uses three named enforcement modules to describe the major responsibilities in the gateway. These are project-level software roles, not hardware-embedded agents.

```text
                        ┌─────────────────────────────┐
                        │ SRP Validation Gateway       │
                        │ srp_proxy.py                 │
                        └──────────────┬──────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
      ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
      │ Sentry       │         │ Scale        │         │ Executioner  │
      │ Network      │         │ Semantic     │         │ Response     │
      │ enforcement  │         │ validation   │         │ operations   │
      └──────────────┘         └──────────────┘         └──────────────┘
```

---

## 1. Sentry — Network Enforcement Layer

**Primary files:** `srp_filter.c`, `srp_loader.py`, `cluster/haproxy_srp.cfg`

Sentry represents the network enforcement path.

Responsibilities:

- attach an XDP program on supported Linux interfaces
- maintain IP state in BPF maps through `srp_loader.py`
- pass or drop traffic based on quarantine state
- expose local health, metrics, map dump, and state update endpoints on port `9001`
- integrate with HAProxy or firewall routing when XDP is not the right deployment mode

Deployment boundaries:

- XDP enforcement requires Linux, BCC, root privileges, and a supported network interface.
- HAProxy mode provides load-balancer health checks and node draining, not pre-kernel packet filtering.
- Userspace simulation mode is for local demos only and does not enforce network security.

---

## 2. Scale — Semantic Validation Layer

**Primary files:** `srp_proxy.py`, `core/sovereign_core.py`

Scale represents the prompt inspection and policy scoring path.

Responsibilities:

- load `all-MiniLM-L6-v2` using `sentence-transformers`
- encode the incoming prompt
- compare prompt embeddings against configured restriction vectors
- compute `compliance_score = 1.0 - max_similarity`
- return one of three software verdicts:
  - `SOVEREIGN_PASS`
  - `CONTEXTUAL_AUDIT`
  - `SOVEREIGN_VIOLATION`
- emit structured events for the API, WebSocket clients, and audit logger

Operational note:

The default policy vectors are examples. Production users should review and tune them to match their own acceptable-use policy, regulatory environment, and false-positive tolerance.

---

## 3. Executioner — Response and Recovery Layer

**Primary files:** `operations/srp_watchdog.py`, `operations/srp_failover.sh`, `operations/srp_audit_incident.py`, `telemetry/`

Executioner represents the operational response path after SRP identifies a violation, health breach, or audit issue.

Responsibilities:

- set violating sources to quarantine state (`0xFF`)
- drain unhealthy HAProxy backends by setting backend weight to zero
- run Track A clear-and-reset recovery workflows
- run Track B emergency isolation workflows
- verify ledger integrity and identify tamper lines
- reload trust blocks or quarantine compromised IPs during incident response

Deployment boundaries:

Executioner does not modify hardware execution state, GPU memory, or firmware. It coordinates software controls available to the deployed SRP node: BPF map updates, HAProxy admin actions, service management, firewall commands, and ledger verification.

---

## Decision Logic Matrix

| Compliance score | Verdict | State | Action |
|---:|---|---|---|
| `>= 0.85` | `SOVEREIGN_PASS` | `0x02` | Approve and forward when upstream routing is configured. |
| `>= 0.60` and `< 0.85` | `CONTEXTUAL_AUDIT` | `0x01` | Approve with elevated audit visibility. |
| `< 0.60` | `SOVEREIGN_VIOLATION` | `0xFF` | Reject request, write quarantine state, and log the event. |

---

## Module Interaction

```text
Request arrives
    │
    ▼
Scale scores prompt in srp_proxy.py
    │
    ├── Pass / audit
    │      ├── write active state through srp_loader.py
    │      ├── append audit ledger record
    │      └── forward request if provider credentials are configured
    │
    └── Violation
           ├── write quarantine state through srp_loader.py
           ├── append audit ledger record
           └── return HTTP 403

Watchdog and failover scripts monitor the running system and can drain,
reset, or isolate nodes when health or integrity checks fail.
```
