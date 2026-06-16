# Sovereign Root Protocol (SRP) — Architecture

**Version:** 2026.4.2  
**Architecture type:** AI traffic gateway, semantic policy enforcement, network quarantine, cluster sync, and tamper-evident audit infrastructure

---

## 1. What SRP Is

Sovereign Root Protocol (SRP) is a deployable software gateway for inspecting AI-bound traffic before it reaches upstream model providers or internal inference services.

SRP combines four practical layers:

1. **Semantic validation** — prompts are scored against configured policy boundaries using `sentence-transformers/all-MiniLM-L6-v2`.
2. **Network enforcement** — denied source IPs can be quarantined through an eBPF/XDP control plane on Linux, or drained through HAProxy in load-balanced deployments.
3. **Cluster coordination** — nodes exchange state over an mTLS peer mesh using generated ECDSA P-256 certificates.
4. **Auditability** — validation decisions are written to a SHA-256 hash-chain ledger so tampering can be detected later.

SRP does **not** require custom silicon, GPU firmware changes, hardware eFuses, or privileged access to model-provider infrastructure. It operates as infrastructure you deploy at your own network, host, or cluster boundary.

---

## 2. Runtime Topology

```text
[Client / Internal Service]
          │
          ▼
[Firewall / Load Balancer]
          │
          │ optional: HAProxy routing, cloud firewall rules, or XDP ingress
          ▼
┌──────────────────────────┐
│ srp_proxy.py             │
│ FastAPI validation proxy │
│ Port 9000                │
└────────────┬─────────────┘
             │
             ├── Semantic policy check
             │   - all-MiniLM-L6-v2 embeddings
             │   - cosine similarity against restriction vectors
             │   - verdict: pass, audit, or violation
             │
             ├── Enforcement update
             │   ▼
             │   ┌──────────────────────────┐
             │   │ srp_loader.py             │
             │   │ eBPF/XDP control plane    │
             │   │ Port 9001                 │
             │   └──────────────────────────┘
             │
             ├── Audit event
             │   ▼
             │   ┌──────────────────────────┐
             │   │ telemetry/srp_ledger.py   │
             │   │ SHA-256 hash chain        │
             │   └──────────────────────────┘
             │
             ├── Cluster notification
             │   ▼
             │   ┌──────────────────────────┐
             │   │ cluster/srp_sync_daemon.py│
             │   │ mTLS peer replication     │
             │   │ Ports 9200 / 9201         │
             │   └──────────────────────────┘
             │
             ▼
[Upstream AI Provider or Internal Model]
```

---

## 3. Core Components

| Component | File | Responsibility |
|---|---|---|
| Validation proxy | `srp_proxy.py` | Accepts AI request manifests, scores prompts, updates enforcement state, optionally forwards approved requests upstream. |
| eBPF/XDP loader | `srp_loader.py` | Compiles and attaches `srp_filter.c`, exposes a local HTTP control plane for IP state updates. |
| XDP filter | `srp_filter.c` | Performs low-level packet pass/drop decisions from BPF maps on supported Linux hosts. |
| Certificate generator | `cluster/generate_certs.py` | Generates a local CA and node certificates for the mTLS sync mesh. |
| Sync daemon | `cluster/srp_sync_daemon.py` | Shares node state and peer health over mTLS. |
| Ledger | `telemetry/srp_ledger.py` | Appends validation records to a SHA-256 hash chain and verifies integrity. |
| Logger | `telemetry/srp_logger.py` | Buffers and ships audit records without blocking the request path. |
| Monitor | `telemetry/srp_monitor.py` | Tails audit events and verifies ledger integrity. |
| Watchdog | `operations/srp_watchdog.py` | Polls health and drains unhealthy nodes or breached paths. |
| Failover scripts | `operations/srp_failover.sh`, `operations/srp_audit_incident.py` | Provide recovery workflows for reset, isolation, incident scanning, and trust-block reloads. |
| Frontend tools | `frontend/` | Browser-based simulator, tutorial, and configuration wizard. |

---

## 4. Decision Model

SRP computes a compliance score as:

```text
compliance_score = 1.0 - max_cosine_similarity(prompt, restriction_vectors)
```

Higher scores indicate the prompt is farther from configured restricted-use examples.

| Compliance score | Internal verdict | State | Default action |
|---:|---|---|---|
| `>= 0.85` | `SOVEREIGN_PASS` | `0x02` | Approve and allow normal forwarding. |
| `>= 0.60` and `< 0.85` | `CONTEXTUAL_AUDIT` | `0x01` | Approve with audit visibility. |
| `< 0.60` | `SOVEREIGN_VIOLATION` | `0xFF` | Deny request and quarantine source state. |

The names are project terminology. Mechanically, they are software states used by the proxy, loader, telemetry, and UI.

---

## 5. Enforcement Modes

### 5.1 Software mode: Linux eBPF/XDP

In software mode, `srp_loader.py` uses BCC to compile and attach `srp_filter.c` to a Linux network interface. The loader maintains BPF maps for source/destination IP state and packet counters.

Typical state flow:

1. `srp_proxy.py` receives a request.
2. The semantic engine returns a verdict.
3. The proxy calls `srp_loader.py` on `127.0.0.1:9001`.
4. The loader writes the IP state into the BPF approval map.
5. The XDP program passes or drops matching packets at the kernel ingress path.

This mode requires Linux, BPF support, BCC, and root privileges.

### 5.2 HAProxy / appliance mode

For environments where direct XDP attachment is not appropriate, SRP can be placed behind HAProxy or a dedicated firewall appliance. HAProxy provides frontend routing, backend health checks, and node draining through stats/admin sockets.

This mode does not claim packet drops before the kernel stack; it provides conventional load-balancer enforcement and operational failover.

### 5.3 Userspace simulation

`srp_loader.py` includes an explicit opt-in userspace simulation mode for local demos and UI testing. It does not intercept packets and must not be treated as a security boundary.

---

## 6. Trust and Audit Model

SRP uses tamper-evident logging, not a blockchain.

Each audit record is canonicalized and sealed with the previous record hash:

```text
Seal_n = SHA256(canonical_record_json + ':' + Seal_n-1)
```

This provides append-order integrity: if a previous record is edited, removed, or reordered, `telemetry/srp_monitor.py --verify` can identify the chain break.

Security properties:

- Detects ledger tampering after the fact.
- Preserves request decision history for incident review.
- Does not prevent deletion of the entire ledger by a fully privileged host attacker.
- Should be paired with off-host log shipping or immutable storage for production deployments.

---

## 7. Cluster Security Model

The cluster mesh uses generated certificates under `cluster/certs/`:

- self-signed CA
- node certificates
- peer configuration in `cluster/cluster_nodes.json`
- mTLS verification through Python TLS contexts

The mesh is intended for trusted SRP nodes under the operator's control. It is not a public consensus network.

---

## 8. Request Lifecycle

```text
1. Inhale
   Proxy accepts a JSON request manifest containing source IP, provider, prompt,
   node ID, and optional metadata.

2. Validate
   The semantic engine embeds the prompt and compares it to restriction vectors.

3. Enforce
   Approved requests set an active state; violations set quarantine state.

4. Forward or reject
   Approved requests are forwarded to a configured upstream provider when API
   credentials exist. Violations return HTTP 403.

5. Audit and cleanup
   The decision is written to the ledger. Active states are reset after the
   configured validation window.
```

---

## 9. Production Boundaries

SRP is strongest when deployed as one layer in a defense-in-depth gateway design.

Recommended production additions:

- authenticate callers to `srp_proxy.py`
- bind control-plane ports (`9001`, `9201`) to localhost or private networks only
- place TLS termination in front of the proxy for external clients
- ship ledger files to off-host storage
- tune policy vectors for the organization's actual acceptable-use policy
- run the security audit suite before exposing the system to untrusted traffic
- benchmark eBPF map capacity and failure behavior on target hardware

---

## 10. Non-Goals

SRP does not:

- modify GPU, TPU, or CPU microcode
- burn keys into hardware fuses
- control global NICs, internet exchanges, or third-party model-provider infrastructure
- guarantee sub-millisecond global routing latency
- replace provider-side model safety systems
- provide cryptographic proof that a model executed a specific computation

It provides a practical, inspectable enforcement gateway that can be deployed and tested with standard Linux, Python, mTLS, HAProxy, and eBPF tooling.
