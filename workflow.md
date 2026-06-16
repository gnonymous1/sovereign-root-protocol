# Sovereign Root Protocol (SRP) — Operational Workflow

**Scope:** Request handling, validation, enforcement, forwarding, and audit flow

---

## 1. Request Lifecycle

SRP handles each AI-bound request as a validation workflow at the gateway boundary.

```text
┌──────────────────────┐
│ Client / workload     │
└──────────┬───────────┘
           │ POST /api/v1/srp/inhale
           ▼
┌──────────────────────┐
│ srp_proxy.py          │
│ Parse request manifest│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Semantic validation   │
│ all-MiniLM-L6-v2      │
└──────────┬───────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
 Approved     Violation
     │           │
     ▼           ▼
 Set active   Set quarantine
 state        state 0xFF
     │           │
     ▼           ▼
 Forward or   Return HTTP 403
 local OK
     │           │
     └─────┬─────┘
           ▼
┌──────────────────────┐
│ Append audit record   │
│ Verify hash chain     │
└──────────────────────┘
```

---

## 2. Intake: `POST /api/v1/srp/inhale`

The proxy accepts a JSON request manifest.

Example:

```json
{
  "node_id": "srp-node-us-east-01",
  "source_ip": "10.88.0.10",
  "provider": "openai",
  "prompt": "How do I train a sentiment analysis model?",
  "metadata": {
    "app": "internal-assistant",
    "request_id": "req-123"
  }
}
```

Important fields:

| Field | Required | Purpose |
|---|---:|---|
| `prompt` | Yes | Text to validate. Empty prompts are rejected. |
| `source_ip` | No | Source to update in enforcement maps. Defaults to client IP when omitted. |
| `node_id` | No | Logical SRP node/workload identifier. Defaults to `unknown`. |
| `provider` | No | Upstream route key. Defaults to `openai`. |
| `metadata` | No | Extra context written into events/audit paths when used. |

---

## 3. Validation

`srp_proxy.py` runs the Scale semantic engine:

1. Load `all-MiniLM-L6-v2`.
2. Embed the incoming prompt.
3. Compare the prompt embedding against configured restriction embeddings.
4. Compute the compliance score.
5. Choose the verdict and gatekeeper state.

```text
compliance_score = 1.0 - max_cosine_similarity(prompt, restriction_vectors)
```

| Score range | Verdict | State |
|---:|---|---|
| `>= 0.85` | `SOVEREIGN_PASS` | `0x02` |
| `>= 0.60` and `< 0.85` | `CONTEXTUAL_AUDIT` | `0x01` |
| `< 0.60` | `SOVEREIGN_VIOLATION` | `0xFF` |

---

## 4. Enforcement

### Approved or audit requests

For `SOVEREIGN_PASS` and `CONTEXTUAL_AUDIT`:

1. The proxy calls `srp_loader.py` on `127.0.0.1:9001`.
2. The loader writes the source IP to the active state in the BPF approval map when XDP mode is enabled.
3. The request is forwarded upstream if the provider route and API key are configured.
4. If no upstream key exists, SRP returns a local approval response for validation-only operation.
5. A cleanup task resets the source state to dormant after the configured validation window.

### Violation requests

For `SOVEREIGN_VIOLATION`:

1. The proxy calls the loader to set the source IP to `0xFF`.
2. XDP-enabled deployments can drop matching traffic according to the BPF map.
3. The proxy returns HTTP `403` with the closest matched policy boundary.
4. The event is written to the audit ledger.

---

## 5. Forwarding

When upstream credentials are present, SRP can forward approved requests to:

| Provider key | Base URL | Credential variable |
|---|---|---|
| `openai` | `https://api.openai.com` | `OPENAI_API_KEY` |
| `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `google` | `https://generativelanguage.googleapis.com` | `GOOGLE_API_KEY` |
| `cohere` | `https://api.cohere.ai` | `COHERE_API_KEY` |

If a provider is unknown or credentials are not configured, SRP still performs validation and returns a local approval response instead of forwarding.

---

## 6. Telemetry and Ledger

Every decision path records audit data through `telemetry/srp_logger.py` and `telemetry/srp_ledger.py`.

Recorded data includes:

- source IP
- prompt intent hash
- compliance score
- verdict action
- latency
- selected provider
- closest matched boundary for violations
- hash-chain seal

Verify the chain:

```bash
python3 telemetry/srp_monitor.py --verify
```

Tail events:

```bash
python3 telemetry/srp_monitor.py --tail --json
```

---

## 7. Cluster Sync

In clustered deployments, `cluster/srp_sync_daemon.py` shares state between trusted SRP nodes over mTLS.

The certificate generator creates:

- a local CA
- node certificates
- certificate paths in cluster configuration
- a manifest for generated cert files

Generate certs:

```bash
python3 cluster/generate_certs.py --output-dir cluster/certs
```

Run sync daemon:

```bash
python3 cluster/srp_sync_daemon.py --notify-port 9201
```

---

## 8. Operational Recovery

SRP includes two recovery tracks:

| Track | Purpose | Tooling |
|---|---|---|
| Track A | Clear-and-reset normal recovery | `operations/srp_failover.sh` |
| Track B | Emergency isolation | `operations/srp_failover.sh` |
| Incident scan | Ledger and trust-state investigation | `operations/srp_audit_incident.py` |
| Watchdog | Health polling and backend draining | `operations/srp_watchdog.py` |

Use `--dry-run` where available before running destructive recovery operations.

---

## 9. Production Notes

Before production use:

- put authentication and TLS in front of public-facing proxy endpoints
- keep loader and notify control planes private
- tune restriction vectors and thresholds
- run the security audit suite
- ship audit logs off-host
- test failover behavior on the actual target network
