# Sovereign Root Protocol (SRP) — Interface Specification

**Design goal:** Clear real-time visibility into AI traffic validation, enforcement state, and audit integrity.

---

## 1. Interface Model

The SRP interface should help operators answer four questions quickly:

1. Is the validation proxy healthy?
2. What traffic is being approved, audited, or blocked?
3. Which sources are active or quarantined?
4. Is the audit ledger still intact?

The frontend can be presented as a real-time topology view, but each visual element should map to an actual software signal from the SRP stack.

```text
        Source / workload node
                 │
                 ▼
        ┌────────────────┐
        │ SRP Proxy       │
        │ validation hub  │
        └───────┬────────┘
                │
     ┌──────────┼──────────┐
     ▼          ▼          ▼
 Approved     Audit     Quarantine
```

---

## 2. Visual Elements

### Canvas

A dark operations canvas can show nodes, event streams, and enforcement state. The background should be decorative only; the important signals are node state, event count, latency, and ledger integrity.

### SRP Hub

Represents the local `srp_proxy.py` instance.

Suggested displayed fields:

- proxy health
- current model status
- requests processed
- average validation latency
- active WebSocket clients
- ledger verification status

### Source Nodes

Represent source IPs, workloads, peer SRP nodes, or simulated clients.

Suggested displayed fields:

- source IP
- node ID
- provider
- last verdict
- compliance score
- current gatekeeper state
- last event timestamp

---

## 3. State Mapping

| State | Hex | Meaning | Suggested color |
|---|---|---|---|
| Dormant | `0x00` | No active validation window or no current state. | Slate / neutral gray |
| Active | `0x01` | Request approved or under audit visibility. | Cyan / blue |
| Full approval | `0x02` | High-confidence approval. | Green |
| Quarantine | `0xFF` | Request denied; source marked for enforcement. | Crimson / red |

The UI should avoid implying that SRP controls GPU firmware, model internals, or third-party infrastructure. These states are gateway enforcement states.

---

## 4. Event Timeline

The event stream should show the request lifecycle:

1. `inhale` — request received
2. `packet_inspection` — semantic score and verdict produced
3. `exhale` — approved request released or local approval returned
4. `sync` — audit/cleanup path completed
5. `map_cleanup` — source state reset after the validation window

For each event, show:

- timestamp
- source IP
- provider
- verdict
- compliance score
- closest boundary when relevant
- action: `APPROVED` or `TERMINATED`

---

## 5. Recommended Dashboard Sections

### Health Panel

- `GET /health` from `srp_proxy.py`
- loader health on port `9001`
- sync notify health on port `9201`
- ledger verification result

### Traffic Panel

- total inspected requests
- approved count
- audit count
- terminated count
- recent source IPs
- provider distribution

### Enforcement Panel

- BPF/loader mode: real XDP or userspace simulation
- current approval map snapshot
- dropped/passed counters when available
- quarantined sources

### Audit Panel

- latest seal
- ledger record count
- chain verification status
- last tamper-detection result

---

## 6. Palette

| Token | Suggested hex | Use |
|---|---|---|
| Obsidian | `#0B0C10` | Background |
| Slate | `#1F2833` | Dormant or inactive state |
| Cyan | `#66FCF1` | Active validation stream |
| Green | `#2ECC71` | High-confidence approval |
| Amber | `#F5A623` | Audit / warning |
| Crimson | `#FF2E63` | Quarantine / terminated traffic |

---

## 7. Operator Warnings

The UI should clearly label simulation mode when enabled. In simulation mode, SRP displays state transitions but does not attach XDP hooks or drop packets.

Suggested banner:

```text
Simulation mode active: no kernel hook is attached and no network traffic is being enforced.
```
