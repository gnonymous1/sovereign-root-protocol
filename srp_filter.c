/* ============================================================================
 *  SOVEREIGN ROOT PROTOCOL (SRP) — MODULE 1: eBPF/XDP KERNEL FILTER
 *  ============================================================================
 *  System Authority : Universal Root Authority
 *  Version          : 2026.4.2-Production
 *  Engine           : BCC-compiled eBPF/XDP hook (tc / xdp)
 *
 *  Purpose:
 *    Attaches to the ingress/egress path of any network interface and enforces
 *    line-rate packet filtering using the sovereign_approval BPF hash map.
 *    Traffic to port 443 is checked against the map:
 *      0x01 (Active Agent)  → XDP_PASS
 *      0xFF (Quarantine)    → XDP_DROP  (zero-byte network drop)
 *      absent / 0x00        → XDP_PASS  (non-AI traffic pass-through)
 *
 *  Architectural References:
 *    - architecture.md §1 (Gatekeeper Bit, OTP eFuse)
 *    - architecture.md §3 (eBPF Network-Layer Hook)
 *    - agents.md §1 (Al-Mir Sentry — DPI on Port 443)
 *    - agents.md §2 (Decision Logic Matrix — state 0x01, 0xFF)
 *    - workflow.md §1 Stage 1-2 (Inhale & Transit)
 *  ============================================================================
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
#include <linux/version.h>

/* ===========================================================================
 *  SOVEREIGN APPROVAL MAP
 *  ===========================================================================
 *  Defined exactly as specified:
 *    BPF_HASH(sovereign_approval, u32, u32);
 *
 *  Key   : u32 — source IPv4 address of the connecting node (network byte order)
 *  Value : u32 — gatekeeper enforcement state:
 *            0x01  → XDP_PASS  (Active Agent — sovereign key valid)
 *            0xFF  → XDP_DROP  (Al-Qahr Quarantine — zero-byte drop)
 *            other → XDP_PASS  (fallback, non-AI or unclassified traffic)
 *
 *  Maximum entries: 65536 (covers large enterprise deployments)
 * ===========================================================================
 */
BPF_HASH(sovereign_approval, __u32, __u32, 65536);

/* ===========================================================================
 *  SOVEREIGN METRICS COUNTERS (Per-CPU for lockless accounting)
 *  ===========================================================================
 *  Index 0: total packets inspected by the hook
 *  Index 1: packets passed (XDP_PASS) — approved or non-AI
 *  Index 2: packets dropped (XDP_DROP) — quarantine enforcement
 * ===========================================================================
 */
BPF_PERCPU_ARRAY(sovereign_metrics, __u64, 3);

/* ===========================================================================
 *  CONSTANTS
 *  ===========================================================================
 *  These match the agents.md Decision Logic Matrix:
 *    0x01 — Active Agent   (Awaiting Pulse / Sovereign Key issued)
 *    0xFF — Al-Qahr Quarantine (immediate isolation)
 * ===========================================================================
 */
#define GATEKEEPER_ACTIVE    0x01
#define GATEKEEPER_QUARANTINE 0xFF
#define AI_TARGET_PORT       443

/* ===========================================================================
 *  sovereign_xdp_ingress — Main XDP enforcement hook
 *  ===========================================================================
 *  Attached to the ingress path. Inspects every inbound IPv4 TCP packet
 *  destined for port 443. Looks up the source IP in sovereign_approval and
 *  enforces line-rate pass/drop.
 *
 *  Returns:
 *    XDP_PASS — Allow packet through (approved or non-AI traffic)
 *    XDP_DROP — Drop packet immediately (Al-Qahr zero-byte enforcement)
 * ===========================================================================
 */
int sovereign_xdp_ingress(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    /* ---- Layer 2: Ethernet ---- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* ---- Layer 3: IP ---- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* ---- Layer 4: TCP ---- */
    __u32 ip_header_len = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Increment total inspected counter */
    __u32 idx_total = 0;
    __u64 *counter = sovereign_metrics.lookup(&idx_total);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    /* ---- Al-Mir Deep Packet Inspection: Port 443 ---- */
    __u16 dest_port = tcp->dest;
    if (dest_port != __constant_htons(AI_TARGET_PORT))
        return XDP_PASS;

    /* ---- Sovereign Approval Lookup (key = source IP) ---- */
    __u32 src_ip = ip->saddr;
    __u32 *state = sovereign_approval.lookup(&src_ip);

    if (state == NULL) {
        /* IP not in map — pass through (unclassified / non-AI) */
        return XDP_PASS;
    }

    __u32 gatekeeper_state = *state;

    /* ---- 0xFF: Al-Qahr Quarantine — Immediate Zero-Byte Drop ---- */
    if (gatekeeper_state == GATEKEEPER_QUARANTINE) {
        __u32 idx_drop = 2;
        __u64 *drop_ctr = sovereign_metrics.lookup(&idx_drop);
        if (drop_ctr)
            __sync_fetch_and_add(drop_ctr, 1);
        return XDP_DROP;
    }

    /* ---- 0x01: Active Agent — Pass Through ---- */
    if (gatekeeper_state == GATEKEEPER_ACTIVE) {
        __u32 idx_pass = 1;
        __u64 *pass_ctr = sovereign_metrics.lookup(&idx_pass);
        if (pass_ctr)
            __sync_fetch_and_add(pass_ctr, 1);
        return XDP_PASS;
    }

    /* ---- Fallback: any other state passes ---- */
    return XDP_PASS;
}

/* ===========================================================================
 *  sovereign_xdp_egress — Egress enforcement hook (optional)
 *  ===========================================================================
 *  Attached to the egress path for symmetric enforcement. Mirrors the ingress
 *  logic but checks destination IP instead (outbound traffic targeting AI
 *  provider endpoints).
 * ===========================================================================
 */
int sovereign_xdp_egress(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* IP */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* TCP */
    __u32 ip_header_len = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Port check */
    __u16 src_port = tcp->source;
    __u16 dest_port = tcp->dest;

    /* Outbound AI traffic: source port is ephemeral, dest is 443 */
    if (dest_port != __constant_htons(AI_TARGET_PORT))
        return XDP_PASS;

    /* Egress: check destination IP (AI provider endpoint) */
    __u32 dst_ip = ip->daddr;
    __u32 *state = sovereign_approval.lookup(&dst_ip);

    if (state == NULL)
        return XDP_PASS;

    __u32 gatekeeper_state = *state;

    if (gatekeeper_state == GATEKEEPER_QUARANTINE)
        return XDP_DROP;

    return XDP_PASS;
}
