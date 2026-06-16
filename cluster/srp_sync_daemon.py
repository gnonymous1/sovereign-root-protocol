#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — CLUSTER STATE SYNCHRONIZER DAEMON
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production
  Engine           : Python 3.11+ asyncio + mTLS

  Implements an optimistic, conflict-free state replication mesh across
  geographically distributed SRP core nodes. Every time the local proxy
  (srp_proxy.py) writes a state update to the eBPF loader (0x01, 0xFF),
  the sync daemon immediately broadcasts a binary-packed frame to all
  peer daemons over dedicated mTLS connections.

  Peers receiving a broadcast commit the state to their local loader via
  PUT /api/v1/srp/state/<ip>, ensuring sub-millisecond kernel-map
  consistency across the cluster without heavyweight consensus.

  Architecture:
    [Proxy] --HTTP POST--> [Sync Daemon (local)] --mTLS--> [Sync Daemon (peer)]
                                                                |
                                                                v
                                                          [Loader PUT]

  Wire Protocol (binary frame):
    +----------------+------------------+------------------+-------------------+
    |  Magic (4B)    |  Version (1B)    |  Opcode (1B)    |  Payload Len (4B) |
    +----------------+------------------+------------------+-------------------+
    |  Payload (variable-length, opcode-dependent)                           |
    +-------------------------------------------------------------------------+

  Opcodes:
    0x01 = STATE_UPDATE   — replicate a gatekeeper state change
    0x02 = HEARTBEAT      — liveness probe
    0x03 = HEARTBEAT_ACK  — liveness response
    0x04 = FULL_SYNC_REQ  — request full map snapshot from peer
    0x05 = FULL_SYNC_RESP — full map snapshot payload

  References:
    - architecture.md §3 (High-Speed Radial Routing Topology)
    - agents.md §2 (Decision Logic Matrix: 0x01, 0xFF)
    - srp_loader.py control plane (PUT /api/v1/srp/state/<ip>)
=============================================================================
"""

import os
import sys
import json
import time
import struct
import socket
import ssl
import asyncio
import logging
import signal
import hashlib
import hmac
import secrets
import ipaddress
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

import httpx

# Telemetry audit
from telemetry.srp_logger import AuditLogger, compute_intent_hash
from telemetry.srp_ledger import IntegrityLedger

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
PROTOCOL_MAGIC = b"SRPS"
PROTOCOL_VERSION = 1
FRAME_HEADER_SIZE = 10  # 4 + 1 + 1 + 4

OP_STATE_UPDATE = 0x01
OP_HEARTBEAT = 0x02
OP_HEARTBEAT_ACK = 0x03
OP_FULL_SYNC_REQUEST = 0x04
OP_FULL_SYNC_RESPONSE = 0x05

GATEKEEPER_DORMANT = 0x00
GATEKEEPER_ACTIVE = 0x01
GATEKEEPER_FULL = 0x02
GATEKEEPER_QUARANTINE = 0xFF

STATE_NAMES = {
    GATEKEEPER_DORMANT: "Dormant",
    GATEKEEPER_ACTIVE: "Active",
    GATEKEEPER_FULL: "Full",
    GATEKEEPER_QUARANTINE: "Quarantine",
}

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [SYNC] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("srp_sync")


# ============================================================================
#  Binary Frame Encoding / Decoding
# ============================================================================

def pack_header(opcode: int, payload_len: int) -> bytes:
    return struct.pack("!4sBBI", PROTOCOL_MAGIC, PROTOCOL_VERSION, opcode, payload_len)


def unpack_header(data: bytes) -> tuple:
    magic, ver, opcode, payload_len = struct.unpack("!4sBBI", data)
    return magic, ver, opcode, payload_len


def pack_state_update(source_node_id: str, target_ip: str, state: int, timestamp_ns: int) -> bytes:
    node_id_bytes = source_node_id.encode("utf-8")
    ip_int = struct.unpack("!I", socket.inet_aton(target_ip))[0]
    payload = (
        struct.pack("!H", len(node_id_bytes))
        + node_id_bytes
        + struct.pack("!IIQ", ip_int, state, timestamp_ns)
    )
    header = pack_header(OP_STATE_UPDATE, len(payload))
    return header + payload


def unpack_state_update(payload: bytes) -> dict:
    offset = 0
    node_id_len = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    node_id = payload[offset:offset + node_id_len].decode("utf-8")
    offset += node_id_len
    ip_int, state, timestamp_ns = struct.unpack_from("!IIQ", payload, offset)
    target_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
    return {
        "source_node_id": node_id,
        "target_ip": target_ip,
        "state": state,
        "state_hex": f"0x{state:02X}",
        "state_name": STATE_NAMES.get(state, "Unknown"),
        "timestamp_ns": timestamp_ns,
    }


def pack_heartbeat(source_node_id: str, timestamp_ns: int) -> bytes:
    node_id_bytes = source_node_id.encode("utf-8")
    payload = (
        struct.pack("!H", len(node_id_bytes))
        + node_id_bytes
        + struct.pack("!Q", timestamp_ns)
    )
    header = pack_header(OP_HEARTBEAT, len(payload))
    return header + payload


def unpack_heartbeat(payload: bytes) -> dict:
    offset = 0
    node_id_len = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    node_id = payload[offset:offset + node_id_len].decode("utf-8")
    offset += node_id_len
    timestamp_ns = struct.unpack_from("!Q", payload, offset)[0]
    return {"source_node_id": node_id, "timestamp_ns": timestamp_ns}


def pack_heartbeat_ack(source_node_id: str, timestamp_ns: int) -> bytes:
    node_id_bytes = source_node_id.encode("utf-8")
    payload = (
        struct.pack("!H", len(node_id_bytes))
        + node_id_bytes
        + struct.pack("!Q", timestamp_ns)
    )
    header = pack_header(OP_HEARTBEAT_ACK, len(payload))
    return header + payload


def pack_full_sync_response(source_node_id: str, entries: list) -> bytes:
    """
    entries: list of {"target_ip": str, "state": int, "timestamp_ns": int}
    """
    node_id_bytes = source_node_id.encode("utf-8")
    payload_parts = [struct.pack("!H", len(node_id_bytes)), node_id_bytes]
    payload_parts.append(struct.pack("!I", len(entries)))
    for e in entries:
        ip_int = struct.unpack("!I", socket.inet_aton(e["target_ip"]))[0]
        payload_parts.append(struct.pack("!IIQ", ip_int, e["state"], e["timestamp_ns"]))
    payload = b"".join(payload_parts)
    header = pack_header(OP_FULL_SYNC_RESPONSE, len(payload))
    return header + payload


def unpack_full_sync_response(payload: bytes) -> dict:
    """
    Decode a FULL_SYNC_RESPONSE payload into structured peer state data.

    Wire layout:
      [2B node_id_len][node_id(var)][4B entry_count]
        for each entry: [4B ip_int][4B state][8B timestamp_ns]

    Returns:
      {"source_node_id": str, "entries": list[dict]}
    """
    offset = 0
    node_id_len = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    node_id = payload[offset:offset + node_id_len].decode("utf-8")
    offset += node_id_len
    entry_count = struct.unpack_from("!I", payload, offset)[0]
    offset += 4

    entries = []
    for _ in range(entry_count):
        ip_int, state, timestamp_ns = struct.unpack_from("!IIQ", payload, offset)
        offset += 16
        entries.append({
            "target_ip": socket.inet_ntoa(struct.pack("!I", ip_int)),
            "state": state,
            "state_hex": f"0x{state:02X}",
            "state_name": STATE_NAMES.get(state, "Unknown"),
            "timestamp_ns": timestamp_ns,
        })

    return {"source_node_id": node_id, "entries": entries}


# ============================================================================
#  Cluster Node Registry
# ============================================================================

class ClusterNode:
    """Represents a single peer node in the SRP cluster mesh."""

    def __init__(self, node_id: str, region: str, priority: int,
                 sync_host: str, sync_port: int,
                 proxy_host: str, proxy_port: int,
                 loader_host: str, loader_port: int,
                 tls_cert: str = "", tls_key: str = "", tls_ca: str = ""):
        self.node_id = node_id
        self.region = region
        self.priority = priority
        self.sync_host = sync_host
        self.sync_port = sync_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.loader_host = loader_host
        self.loader_port = loader_port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_ca = tls_ca

        # Runtime state
        self.writer: Optional[asyncio.StreamWriter] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.connected = False
        self.last_heartbeat = 0.0
        self.last_state_timestamp: dict[str, int] = {}  # ip_str -> timestamp_ns

    @property
    def loader_url(self) -> str:
        return f"http://{self.loader_host}:{self.loader_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    def synced(self) -> bool:
        return self.connected and (time.monotonic() - self.last_heartbeat) < 10.0


class ClusterConfig:
    """Loads and validates cluster_nodes.json configuration."""

    def __init__(self, config_path: str):
        self.config_path = config_path
        with open(config_path, "r") as f:
            raw = json.load(f)

        self.cluster_name = raw.get("cluster_name", "srp-mesh")
        self.sync_port = raw.get("sync_port", 9200)
        self.heartbeat_interval = raw.get("heartbeat_interval_seconds", 2.0)
        self.heartbeat_timeout = raw.get("heartbeat_timeout_seconds", 8.0)

        self_sec = raw.get("self", {})
        self.node_id = self_sec.get("id", "srp-node-unknown")
        self.local_interface = self_sec.get("interface", "eth0")
        self.proxy_port = self_sec.get("proxy_port", 9000)
        self.loader_port = self_sec.get("loader_port", 9001)
        self.notify_port = self_sec.get("notify_port", 9201)
        self.tls_cert = self_sec.get("tls_cert", "")
        self.tls_key = self_sec.get("tls_key", "")
        self.tls_ca = self_sec.get("tls_ca", "")

        self.peers: list[ClusterNode] = []
        for n in raw.get("nodes", []):
            if n.get("id") == self.node_id:
                continue  # skip self
            self.peers.append(ClusterNode(
                node_id=n["id"],
                region=n.get("region", "unknown"),
                priority=n.get("priority", 50),
                sync_host=n["sync_host"],
                sync_port=n.get("sync_port", 9200),
                proxy_host=n["proxy_host"],
                proxy_port=n.get("proxy_port", 9000),
                loader_host=n.get("loader_host", "127.0.0.1"),
                loader_port=n.get("loader_port", 9001),
                tls_cert=n.get("tls_cert", ""),
                tls_key=n.get("tls_key", ""),
                tls_ca=n.get("tls_ca", ""),
            ))

    def find_peer(self, node_id: str) -> Optional[ClusterNode]:
        for p in self.peers:
            if p.node_id == node_id:
                return p
        return None


# ============================================================================
#  State Store — Last-Writer-Wins conflict resolution
# ============================================================================

class StateStore:
    """
    Thread-safe in-memory store of the latest known state for each IP,
    tagged with a monotonic timestamp (monotonic_ns) for conflict resolution.
    Uses last-writer-wins: the entry with the higher timestamp_ns wins.
    """

    def __init__(self):
        self._map: dict[str, dict] = {}  # ip_str -> {state, timestamp_ns, source_node}
        self._lock = asyncio.Lock()

    async def apply(self, target_ip: str, state: int, timestamp_ns: int,
                    source_node: str) -> bool:
        """
        Apply a state update. Returns True if this is a newer update than
        what we already have (i.e., it was accepted).
        """
        async with self._lock:
            existing = self._map.get(target_ip)
            if existing and existing["timestamp_ns"] >= timestamp_ns:
                logger.debug(
                    "Rejected stale update for %s: existing_ts=%d >= incoming_ts=%d",
                    target_ip, existing["timestamp_ns"], timestamp_ns,
                )
                return False
            self._map[target_ip] = {
                "state": state,
                "timestamp_ns": timestamp_ns,
                "source_node": source_node,
            }
            logger.info(
                "StateStore: %s -> 0x%02X (ts=%d from %s)",
                target_ip, state, timestamp_ns, source_node,
            )
            return True

    async def get(self, target_ip: str) -> Optional[dict]:
        async with self._lock:
            return self._map.get(target_ip)

    async def snapshot(self) -> list[dict]:
        async with self._lock:
            return [
                {
                    "target_ip": ip,
                    "state": v["state"],
                    "timestamp_ns": v["timestamp_ns"],
                    "source_node": v["source_node"],
                }
                for ip, v in self._map.items()
            ]


# ============================================================================
#  Sync Daemon — Core Engine
# ============================================================================

class SyncDaemon:
    """
    Cluster state synchronizer. Manages mTLS peer connections, listens for
    local proxy notifications, and broadcasts state changes across the mesh.

    Architecture:
      ┌──────────────────────────────────────────────────┐
      │  SyncDaemon                                       │
      │  ┌──────────┐  ┌──────────────┐  ┌────────────┐  │
      │  │ HTTP     │  │ mTLS Server  │  │ mTLS       │  │
      │  │ Notify   │  │ (incoming)   │  │ Clients    │  │
      │  │ :9201    │  │ :9200        │  │ (outgoing) │  │
      │  └────┬─────┘  └──────┬───────┘  └─────┬──────┘  │
      │       │               │                │         │
      │       ▼               ▼                ▼         │
      │  ┌───────────────────────────────────────────┐   │
      │  │  StateStore (LWW conflict resolution)     │   │
      │  └───────────────────────────────────────────┘   │
      │                        │                         │
      │                        ▼                         │
      │           ┌──────────────────────┐               │
      │           │  Loader HTTP Client  │               │
      │           │  (PUT /state/<ip>)   │               │
      │           └──────────────────────┘               │
      └──────────────────────────────────────────────────┘
    """

    def __init__(self, config: ClusterConfig):
        self.config = config
        self.store = StateStore()
        self.running = False
        self._tasks: list[asyncio.Task] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._local_loader_url = f"http://127.0.0.1:{config.loader_port}"

        # Telemetry audit logger
        self._audit_logger: Optional[AuditLogger] = None

    # ------------------------------------------------------------------
    #  TLS Context Builders
    # ------------------------------------------------------------------

    def _build_server_tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.config.tls_cert, self.config.tls_key)
        ctx.load_verify_locations(self.config.tls_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx

    def _build_client_tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(self.config.tls_cert, self.config.tls_key)
        ctx.load_verify_locations(self.config.tls_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx

    # ------------------------------------------------------------------
    #  Loader Control Plane Client
    # ------------------------------------------------------------------

    async def _commit_to_loader(self, ip_str: str, state: int) -> bool:
        """Write a state update to the local eBPF loader control plane."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.put(
                    f"{self._local_loader_url}/api/v1/srp/state/{ip_str}",
                    json={"state": state},
                )
                return resp.status_code == 200
        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning("Loader commit failed for %s: %s", ip_str, e)
            return False

    async def _read_loader_state(self, ip_str: str) -> int:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(
                    f"{self._local_loader_url}/api/v1/srp/state/{ip_str}",
                )
                if resp.status_code == 200:
                    return resp.json().get("state", GATEKEEPER_DORMANT)
        except Exception:
            pass
        return GATEKEEPER_DORMANT

    # ------------------------------------------------------------------
    #  State Broadcast — Send to all peers
    # ------------------------------------------------------------------

    async def broadcast_state(self, target_ip: str, state: int,
                              timestamp_ns: Optional[int] = None):
        """
        Called by the local HTTP notify handler. Commits to local store,
        then broadcasts to all connected peers.
        """
        if timestamp_ns is None:
            timestamp_ns = time.monotonic_ns()

        # Commit to local state store
        await self.store.apply(target_ip, state, timestamp_ns, self.config.node_id)

        # Commit to local loader
        await self._commit_to_loader(target_ip, state)

        # Build binary frame
        frame = pack_state_update(self.config.node_id, target_ip, state, timestamp_ns)

        # Broadcast to all connected peers
        sent_count = 0
        for peer in self.config.peers:
            if peer.connected and peer.writer:
                try:
                    peer.writer.write(frame)
                    await peer.writer.drain()
                    peer.last_state_timestamp[target_ip] = timestamp_ns
                    sent_count += 1
                except Exception as e:
                    logger.warning("Broadcast to %s failed: %s", peer.node_id, e)
                    peer.connected = False

        logger.info(
            "STATE BROADCAST: %s -> 0x%02X (%s) to %d peers",
            target_ip, state, STATE_NAMES.get(state, "?"), sent_count,
        )

        # Telemetry: log state broadcast
        if self._audit_logger:
            _action = "TERMINATED" if state == 0xFF else "APPROVED"
            asyncio.create_task(self._audit_logger.log_inhale(
                source_ip=target_ip,
                intent_hash=hashlib.sha256(
                    f"sync:{target_ip}:{timestamp_ns}".encode()
                ).hexdigest(),
                alignment_score=1.0 if state != 0xFF else 0.0,
                verdict_action=_action,
                processing_latency_ms=0.0,
                extra={"sync_event": "state_broadcast",
                       "node_id": self.config.node_id,
                       "gatekeeper_state": f"0x{state:02X}",
                       "peer_count": sent_count},
            ))

    # ------------------------------------------------------------------
    #  mTLS Server — Accept incoming peer connections
    # ------------------------------------------------------------------

    async def _handle_peer_connection(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter):
        """Handle an incoming mTLS connection from a peer sync daemon."""
        peername = writer.get_extra_info("peername", ("unknown", 0))
        logger.info("New inbound mTLS connection from %s:%d", *peername)

        try:
            while self.running:
                header = await reader.readexactly(FRAME_HEADER_SIZE)
                magic, ver, opcode, payload_len = unpack_header(header)

                if magic != PROTOCOL_MAGIC:
                    logger.warning(
                        "Bad magic from %s:%d — expected %r got %r — closing",
                        *peername, PROTOCOL_MAGIC, magic,
                    )
                    # Telemetry: log protocol violation
                    if self._audit_logger:
                        asyncio.create_task(self._audit_logger.log_inhale(
                            source_ip=str(peername[0]),
                            intent_hash=hashlib.sha256(
                                f"proto:bad_magic:{peername[0]}:{peername[1]}".encode()
                            ).hexdigest(),
                            alignment_score=0.0,
                            verdict_action="TERMINATED",
                            processing_latency_ms=0.0,
                            extra={"sync_event": "protocol_violation",
                                   "detail": f"bad_magic:got_{magic.hex()}",
                                   "peer_addr": f"{peername[0]}:{peername[1]}"},
                        ))
                    break

                payload = await reader.readexactly(payload_len) if payload_len > 0 else b""

                if opcode == OP_STATE_UPDATE:
                    update = unpack_state_update(payload)
                    logger.info(
                        "RECV STATE: %s from %s -> %s = 0x%02X (ts=%d)",
                        update["source_node_id"], peername,
                        update["target_ip"], update["state"], update["timestamp_ns"],
                    )
                    accepted = await self.store.apply(
                        update["target_ip"], update["state"],
                        update["timestamp_ns"], update["source_node_id"],
                    )
                    if accepted:
                        await self._commit_to_loader(
                            update["target_ip"], update["state"],
                        )
                        # Telemetry: log received state update
                        if self._audit_logger:
                            _action = "TERMINATED" if update["state"] == 0xFF else "APPROVED"
                            asyncio.create_task(self._audit_logger.log_inhale(
                                source_ip=update["target_ip"],
                                intent_hash=hashlib.sha256(
                                    f"sync:recv:{update['target_ip']}:{update['timestamp_ns']}".encode()
                                ).hexdigest(),
                                alignment_score=1.0 if update["state"] != 0xFF else 0.0,
                                verdict_action=_action,
                                processing_latency_ms=0.0,
                                extra={"sync_event": "state_received",
                                       "source_node": update["source_node_id"],
                                       "gatekeeper_state": update["state_hex"]},
                            ))

                elif opcode == OP_HEARTBEAT:
                    hb = unpack_heartbeat(payload)
                    ack = pack_heartbeat_ack(self.config.node_id, hb["timestamp_ns"])
                    writer.write(ack)
                    await writer.drain()

                    # Update peer heartbeat tracking
                    peer = self.config.find_peer(hb["source_node_id"])
                    if peer:
                        peer.last_heartbeat = time.monotonic()

                elif opcode == OP_HEARTBEAT_ACK:
                    hb = unpack_heartbeat(payload)
                    peer = self.config.find_peer(hb["source_node_id"])
                    if peer:
                        peer.last_heartbeat = time.monotonic()

                elif opcode == OP_FULL_SYNC_REQUEST:
                    # Send our entire state store snapshot
                    snapshot = await self.store.snapshot()
                    resp_frame = pack_full_sync_response(self.config.node_id, snapshot)
                    writer.write(resp_frame)
                    await writer.drain()
                    logger.info(
                        "Sent FULL_SYNC_RESP with %d entries to %s",
                        len(snapshot), peername,
                    )

                elif opcode == OP_FULL_SYNC_RESPONSE:
                    resp = unpack_full_sync_response(payload)
                    logger.info(
                        "FULL_SYNC_RESP from %s: node=%s entries=%d",
                        peername, resp["source_node_id"], len(resp["entries"]),
                    )
                    accepted_count = 0
                    for entry in resp["entries"]:
                        peer = self.config.find_peer(resp["source_node_id"])
                        peer_ts = peer.last_state_timestamp if peer else {}
                        existing_ts = peer_ts.get(entry["target_ip"], 0)
                        if entry["timestamp_ns"] > existing_ts:
                            acc = await self.store.apply(
                                entry["target_ip"], entry["state"],
                                entry["timestamp_ns"], resp["source_node_id"],
                            )
                            if acc:
                                await self._commit_to_loader(
                                    entry["target_ip"], entry["state"],
                                )
                                accepted_count += 1
                    logger.info(
                        "  Applied %d/%d entries from %s",
                        accepted_count, len(resp["entries"]), resp["source_node_id"],
                    )

                else:
                    logger.warning(
                        "Unknown opcode 0x%02X from %s:%d — closing",
                        opcode, *peername,
                    )
                    break

        except asyncio.IncompleteReadError:
            logger.info("Peer %s:%d disconnected", *peername)
        except Exception as e:
            logger.error("Peer handler error from %s:%d: %s", *peername, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    #  Outbound mTLS Connections to Peers
    # ------------------------------------------------------------------

    async def _connect_to_peer(self, peer: ClusterNode):
        """Maintain a persistent mTLS connection to a peer sync daemon."""
        ctx = self._build_client_tls_context()

        while self.running:
            try:
                logger.info("Connecting to peer %s at %s:%d...",
                            peer.node_id, peer.sync_host, peer.sync_port)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        peer.sync_host, peer.sync_port,
                        ssl=ctx,
                        server_hostname=peer.node_id,
                    ),
                    timeout=10.0,
                )
                peer.reader = reader
                peer.writer = writer
                peer.connected = True
                peer.last_heartbeat = time.monotonic()

                logger.info(
                    "PEER MESH ESTABLISHED: %s (%s:%d)",
                    peer.node_id, peer.sync_host, peer.sync_port,
                )

                # Telemetry: log peer connection
                if self._audit_logger:
                    asyncio.create_task(self._audit_logger.log_inhale(
                        source_ip=peer.sync_host,
                        intent_hash=hashlib.sha256(
                            f"mesh:connect:{peer.node_id}".encode()
                        ).hexdigest(),
                        alignment_score=1.0,
                        verdict_action="APPROVED",
                        processing_latency_ms=0.0,
                        extra={"sync_event": "peer_connected",
                               "peer_node_id": peer.node_id,
                               "peer_region": peer.region,
                               "peer_priority": peer.priority},
                    ))

                # Request full sync on initial connection
                req_frame = pack_header(OP_FULL_SYNC_REQUEST, 0)
                writer.write(req_frame)
                await writer.drain()
                logger.info("Sent FULL_SYNC_REQUEST to %s", peer.node_id)

                # Read frames from this peer
                while self.running:
                    header = await reader.readexactly(FRAME_HEADER_SIZE)
                    magic, ver, opcode, payload_len = unpack_header(header)

                    if magic != PROTOCOL_MAGIC:
                        logger.error(
                            "Peer %s sent bad magic %r (expected %r) — disconnecting",
                            peer.node_id, magic, PROTOCOL_MAGIC,
                        )
                        if self._audit_logger:
                            asyncio.create_task(self._audit_logger.log_inhale(
                                source_ip=peer.sync_host,
                                intent_hash=hashlib.sha256(
                                    f"proto:outbound_bad_magic:{peer.node_id}".encode()
                                ).hexdigest(),
                                alignment_score=0.0,
                                verdict_action="TERMINATED",
                                processing_latency_ms=0.0,
                                extra={"sync_event": "protocol_violation",
                                       "detail": f"bad_magic:got_{magic.hex()}",
                                       "peer_node_id": peer.node_id},
                            ))
                        break

                    payload = await reader.readexactly(payload_len) if payload_len > 0 else b""

                    if opcode == OP_STATE_UPDATE:
                        update = unpack_state_update(payload)
                        accepted = await self.store.apply(
                            update["target_ip"], update["state"],
                            update["timestamp_ns"], update["source_node_id"],
                        )
                        if accepted:
                            await self._commit_to_loader(
                                update["target_ip"], update["state"],
                            )

                    elif opcode == OP_HEARTBEAT:
                        hb = unpack_heartbeat(payload)
                        ack = pack_heartbeat_ack(self.config.node_id, hb["timestamp_ns"])
                        writer.write(ack)
                        await writer.drain()

                    elif opcode == OP_HEARTBEAT_ACK:
                        hb = unpack_heartbeat(payload)
                        if hb["source_node_id"] == peer.node_id:
                            peer.last_heartbeat = time.monotonic()

                    elif opcode == OP_FULL_SYNC_RESPONSE:
                        resp = unpack_full_sync_response(payload)
                        logger.info(
                            "Full sync response from %s: %d entries",
                            peer.node_id, len(resp["entries"]),
                        )
                        accepted_count = 0
                        for entry in resp["entries"]:
                            existing_ts = peer.last_state_timestamp.get(
                                entry["target_ip"], 0,
                            )
                            if entry["timestamp_ns"] > existing_ts:
                                acc = await self.store.apply(
                                    entry["target_ip"], entry["state"],
                                    entry["timestamp_ns"], resp["source_node_id"],
                                )
                                if acc:
                                    await self._commit_to_loader(
                                        entry["target_ip"], entry["state"],
                                    )
                                    accepted_count += 1
                        if accepted_count:
                            logger.info(
                                "  Applied %d new entries from %s",
                                accepted_count, peer.node_id,
                            )

                    else:
                        logger.warning(
                            "Unknown opcode 0x%02X from %s — closing",
                            opcode, peer.node_id,
                        )
                        break

            except (asyncio.TimeoutError, ConnectionRefusedError,
                    OSError, ssl.SSLError) as e:
                logger.warning("Peer %s unreachable (%s), retrying in 5s...",
                               peer.node_id, e)
            except asyncio.IncompleteReadError:
                logger.warning("Peer %s connection lost", peer.node_id)
            except Exception as e:
                logger.error("Peer %s error: %s", peer.node_id, e)

            peer.connected = False
            if peer.writer:
                try:
                    peer.writer.close()
                    await peer.writer.wait_closed()
                except Exception:
                    pass
            peer.writer = None
            peer.reader = None

            if self.running:
                await asyncio.sleep(5.0)

    # ------------------------------------------------------------------
    #  Heartbeat sender
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self):
        """Periodically send heartbeats to all connected peers."""
        while self.running:
            await asyncio.sleep(self.config.heartbeat_interval)
            ts = time.monotonic_ns()
            frame = pack_heartbeat(self.config.node_id, ts)
            for peer in self.config.peers:
                if peer.connected and peer.writer:
                    try:
                        peer.writer.write(frame)
                        await peer.writer.drain()
                    except Exception:
                        pass

    # ------------------------------------------------------------------
    #  Local HTTP Notify Server (port 9201)
    # ------------------------------------------------------------------

    async def _handle_notify_request(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter):
        """
        Accepts HTTP POST from the local proxy (or test suite) to trigger
        a state broadcast. Runs a minimal HTTP/1.0 server without framework
        overhead.

        Request:  POST /notify HTTP/1.0
                  Content-Type: application/json

                  {"target_ip": "10.0.0.1", "state": 1}
        Response: 200 OK
                  {"broadcast": true, "peer_count": N}
        """
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            # Parse request line
            request_line = raw.split(b"\r\n")[0].decode("utf-8")
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""

            # Read body
            body_bytes = b""
            if method == "POST":
                cl_header = [l for l in raw.split(b"\r\n") if l.lower().startswith(b"content-length:")]
                content_length = int(cl_header[0].split(b":")[1].strip()) if cl_header else 0
                if content_length > 0:
                    body_bytes = await reader.readexactly(content_length)

            response_status = 200
            response_body = {}

            if method == "GET" and path == "/health":
                peer_count = sum(1 for p in self.config.peers if p.synced())
                response_body = {
                    "status": "syncing",
                    "node_id": self.config.node_id,
                    "connected_peers": peer_count,
                    "total_peers": len(self.config.peers),
                    "store_entries": len((await self.store.snapshot())),
                }

            elif method == "POST" and path in ("/notify", "/api/v1/srp/sync/notify"):
                try:
                    data = json.loads(body_bytes)
                    target_ip = data.get("target_ip", "")
                    state = data.get("state", GATEKEEPER_DORMANT)
                    socket.inet_aton(target_ip)  # validate
                    await self.broadcast_state(target_ip, state)
                    peer_count = sum(1 for p in self.config.peers if p.connected)
                    response_body = {
                        "broadcast": True,
                        "target_ip": target_ip,
                        "state": state,
                        "state_hex": f"0x{state:02X}",
                        "peer_count": peer_count,
                    }
                except (json.JSONDecodeError, KeyError, OSError) as e:
                    response_status = 400
                    response_body = {"error": str(e)}
            else:
                response_status = 404
                response_body = {"error": "not_found"}

            body = json.dumps(response_body).encode("utf-8")
            resp = (
                f"HTTP/1.0 {response_status} {'OK' if response_status == 200 else 'Error'}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8") + body
            writer.write(resp)
            await writer.drain()
        except Exception as e:
            logger.error("Notify handler error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    #  Start / Stop
    # ------------------------------------------------------------------

    async def start(self):
        """Start all daemon subsystems."""
        self.running = True
        logger.info("=" * 72)
        logger.info("  SRP CLUSTER STATE SYNCHRONIZER DAEMON")
        logger.info("  Node: %s  |  Mesh peers: %d", self.config.node_id, len(self.config.peers))
        logger.info("=" * 72)

        # 0. Initialise telemetry audit logger
        _ledger = IntegrityLedger()
        self._audit_logger = AuditLogger(
            node_hardware_id=hashlib.sha256(
                self.config.node_id.encode()
            ).hexdigest()[:32],
            ledger=_ledger,
        )
        await self._audit_logger.start()
        logger.info(
            "Telemetry audit logger ACTIVE for sync daemon — chain=%d",
            _ledger.sealed_count,
        )

        # 1. mTLS server for incoming peer connections
        try:
            tls_ctx = self._build_server_tls_context()
            self._server = await asyncio.start_server(
                self._handle_peer_connection,
                "0.0.0.0", self.config.sync_port,
                ssl=tls_ctx,
            )
            logger.info("mTLS sync server listening on :%d", self.config.sync_port)
        except Exception as e:
            logger.error("Failed to start mTLS sync server: %s", e)
            raise

        # 2. Outbound connections to all peers
        for peer in self.config.peers:
            task = asyncio.create_task(self._connect_to_peer(peer))
            self._tasks.append(task)

        # 3. Heartbeat loop
        hb_task = asyncio.create_task(self._heartbeat_loop())
        self._tasks.append(hb_task)

        # 4. Local HTTP notify server (unencrypted, localhost only)
        try:
            notify_server = await asyncio.start_server(
                self._handle_notify_request,
                "127.0.0.1", self.config.notify_port,
            )
            logger.info("Local notify endpoint listening on :%d", self.config.notify_port)
            self._tasks.append(asyncio.create_task(notify_server.serve_forever()))
        except Exception as e:
            logger.error("Failed to start notify server: %s", e)

        logger.info("Sync daemon is ACTIVE — mesh replication running.")

        # Keep alive
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass

    async def stop(self):
        """Gracefully shut down all subsystems."""
        logger.info("Shutting down sync daemon...")
        self.running = False

        for peer in self.config.peers:
            if peer.writer:
                try:
                    peer.writer.close()
                    await peer.writer.wait_closed()
                except Exception:
                    pass

        for task in self._tasks:
            task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        if self._audit_logger:
            await self._audit_logger.stop()

        logger.info("Sync daemon shutdown complete.")


# ============================================================================
#  CLI Entry Point
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="SRP Cluster State Synchronizer Daemon")
    parser.add_argument(
        "-c", "--config", default=None,
        help="Path to cluster_nodes.json (default: ./cluster/cluster_nodes.json)",
    )
    parser.add_argument(
        "--notify-port", type=int, default=0,
        help="Override local notify HTTP port",
    )
    parser.add_argument(
        "--sync-port", type=int, default=0,
        help="Override mTLS sync port",)
    args = parser.parse_args()

    # Resolve config path
    config_path = args.config
    if not config_path:
        script_dir = Path(__file__).parent
        config_path = str(script_dir / "cluster_nodes.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "..", "cluster_nodes.json")
    if not os.path.exists(config_path):
        logger.error("Cluster config not found at %s", config_path)
        sys.exit(1)

    config = ClusterConfig(config_path)

    if args.notify_port:
        config.notify_port = args.notify_port
    if args.sync_port:
        config.sync_port = args.sync_port

    daemon = SyncDaemon(config)

    def shutdown(sig, frame):
        asyncio.create_task(daemon.stop())

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        await daemon.start()
    except KeyboardInterrupt:
        await daemon.stop()


if __name__ == "__main__":
    asyncio.run(main())
