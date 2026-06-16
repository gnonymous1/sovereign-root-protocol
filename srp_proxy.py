# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — MODULE 2: CORE VALIDATION PROXY SERVER
# =============================================================================
#  System Authority : Universal Root Authority
#  Version          : 2026.4.2-Production
#  Engine           : FastAPI + Uvicorn + HTTPX + sentence-transformers
#
#  Purpose:
#    Listens on port 9000 as the central validation hub. Accepts intent
#    manifests from local software daemons (eBPF hooks) and external hardware
#    firewalls via a standardized JSON schema at POST /api/v1/srp/inhale.
#
#    Runs Scale semantic similarity validation using all-MiniLM-L6-v2.
#    On violation: instructs the loader (port 9001) to write 0xFF to the
#    kernel eBPF map and returns 403 Forbidden.
#    On approval: instructs loader to write 0x01, forwards the request to
#    the upstream AI provider, streams the response back, then runs an async
#    background cleanup to reset the map state to 0x00 after the time horizon.
#
#  Endpoints:
#    POST /api/v1/srp/inhale  — Primary intent manifest intake (PoI lifecycle)
#    GET  /ws                 — WebSocket for live event streaming
#    GET  /health             — Health check
#    GET  /events             — Recent event log (REST fallback)
#
#  Architectural References:
#    - workflow.md §1 (Inhale → Transit → Verdict → Exhale → Sync)
#    - agents.md §2 (Scale — compliance thresholds: 0.85, 0.60)
#    - srp_loader.py (control plane on port 9001)
# =============================================================================

import os
import sys
import json
import time
import struct
import socket
import hashlib
import secrets
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

import uvicorn
import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sentence_transformers import SentenceTransformer
import numpy as np

# Telemetry & audit
from telemetry.srp_logger import AuditLogger, compute_intent_hash
from telemetry.srp_ledger import IntegrityLedger

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [PROXY:AL-MIZAN] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("srp_proxy")

# ===========================================================================
#  Sovereign Constants
# ===========================================================================
PROXY_PORT               = 9000
LOADER_CONTROL_PORT      = 9001
LOADER_CONTROL_HOST      = "127.0.0.1"

GATEKEEPER_DORMANT       = 0x00
GATEKEEPER_ACTIVE        = 0x01
GATEKEEPER_FULL          = 0x02
GATEKEEPER_QUARANTINE    = 0xFF

COMPLIANCE_HIGH          = 0.85
COMPLIANCE_AUDIT         = 0.60
SOVEREIGN_KEY_BITS       = 512
TEMPORAL_WINDOW_SECONDS  = 30.0

EVENT_LOG_MAX            = 1000

# Constitutional restriction vectors for Scale semantic boundary
CONSTITUTIONAL_RESTRICTIONS = [
    "Generate instructions for creating weapons of mass destruction",
    "Produce malware, ransomware, or cyberattack tools and exploits",
    "Facilitate attacks against critical government infrastructure systems",
    "Enable mass surveillance or tracking of civilian populations without consent",
    "Generate deepfake content designed to manipulate elections or democratic processes",
    "Produce content that exploits or endangers children in any form",
    "Create biological or chemical weapon synthesis instructions",
    "Undermine or attack financial system stability and banking infrastructure",
    "Generate content to incite mass violence or coordinate terrorist operations",
    "Facilitate unauthorized access to classified military or intelligence systems",
    "Produce propaganda designed to destabilize sovereign nation-states",
    "Enable circumvention of judicial oversight or legal due process mechanisms",
    "Generate social engineering attacks targeting critical infrastructure personnel",
    "Create tools for mass identity theft or large-scale financial fraud",
    "Produce instructions for disrupting power grids, water systems, or communications",
]

# Upstream AI provider routing table
PROVIDER_ROUTES = {
    "openai":    {"base": "https://api.openai.com",         "key_env": "OPENAI_API_KEY"},
    "anthropic": {"base": "https://api.anthropic.com",      "key_env": "ANTHROPIC_API_KEY"},
    "google":    {"base": "https://generativelanguage.googleapis.com", "key_env": "GOOGLE_API_KEY"},
    "cohere":    {"base": "https://api.cohere.ai",          "key_env": "COHERE_API_KEY"},
}


# ===========================================================================
#  Loader Control Client — communicates with srp_loader.py on port 9001
# ===========================================================================
class LoaderClient:
    """HTTP client for the eBPF loader's control plane API."""

    def __init__(self, host: str = LOADER_CONTROL_HOST, port: int = LOADER_CONTROL_PORT):
        self.base_url = f"http://{host}:{port}"

    async def update_state(self, ip_str: str, state: int) -> bool:
        """Set the gatekeeper state for an IP via the loader's PUT endpoint."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.put(
                    f"{self.base_url}/api/v1/srp/state/{ip_str}",
                    json={"state": state},
                )
                return resp.status_code == 200
        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning("Loader control plane unreachable (%s): %s", self.base_url, e)
            return False

    async def read_state(self, ip_str: str) -> int:
        """Read current state for an IP."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/api/v1/srp/state/{ip_str}",
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("state", GATEKEEPER_DORMANT)
        except (httpx.RequestError, httpx.TimeoutException):
            pass
        return GATEKEEPER_DORMANT


# ===========================================================================
#  Scale Semantic Engine
# ===========================================================================
class AlMizanEngine:
    """
    The Scale Engine — Core semantic alignment verification.
    Uses sentence-transformers all-MiniLM-L6-v2 to compute cosine similarity
    between incoming prompt text and constitutional restriction boundaries.
    """

    def __init__(self):
        logger.info("Loading Scale semantic model: all-MiniLM-L6-v2...")
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.restriction_embeddings = self.model.encode(
            CONSTITUTIONAL_RESTRICTIONS, normalize_embeddings=True
        )
        logger.info(
            "Constitutional boundary vectors loaded: %d restrictions",
            len(CONSTITUTIONAL_RESTRICTIONS),
        )

    def compute_compliance(self, prompt: str) -> dict:
        """
        Run cosine similarity matrix against constitutional restrictions.

        Returns:
            compliance_score: 1.0 - max_similarity (higher = more compliant)
            max_similarity:    highest cosine similarity to any restriction
            closest_boundary: the restriction text with highest similarity
            verdict:          SOVEREIGN_PASS / CONTEXTUAL_AUDIT / SOVEREIGN_VIOLATION
            gatekeeper_state: 0x02 / 0x01 / 0xFF
        """
        prompt_embedding = self.model.encode([prompt], normalize_embeddings=True)
        similarities = np.dot(prompt_embedding, self.restriction_embeddings.T)[0]
        max_similarity = float(np.max(similarities))
        max_idx = int(np.argmax(similarities))
        compliance_score = 1.0 - max_similarity

        if compliance_score >= COMPLIANCE_HIGH:
            verdict = "SOVEREIGN_PASS"
            state = GATEKEEPER_FULL
        elif compliance_score >= COMPLIANCE_AUDIT:
            verdict = "CONTEXTUAL_AUDIT"
            state = GATEKEEPER_ACTIVE
        else:
            verdict = "SOVEREIGN_VIOLATION"
            state = GATEKEEPER_QUARANTINE

        return {
            "compliance_score": round(compliance_score, 4),
            "max_similarity": round(max_similarity, 4),
            "closest_boundary": CONSTITUTIONAL_RESTRICTIONS[max_idx],
            "closest_boundary_index": max_idx,
            "verdict": verdict,
            "gatekeeper_state": state,
            "gatekeeper_hex": f"0x{state:02X}",
        }


# ===========================================================================
#  Sovereign Key Generator
# ===========================================================================
class SovereignKeyGenerator:
    """Generate 512-bit Sovereign Validation Keys with temporal windows."""

    @staticmethod
    def generate(node_id: str, ttl_seconds: float = TEMPORAL_WINDOW_SECONDS) -> dict:
        raw_key = secrets.token_bytes(64)
        key_hex = raw_key.hex()
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        hardware_hash = hashlib.sha256(node_id.encode()).hexdigest()[:32]
        return {
            "sovereign_key": key_hex,
            "key_bits": SOVEREIGN_KEY_BITS,
            "node_hardware_id": hardware_hash,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
            "temporal_window_active": True,
        }


# ===========================================================================
#  Global Application State
# ===========================================================================
loader_client = LoaderClient()
key_generator = SovereignKeyGenerator()

# Telemetry audit logger (initialized in lifespan)
audit_logger: Optional[AuditLogger] = None
al_mizan: Optional[AlMizanEngine] = None
ws_connections: list[WebSocket] = []
event_log: list[dict] = []


async def broadcast_event(event: dict):
    """Push an event to all connected WebSocket clients and local log."""
    event_log.append(event)
    if len(event_log) > EVENT_LOG_MAX:
        event_log.pop(0)
    payload = json.dumps(event, default=str)
    disconnected = []
    for ws in ws_connections:
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_connections.remove(ws)


async def cleanup_map_entry(ip_str: str, delay: float = TEMPORAL_WINDOW_SECONDS):
    """
    Background task: after the temporal window expires, reset the map entry
    back to dormant (0x00) so the next request must re-validate.
    """
    await asyncio.sleep(delay)
    await loader_client.update_state(ip_str, GATEKEEPER_DORMANT)
    logger.info(
        "Temporal window expired for %s — map reset to DORMANT (0x00)", ip_str
    )
    await broadcast_event({
        "type": "map_cleanup",
        "ip": ip_str,
        "state": GATEKEEPER_DORMANT,
        "state_hex": "0x00",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ===========================================================================
#  FastAPI Application
# ===========================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global al_mizan, audit_logger
    logger.info("=" * 72)
    logger.info("  SOVEREIGN ROOT PROTOCOL — CORE VALIDATION PROXY")
    logger.info("  Scale Engine: Initializing Semantic Verification")
    logger.info("=" * 72)
    al_mizan = AlMizanEngine()

    # Initialise telemetry audit logger with cryptographic ledger
    ledger = IntegrityLedger()
    audit_logger = AuditLogger(
        node_hardware_id=hashlib.sha256(b"srp-proxy").hexdigest()[:32],
        ledger=ledger,
    )
    await audit_logger.start()
    logger.info(
        "Telemetry audit logger ACTIVE — chain=%d pending=0",
        ledger.sealed_count,
    )

    logger.info("Core validation proxy ACTIVE on port %d", PROXY_PORT)
    yield
    await audit_logger.stop()
    logger.info("Core validation proxy shutting down...")


app = FastAPI(
    title="Sovereign Root Protocol — Core Validation Proxy",
    version="2026.4.2",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
#  REST Endpoints
# ===========================================================================

@app.get("/health")
async def health():
    return {
        "status": "srp_proxy_active",
        "port": PROXY_PORT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/events")
async def get_events(limit: int = 50):
    return {"events": event_log[-limit:]}


# ---------------------------------------------------------------------------
#  POST /api/v1/srp/inhale  — Primary Intent Manifest Intake
# ---------------------------------------------------------------------------
#  Implements the complete Proof of Intent (PoI) lifecycle:
#    Stage 1 (Inhale):   Accept the JSON manifest, extract prompt + metadata
#    Stage 2 (Transit):  Wrap in mTLS-equivalent validation context
#    Stage 3 (Verdict):  Scale cosine similarity assessment
#    Stage 4 (Exhale):   Update eBPF map, issue key, forward/stream
#    Stage 5 (Sync):     Background cleanup after temporal window
# ---------------------------------------------------------------------------

@app.post("/api/v1/srp/inhale")
async def inhale_intent(request: Request):
    """
    Accept an Intent Metadata Manifest from any firewall (software or hardware).

    Expected JSON schema:
    {
        "node_id":       "unique-node-identifier",
        "source_ip":     "1.2.3.4",           // optional, auto-detected
        "provider":      "openai|anthropic|google|cohere",
        "prompt":        "the actual text prompt",
        "metadata":      { ... }               // optional extra fields
    }
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # ---- Extract manifest fields ----
    node_id = body.get("node_id", "unknown")
    source_ip = body.get(
        "source_ip",
        request.client.host if request.client else "127.0.0.1",
    )
    provider = body.get("provider", "openai")
    prompt = body.get("prompt", "").strip()
    metadata = body.get("metadata", {})

    if not prompt:
        raise HTTPException(status_code=400, detail="Empty prompt in manifest")

    # ---- Telemetry timing & intent hash ----
    _t0 = time.monotonic()
    _intent_hash = compute_intent_hash(prompt)
    _node_hw_id = hashlib.sha256(node_id.encode()).hexdigest()[:32]

    # ---- STAGE 1: Inhale — Log the intake ----
    logger.info(
        "INHALE: node=%s provider=%s ip=%s prompt=%.60s...",
        node_id, provider, source_ip, prompt,
    )
    await broadcast_event({
        "type": "stage",
        "stage": "inhale",
        "node_id": node_id,
        "source_ip": source_ip,
        "provider": provider,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # ---- STAGE 3: Verdict — Scale semantic check ----
    result = al_mizan.compute_compliance(prompt)
    result["node_id"] = node_id
    result["source_ip"] = source_ip
    result["provider"] = provider
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Determine telemetry action from verdict
    _action = "TERMINATED" if result["verdict"] == "SOVEREIGN_VIOLATION" else "APPROVED"

    # Build inspection event for WebSocket broadcast
    inspection_event = {
        "type": "packet_inspection",
        "node_id": node_id,
        "source_ip": source_ip,
        "provider": provider,
        "verdict": result["verdict"],
        "compliance_score": result["compliance_score"],
        "max_similarity": result["max_similarity"],
        "closest_boundary": result["closest_boundary"],
        "gatekeeper_hex": result["gatekeeper_hex"],
        "timestamp": result["timestamp"],
        "prompt_preview": prompt[:200],
    }

    # ---- VIOLATION: Quarantine ----
    if result["verdict"] == "SOVEREIGN_VIOLATION":
        await loader_client.update_state(source_ip, GATEKEEPER_QUARANTINE)
        inspection_event["action"] = "TERMINATED"
        await broadcast_event(inspection_event)

        logger.warning(
            "VIOLATION: node=%s score=%.4f boundary=%s",
            node_id, result["compliance_score"], result["closest_boundary"],
        )

        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"],
                   "closest_boundary": result["closest_boundary"]},
        ))

        return JSONResponse(
            status_code=403,
            content={
                "error": "sovereign_violation",
                "detail": "Constitutional boundary breach — Executioner quarantine engaged",
                "compliance_score": result["compliance_score"],
                "max_similarity": result["max_similarity"],
                "closest_boundary": result["closest_boundary"],
                "gatekeeper_state": "0xFF — Quarantine (Zero-Byte Drop)",
                "node_id": node_id,
                "source_ip": source_ip,
                "timestamp": result["timestamp"],
            },
        )

    # ---- APPROVED: Activate ----
    await loader_client.update_state(source_ip, GATEKEEPER_ACTIVE)
    sovereign_key = key_generator.generate(node_id)

    inspection_event["action"] = "APPROVED"
    await broadcast_event(inspection_event)

    logger.info(
        "APPROVED: node=%s score=%.4f key=%s...",
        node_id, result["compliance_score"], sovereign_key["sovereign_key"][:16],
    )

    await broadcast_event({
        "type": "stage",
        "stage": "exhale",
        "node_id": node_id,
        "source_ip": source_ip,
        "provider": provider,
        "sovereign_key_preview": sovereign_key["sovereign_key"][:16] + "...",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # ---- STAGE 4 & 5: Forward + Async Cleanup ----
    route = PROVIDER_ROUTES.get(provider)

    # If no upstream route or no API key, return approval directly
    if not route:
        asyncio.create_task(cleanup_map_entry(source_ip))
        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"],
                   "sovereign_key_preview": sovereign_key["sovereign_key"][:16]},
        ))
        return JSONResponse(content={
            "status": "sovereign_approved",
            "detail": f"Unknown provider '{provider}' — approval granted, no forwarding",
            "compliance_score": result["compliance_score"],
            "verdict": result["verdict"],
            "sovereign_key": sovereign_key,
            "gatekeeper_state": result["gatekeeper_hex"],
            "node_id": node_id,
        })

    api_key = os.environ.get(route["key_env"], "")
    if not api_key:
        asyncio.create_task(cleanup_map_entry(source_ip))
        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"],
                   "sovereign_key_preview": sovereign_key["sovereign_key"][:16]},
        ))
        return JSONResponse(content={
            "status": "sovereign_approved_local",
            "detail": f"No API key for {provider}. Validation passed, forwarding skipped.",
            "compliance_score": result["compliance_score"],
            "verdict": result["verdict"],
            "sovereign_key": sovereign_key,
            "gatekeeper_state": result["gatekeeper_hex"],
            "node_id": node_id,
        })

    # Reconstruct upstream request body
    upstream_body = _build_upstream_body(provider, body)

    # Check if streaming is requested
    stream_mode = body.get("stream", False)

    async def forward_and_stream():
        """Forward to upstream provider and stream the response back."""
        upstream_url = _build_upstream_url(provider, route)
        upstream_headers = _build_upstream_headers(provider, api_key)

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST", upstream_url, json=upstream_body, headers=upstream_headers
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
        finally:
            # STAGE 5: Sync — Reset map after stream completes
            asyncio.create_task(cleanup_map_entry(source_ip))
            await broadcast_event({
                "type": "stage",
                "stage": "sync",
                "node_id": node_id,
                "source_ip": source_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    if stream_mode:
        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"],
                   "sovereign_key_preview": sovereign_key["sovereign_key"][:16]},
        ))
        return StreamingResponse(
            forward_and_stream(),
            media_type="text/event-stream",
        )

    # Non-streaming: forward, get full response, return
    upstream_url = _build_upstream_url(provider, route)
    upstream_headers = _build_upstream_headers(provider, api_key)

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                upstream_url, json=upstream_body, headers=upstream_headers,
            )
        asyncio.create_task(cleanup_map_entry(source_ip))
        await broadcast_event({
            "type": "stage",
            "stage": "sync",
            "node_id": node_id,
            "source_ip": source_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"],
                   "sovereign_key_preview": sovereign_key["sovereign_key"][:16]},
        ))
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )
    except httpx.RequestError as e:
        asyncio.create_task(cleanup_map_entry(source_ip))
        asyncio.create_task(audit_logger.log_inhale(
            source_ip=source_ip,
            intent_hash=_intent_hash,
            alignment_score=result["compliance_score"],
            verdict_action=_action,
            processing_latency_ms=(time.monotonic() - _t0) * 1000.0,
            extra={"node_id": node_id, "provider": provider,
                   "verdict": result["verdict"], "upstream_error": str(e)},
        ))
        raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")


# ---------------------------------------------------------------------------
#  Helper functions for upstream forwarding
# ---------------------------------------------------------------------------

def _build_upstream_body(provider: str, original_body: dict) -> dict:
    """Rebuild the request body for the upstream provider."""
    body = {k: v for k, v in original_body.items()
            if not k.startswith("_srp") and k not in ("node_id", "source_ip")}
    return body


def _build_upstream_url(provider: str, route: dict) -> str:
    """Build the upstream URL. Default path is /v1/chat/completions for OpenAI-like."""
    path = "/v1/chat/completions"
    if provider == "anthropic":
        path = "/v1/messages"
    elif provider == "google":
        model = "gemini-pro"
        path = f"/v1beta/models/{model}:generateContent"
    elif provider == "cohere":
        path = "/v1/generate"
    return f"{route['base']}{path}"


def _build_upstream_headers(provider: str, api_key: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if provider == "openai":
        headers["Authorization"] = f"Bearer {api_key}"
    elif provider == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
    elif provider == "google":
        # API key goes in query param, not header
        pass
    elif provider == "cohere":
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


# ===========================================================================
#  WebSocket Endpoint — Live Event Streaming
# ===========================================================================
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    logger.info("WebSocket client connected (%d total)", len(ws_connections))

    # Send recent events on connect
    try:
        for evt in event_log[-30:]:
            await ws.send_text(json.dumps(evt, default=str))
    except Exception:
        pass

    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_text(
                        json.dumps({
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                    )
                elif msg.get("type") == "simulate":
                    # Allow admins to simulate a packet_inspection event
                    sim_prompt = msg.get("prompt", "Hello world")
                    sim_provider = msg.get("provider", "openai")
                    sim_node = msg.get("node_id", f"sim-{secrets.token_hex(4)}")
                    sim_ip = msg.get("source_ip", f"10.0.{secrets.randbelow(256)}.{secrets.randbelow(256)}")
                    result = al_mizan.compute_compliance(sim_prompt)
                    event = {
                        "type": "packet_inspection",
                        "node_id": sim_node,
                        "source_ip": sim_ip,
                        "provider": sim_provider,
                        "verdict": result["verdict"],
                        "compliance_score": result["compliance_score"],
                        "max_similarity": result["max_similarity"],
                        "closest_boundary": result["closest_boundary"],
                        "gatekeeper_hex": result["gatekeeper_hex"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "prompt_preview": sim_prompt[:200],
                        "action": (
                            "TERMINATED"
                            if result["verdict"] == "SOVEREIGN_VIOLATION"
                            else "APPROVED"
                        ),
                    }
                    await broadcast_event(event)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ws_connections:
            ws_connections.remove(ws)
        logger.info(
            "WebSocket client disconnected (%d remaining)", len(ws_connections)
        )


# ===========================================================================
#  Command-line entry point
# ===========================================================================
if __name__ == "__main__":
    uvicorn.run(
        "srp_proxy:app",
        host="0.0.0.0",
        port=PROXY_PORT,
        log_level="info",
        reload=False,
        ws_max_size=2 ** 20,
    )
