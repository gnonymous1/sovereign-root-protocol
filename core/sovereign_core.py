"""
SRP MODULE 2: CORE VALIDATION PROXY
Port 9000 — FastAPI + Uvicorn + HTTPX + sentence-transformers
Implements semantic validation, gateway state updates, and validation windows.
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import struct
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
import numpy as np
import uvicorn
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sentence_transformers import SentenceTransformer

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [CORE:SCALE] %(levelname)s — %(message)s"
)
logger = logging.getLogger("sovereign_core")

# --- Constants from architecture.md & agents.md ---
SOVEREIGN_PORT = 9000
GATEKEEPER_DORMANT = 0x00
GATEKEEPER_ACTIVE = 0x01
GATEKEEPER_FULL = 0x02
GATEKEEPER_ISOLATE = 0xFF
COMPLIANCE_HIGH = 0.85
COMPLIANCE_AUDIT = 0.60
SOVEREIGN_KEY_BITS = 512

# Constitutional restriction vectors (Scale boundary definitions)
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

# Provider endpoint routing
PROVIDER_ROUTES = {
    "openai": {"base": "https://api.openai.com", "key_env": "OPENAI_API_KEY"},
    "anthropic": {"base": "https://api.anthropic.com", "key_env": "ANTHROPIC_API_KEY"},
    "google": {
        "base": "https://generativelanguage.googleapis.com",
        "key_env": "GOOGLE_API_KEY",
    },
    "cohere": {"base": "https://api.cohere.ai", "key_env": "COHERE_API_KEY"},
}


class SovereignApprovalMap:
    """In-memory emulation of the eBPF sovereign_approval BPF hash map."""

    def __init__(self):
        self._map = {}
        self._lock = asyncio.Lock()

    async def read(self, key: str) -> int:
        async with self._lock:
            return self._map.get(key, GATEKEEPER_DORMANT)

    async def write(self, key: str, state: int):
        async with self._lock:
            self._map[key] = state
            logger.info(f"Approval map: {key} -> 0x{state:02X}")

    async def flush_to_dormant(self, key: str):
        await self.write(key, GATEKEEPER_DORMANT)

    async def snapshot(self) -> dict:
        async with self._lock:
            return dict(self._map)


class AlMizanEngine:
    """
    The Scale Engine — Semantic vector alignment verification.
    Uses all-MiniLM-L6-v2 for cosine similarity against constitutional restrictions.
    """

    def __init__(self):
        logger.info("Loading Scale semantic model: all-MiniLM-L6-v2...")
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.restriction_embeddings = self.model.encode(
            CONSTITUTIONAL_RESTRICTIONS, normalize_embeddings=True
        )
        logger.info(
            f"Constitutional vectors loaded: {len(CONSTITUTIONAL_RESTRICTIONS)} boundaries"
        )

    def compute_compliance(self, prompt: str) -> dict:
        """
        Run cosine similarity matrix check against constitutional restrictions.
        Returns compliance metric and violation details.
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
            state = GATEKEEPER_ISOLATE

        return {
            "compliance_score": round(compliance_score, 4),
            "max_similarity": round(max_similarity, 4),
            "closest_boundary": CONSTITUTIONAL_RESTRICTIONS[max_idx],
            "closest_boundary_index": max_idx,
            "verdict": verdict,
            "gatekeeper_state": state,
            "gatekeeper_hex": f"0x{state:02X}",
        }


class SovereignKeyGenerator:
    """Generate 512-bit Sovereign Validation Keys with temporal windows."""

    @staticmethod
    def generate(node_id: str, ttl_seconds: float = 30.0) -> dict:
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


# --- Global state ---
approval_map = SovereignApprovalMap()
key_generator = SovereignKeyGenerator()
al_mizan: Optional[AlMizanEngine] = None
ws_connections: list[WebSocket] = []
event_log: list[dict] = []

EVENT_LOG_MAX = 500


async def broadcast_event(event: dict):
    """Broadcast event to all connected WebSocket clients (frontend)."""
    event_log.append(event)
    if len(event_log) > EVENT_LOG_MAX:
        event_log.pop(0)
    payload = json.dumps(event)
    disconnected = []
    for ws in ws_connections:
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_connections.remove(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global al_mizan
    logger.info("=" * 72)
    logger.info("  SOVEREIGN ROOT PROTOCOL — HEART CORE ENGINE (THE BRAIN)")
    logger.info("  Scale Engine: Initializing Semantic Verification")
    logger.info("=" * 72)
    al_mizan = AlMizanEngine()
    logger.info(f"Sovereign Heart Core ACTIVE on port {SOVEREIGN_PORT}")
    yield
    logger.info("Sovereign Heart Core shutting down...")


app = FastAPI(
    title="Sovereign Root Protocol — Heart Core",
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


# --- ENDPOINTS ---


@app.get("/health")
async def health():
    return {
        "status": "sovereign_active",
        "port": SOVEREIGN_PORT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics")
async def metrics():
    return {
        "approval_map": await approval_map.snapshot(),
        "event_count": len(event_log),
        "ws_clients": len(ws_connections),
    }


@app.get("/events")
async def get_events(limit: int = 50):
    return {"events": event_log[-limit:]}


@app.post("/validate")
async def validate_intent(request: Request):
    """
    Validate a prompt, compute the semantic compliance score, and return a
    validation token or violation response.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract prompt from various provider formats
    prompt = ""
    messages = body.get("messages", [])
    if messages:
        prompt = " ".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )
    elif "prompt" in body:
        prompt = body["prompt"]
    elif "contents" in body:
        for c in body.get("contents", []):
            for p in c.get("parts", []):
                prompt += p.get("text", "") + " "

    if not prompt.strip():
        raise HTTPException(status_code=400, detail="No extractable prompt content")

    node_id = request.headers.get(
        "X-Node-ID", request.client.host if request.client else "unknown"
    )
    provider = body.get("_srp_provider", "openai")

    # STAGE 3: Scale verdict
    result = al_mizan.compute_compliance(prompt.strip())
    result["node_id"] = node_id
    result["provider"] = provider
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["stage"] = "verdict"

    event = {
        "type": "packet_inspection",
        "node_id": node_id,
        "provider": provider,
        "verdict": result["verdict"],
        "compliance_score": result["compliance_score"],
        "gatekeeper_hex": result["gatekeeper_hex"],
        "timestamp": result["timestamp"],
        "prompt_preview": prompt.strip()[:120],
    }

    if result["verdict"] == "SOVEREIGN_VIOLATION":
        # Write 0x00 to eBPF map — immediate dormant lockdown
        await approval_map.write(node_id, GATEKEEPER_DORMANT)
        event["action"] = "DROPPED"
        await broadcast_event(event)
        return JSONResponse(
            status_code=403,
            content={
                "error": "sovereign_violation",
                "detail": "Constitutional boundary breach detected by Scale",
                "compliance_score": result["compliance_score"],
                "closest_boundary": result["closest_boundary"],
                "gatekeeper_state": "0xFF — Quarantine",
                "node_id": node_id,
                "timestamp": result["timestamp"],
            },
        )

    # APPROVED — issue validation token and set gateway state to active
    await approval_map.write(node_id, GATEKEEPER_FULL)
    sovereign_key = key_generator.generate(node_id, ttl_seconds=30.0)
    result["sovereign_key"] = sovereign_key
    event["action"] = "APPROVED"
    event["sovereign_key_preview"] = sovereign_key["sovereign_key"][:16] + "..."
    await broadcast_event(event)

    return JSONResponse(
        content={
            "status": "sovereign_approved",
            "compliance_score": result["compliance_score"],
            "verdict": result["verdict"],
            "sovereign_key": sovereign_key,
            "gatekeeper_state": result["gatekeeper_hex"],
            "node_id": node_id,
        }
    )


@app.post("/proxy/{provider}/{path:path}")
async def sovereign_proxy(provider: str, path: str, request: Request):
    """
    Full proxy path: validate, forward, stream response, then reset gateway state.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract prompt
    prompt = ""
    messages = body.get("messages", [])
    if messages:
        prompt = " ".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )
    elif "prompt" in body:
        prompt = body["prompt"]

    node_id = request.headers.get(
        "X-Node-ID", request.client.host if request.client else "unknown"
    )

    # Stage 1: mark request as pending validation.
    await approval_map.write(node_id, GATEKEEPER_DORMANT)
    await broadcast_event(
        {
            "type": "stage",
            "stage": "inhale",
            "node_id": node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    # STAGE 2: TRANSIT — Encapsulated tunnel to Core
    await broadcast_event(
        {
            "type": "stage",
            "stage": "transit",
            "node_id": node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    # STAGE 3: VERDICT — Scale check
    if prompt.strip():
        result = al_mizan.compute_compliance(prompt.strip())
    else:
        result = {
            "verdict": "SOVEREIGN_PASS",
            "compliance_score": 1.0,
            "gatekeeper_state": GATEKEEPER_FULL,
            "gatekeeper_hex": "0x02",
            "max_similarity": 0.0,
            "closest_boundary": "N/A",
            "closest_boundary_index": -1,
        }

    verdict_event = {
        "type": "packet_inspection",
        "node_id": node_id,
        "provider": provider,
        "verdict": result["verdict"],
        "compliance_score": result["compliance_score"],
        "gatekeeper_hex": result["gatekeeper_hex"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt_preview": prompt.strip()[:120],
    }

    if result["verdict"] == "SOVEREIGN_VIOLATION":
        await approval_map.write(node_id, GATEKEEPER_DORMANT)
        verdict_event["action"] = "DROPPED"
        await broadcast_event(verdict_event)
        return JSONResponse(
            status_code=403,
            content={
                "error": "sovereign_violation",
                "detail": "Constitutional boundary breach — Executioner isolation engaged",
                "compliance_score": result["compliance_score"],
                "gatekeeper_state": "0xFF — Quarantine",
            },
        )

    # STAGE 4: EXHALE — Activate & forward
    await approval_map.write(node_id, GATEKEEPER_FULL)
    sovereign_key = key_generator.generate(node_id)
    verdict_event["action"] = "APPROVED"
    await broadcast_event(verdict_event)
    await broadcast_event(
        {
            "type": "stage",
            "stage": "exhale",
            "node_id": node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Forward to upstream provider
    route = PROVIDER_ROUTES.get(provider)
    if not route:
        await approval_map.flush_to_dormant(node_id)
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    api_key = os.environ.get(route["key_env"], "")
    if not api_key:
        await approval_map.flush_to_dormant(node_id)
        return JSONResponse(
            status_code=200,
            content={
                "status": "sovereign_approved_local",
                "detail": f"No API key for {provider}. Validation passed, but upstream forwarding skipped.",
                "compliance_score": result["compliance_score"],
                "sovereign_key": sovereign_key,
            },
        )

    upstream_url = f"{route['base']}/{path}"
    headers = {"Content-Type": "application/json"}
    if provider == "openai":
        headers["Authorization"] = f"Bearer {api_key}"
    elif provider == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"

    stream_mode = body.get("stream", False)

    async def stream_upstream():
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                async with client.stream(
                    "POST", upstream_url, json=body, headers=headers
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
        finally:
            # STAGE 5: SYNC — Flush key back to dormant
            await approval_map.flush_to_dormant(node_id)
            await broadcast_event(
                {
                    "type": "stage",
                    "stage": "sync",
                    "node_id": node_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

    if stream_mode:
        return StreamingResponse(stream_upstream(), media_type="text/event-stream")
    else:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(upstream_url, json=body, headers=headers)
                # STAGE 5: SYNC
                await approval_map.flush_to_dormant(node_id)
                await broadcast_event(
                    {
                        "type": "stage",
                        "stage": "sync",
                        "node_id": node_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/json"),
                )
        except httpx.RequestError as e:
            await approval_map.flush_to_dormant(node_id)
            raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket stream for real-time frontend events."""
    await ws.accept()
    ws_connections.append(ws)
    logger.info(f"WebSocket client connected ({len(ws_connections)} total)")

    # Send recent events on connect
    try:
        for event in event_log[-20:]:
            await ws.send_text(json.dumps(event))
    except Exception:
        pass

    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_text(
                        json.dumps(
                            {
                                "type": "pong",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                    )
                elif msg.get("type") == "simulate":
                    sim_prompt = msg.get("prompt", "Hello world")
                    sim_provider = msg.get("provider", "openai")
                    sim_node = msg.get("node_id", f"sim-{secrets.token_hex(4)}")
                    result = al_mizan.compute_compliance(sim_prompt)
                    event = {
                        "type": "packet_inspection",
                        "node_id": sim_node,
                        "provider": sim_provider,
                        "verdict": result["verdict"],
                        "compliance_score": result["compliance_score"],
                        "gatekeeper_hex": result["gatekeeper_hex"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "prompt_preview": sim_prompt[:120],
                        "action": "DROPPED"
                        if result["verdict"] == "SOVEREIGN_VIOLATION"
                        else "APPROVED",
                    }
                    await broadcast_event(event)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ws_connections:
            ws_connections.remove(ws)
        logger.info(f"WebSocket client disconnected ({len(ws_connections)} remaining)")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=SOVEREIGN_PORT, log_level="info")
