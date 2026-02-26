"""
TPL Communication Engine — Secure inter-engine messaging bus.

Features:
  • HMAC signature verification for external messages
  • AES-256-GCM payload encryption (via encryption engine)
  • Internal engine-to-engine messaging bus
  • Message routing with type-based handlers
  • Audit trail with nonce replay protection
"""

import hashlib, hmac, json, os, time, threading, secrets
from collections import defaultdict
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, constr
from typing import Optional

from ..secret_loader import get_secret

class CommMessage(BaseModel):
    sender: constr(min_length=1, max_length=64)
    recipient: constr(min_length=1, max_length=64)
    msg_type: constr(min_length=1, max_length=64)
    payload: dict
    nonce: constr(min_length=8, max_length=64)
    ts: int
    signature: constr(min_length=32, max_length=128)
    encrypted: Optional[bool] = False

class InternalMessage(BaseModel):
    sender: constr(min_length=1, max_length=64)
    recipient: constr(min_length=1, max_length=64)
    msg_type: constr(min_length=1, max_length=64)
    payload: dict

_LOCK = threading.Lock()

def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    root = ctx["root"]
    comm_file = os.path.join(root, ".tpl_comm.jsonl")
    # COMM_SHARED_SECRET loaded dynamically from secret_loader for hot-reload support
    def _get_comm_secret() -> str:
        return get_secret("COMM_SHARED_SECRET")

    # Nonce replay protection (last 1000 nonces)
    _seen_nonces: list[str] = []

    # Internal message bus — subscribers keyed by recipient engine name
    _subscribers: dict[str, list] = defaultdict(list)

    # Stats
    _stats = {
        "messages_sent": 0,
        "messages_internal": 0,
        "messages_encrypted": 0,
        "signatures_verified": 0,
        "signatures_failed": 0,
        "replay_blocked": 0,
        "uptime_start": time.time(),
    }

    def _get_enc():
        return getattr(app.state, "encryption_engine", None)

    def canonical(x: CommMessage):
        payload = json.dumps(x.payload, sort_keys=True, separators=(",", ":"))
        return f"{x.sender}|{x.recipient}|{x.msg_type}|{payload}|{x.nonce}|{x.ts}"

    def verify(x: CommMessage):
        data = canonical(x).encode("utf-8")
        digest = hmac.new(_get_comm_secret().encode("utf-8"), data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(digest, x.signature)

    def _check_nonce(nonce: str) -> bool:
        """Return True if nonce is new (not replayed)."""
        with _LOCK:
            if nonce in _seen_nonces:
                _stats["replay_blocked"] += 1
                return False
            _seen_nonces.append(nonce)
            if len(_seen_nonces) > 1000:
                _seen_nonces.pop(0)
            return True

    def _encrypt_payload(payload: dict) -> tuple[str, bool]:
        """Try to encrypt payload using encryption engine."""
        enc = _get_enc()
        if enc:
            try:
                raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                encrypted = enc["encrypt"](raw)
                return encrypted, True
            except Exception:
                pass
        return json.dumps(payload, separators=(",", ":")), False

    def _decrypt_payload(data: str) -> dict:
        """Decrypt payload using encryption engine."""
        enc = _get_enc()
        if enc:
            try:
                decrypted = enc["decrypt"](data)
                return json.loads(decrypted)
            except Exception:
                pass
        try:
            return json.loads(data)
        except Exception:
            return {"raw": data}

    def append(row: dict):
        """Append message to comm log file."""
        with _LOCK:
            with open(comm_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, separators=(",", ":")) + "\n")

    def tail(limit: int):
        limit = max(1, min(limit, 500))
        if not os.path.isfile(comm_file):
            return []
        out = []
        with open(comm_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out[-limit:]

    def _route_internal(sender: str, recipient: str, msg_type: str, payload: dict):
        """Route message to internal subscribers."""
        with _LOCK:
            handlers = _subscribers.get(recipient, [])
        for handler in handlers:
            try:
                handler(sender, msg_type, payload)
            except Exception:
                pass

    # ── Internal messaging API for other engines ──────────────────────

    def _send_internal(sender: str, recipient: str, msg_type: str, payload: dict):
        """Send an internal engine-to-engine message (no signature needed)."""
        with _LOCK:
            _stats["messages_internal"] += 1

        # Encrypt payload for audit trail
        enc_payload, was_encrypted = _encrypt_payload(payload)
        if was_encrypted:
            with _LOCK:
                _stats["messages_encrypted"] += 1

        row = {
            "ts": int(time.time()),
            "sender": sender,
            "recipient": recipient,
            "msg_type": msg_type,
            "payload": enc_payload if was_encrypted else payload,
            "encrypted": was_encrypted,
            "internal": True,
        }
        append(row)

        # Route to subscriber
        _route_internal(sender, recipient, msg_type, payload)

        logger = getattr(app.state, "log_engine_append", None)
        if callable(logger):
            logger({
                "source": "communication_engine",
                "level": "info",
                "event": "internal_message",
                "message": f"internal:{sender}->{recipient}:{msg_type}",
                "meta": {"recipient": recipient, "msg_type": msg_type, "encrypted": was_encrypted},
            })

    def _subscribe(engine_name: str, handler):
        """Subscribe an engine to receive messages."""
        with _LOCK:
            _subscribers[engine_name].append(handler)

    # Expose on app.state for other engines
    app.state.comm_send = _send_internal
    app.state.comm_subscribe = _subscribe

    # ── API Endpoints ─────────────────────────────────────────────────

    @app.post("/comm/send")
    async def send_message(x: CommMessage, _: dict = Depends(require_admin)):
        now = int(time.time())
        if abs(now - x.ts) > 300:
            raise HTTPException(400, "stale_timestamp")
        if not _check_nonce(x.nonce):
            raise HTTPException(409, "replay_detected")
        if not verify(x):
            with _LOCK:
                _stats["signatures_failed"] += 1
            raise HTTPException(401, "bad_signature")

        with _LOCK:
            _stats["signatures_verified"] += 1
            _stats["messages_sent"] += 1

        # Encrypt payload before storing
        enc_payload, was_encrypted = _encrypt_payload(x.payload)
        if was_encrypted:
            with _LOCK:
                _stats["messages_encrypted"] += 1

        row = {
            "ts": now,
            "sender": x.sender,
            "recipient": x.recipient,
            "msg_type": x.msg_type,
            "payload": enc_payload if was_encrypted else x.payload,
            "nonce": x.nonce,
            "verified": True,
            "encrypted": was_encrypted,
        }
        append(row)

        # Route internally if recipient is an engine
        _route_internal(x.sender, x.recipient, x.msg_type, x.payload)

        logger = getattr(app.state, "log_engine_append", None)
        if callable(logger):
            logger({
                "source": "communication_engine",
                "level": "info",
                "event": "message_sent",
                "message": f"{x.sender}->{x.recipient}:{x.msg_type}",
                "meta": {"recipient": x.recipient, "msg_type": x.msg_type, "encrypted": was_encrypted},
            })

        return {"ok": True, "verified": True, "encrypted": was_encrypted}

    @app.post("/comm/internal")
    async def internal_message(x: InternalMessage, _: dict = Depends(require_admin)):
        """Send an internal message via API (admin only)."""
        _send_internal(x.sender, x.recipient, x.msg_type, x.payload)
        return {"ok": True, "routed": True}

    @app.get("/comm/logs")
    async def comm_logs(limit: int = 100, _: dict = Depends(require_admin)):
        items = tail(limit)
        # Decrypt payloads for display if encrypted
        for item in items:
            if item.get("encrypted") and isinstance(item.get("payload"), str):
                item["payload"] = _decrypt_payload(item["payload"])
        return {"items": items, "count": len(items)}

    @app.get("/comm/status")
    async def comm_status(_: dict = Depends(require_admin)):
        with _LOCK:
            return {
                "engine": "active",
                "uptime": time.time() - _stats["uptime_start"],
                "messages_sent": _stats["messages_sent"],
                "messages_internal": _stats["messages_internal"],
                "messages_encrypted": _stats["messages_encrypted"],
                "signatures_verified": _stats["signatures_verified"],
                "signatures_failed": _stats["signatures_failed"],
                "replay_blocked": _stats["replay_blocked"],
                "subscribers": {k: len(v) for k, v in _subscribers.items()},
                "encryption_available": _get_enc() is not None,
            }

    @app.get("/comm/subscribers")
    async def comm_subscribers(_: dict = Depends(require_admin)):
        with _LOCK:
            return {
                "subscribers": {k: len(v) for k, v in _subscribers.items()},
                "count": sum(len(v) for v in _subscribers.values()),
            }

    @app.post("/comm/ping")
    async def comm_ping(u: dict = Depends(require_admin)):
        """Server-side health-check ping — signs the message internally so the
        comm shared secret never reaches the frontend."""
        now = int(time.time())
        nonce = f"{now}{secrets.token_hex(8)}"
        msg_data = {
            "sender": "admin_dashboard",
            "recipient": "log_engine",
            "msg_type": "ping",
            "payload": {"note": "health-check"},
            "nonce": nonce,
            "ts": now,
        }
        payload_str = json.dumps(msg_data["payload"], sort_keys=True, separators=(",", ":"))
        canon = f"{msg_data['sender']}|{msg_data['recipient']}|{msg_data['msg_type']}|{payload_str}|{nonce}|{now}"
        sig = hmac.new(_get_comm_secret().encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()
        msg_data["signature"] = sig
        row = {"ts": now, "sender": msg_data["sender"], "recipient": msg_data["recipient"],
               "msg_type": msg_data["msg_type"], "payload": msg_data["payload"],
               "nonce": nonce, "verified": True}
        append(row)
        logger = getattr(app.state, "log_engine_append", None)
        if callable(logger):
            logger({"source": "communication_engine", "level": "info",
                     "event": "ping_sent", "message": "admin_dashboard->log_engine:ping",
                     "meta": {"actor": u.get("sub", "admin")}})
        return {"ok": True, "verified": True}
