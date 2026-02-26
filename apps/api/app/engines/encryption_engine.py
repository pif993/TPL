"""
TPL Encryption Engine — Motore di crittografia avanzato ed efficiente.

Supporta:
  - AES-256-GCM (authenticated encryption) via `cryptography` library
  - HMAC-SHA256 / SHA-512 (firma e verifica messaggi)
  - PBKDF2 / scrypt (derivazione chiavi da password)
  - Secure random token generation
  - File checksum (SHA-256 / SHA-512 / BLAKE2b)
  - Data sealing (encrypt + sign + timestamp + anti-replay)
  - Key rotation management
  - Constant-time comparison
  - Base64/Hex encoding helpers

Usa la libreria `cryptography` per AES-256-GCM reale.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading

from ..secret_loader import get_secret
import time
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, constr

_LOCK = threading.Lock()

# ─── Configuration ────────────────────────────────────────────────────────────
# Master key loaded from Vault tmpfs via secret_loader (validated there).
def _get_master_key() -> str:
    """Get master key at call time to support hot-reload rotation."""
    return get_secret("TPL_MASTER_KEY")
_KEY_ITERATIONS = 100_000      # PBKDF2 iterations
_SCRYPT_N = 2**14              # scrypt CPU/memory cost
_SCRYPT_R = 8
_SCRYPT_P = 1
_NONCE_SIZE = 12               # 96 bits for GCM
_TAG_SIZE = 16                 # AES-GCM tag (128 bits)
_SEAL_VERSION = 1              # Data seal format version
_REPLAY_WINDOW = 300           # 5 min anti-replay window
_KEY_ROTATION_INTERVAL = 86400 # 24h rotation check


# ─── Statistics ───────────────────────────────────────────────────────────────
class _Stats:
    def __init__(self):
        self.encryptions: int = 0
        self.decryptions: int = 0
        self.signatures: int = 0
        self.verifications: int = 0
        self.key_derivations: int = 0
        self.tokens_generated: int = 0
        self.checksums: int = 0
        self.seals_created: int = 0
        self.seals_verified: int = 0
        self.seal_failures: int = 0
        self.replay_blocked: int = 0
        self.errors: int = 0
        self.total_ops: int = 0
        self.ops_by_type: dict[str, int] = defaultdict(int)
        self.keys_rotated: int = 0
        self.uptime_start: float = time.time()
        self.last_rotation: float = 0.0
        self.active_keys: int = 1

_ST = _Stats()

# ─── Used nonces for anti-replay ──────────────────────────────────────────────
_used_nonces: dict[str, float] = {}


# ─── Core Crypto Primitives ──────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes, length: int = 32, method: str = "pbkdf2") -> bytes:
    """Deriva chiave da password usando PBKDF2 o scrypt."""
    with _LOCK:
        _ST.key_derivations += 1
        _ST.total_ops += 1
        _ST.ops_by_type["key_derive"] += 1
    if method == "scrypt":
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=length
        )
    # Default: PBKDF2-HMAC-SHA256
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _KEY_ITERATIONS, dklen=length)


def _get_encryption_key(key: str | None = None) -> bytes:
    """Ottiene chiave di crittografia a 32 bytes (AES-256)."""
    source = key or _get_master_key()
    return hashlib.sha256(source.encode("utf-8")).digest()


def _encrypt_aes256_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """
    AES-256-GCM authenticated encryption using the `cryptography` library.
    Format: nonce (12) || ciphertext+tag (variable, tag is 16 bytes appended by AESGCM)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)
    # AESGCM.encrypt returns ciphertext || 16-byte tag
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad or None)

    with _LOCK:
        _ST.encryptions += 1
        _ST.total_ops += 1
        _ST.ops_by_type["encrypt"] += 1

    return nonce + ct_and_tag


def _decrypt_aes256_gcm(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM authenticated decryption using the `cryptography` library."""
    if len(data) < _NONCE_SIZE + 16:  # 12 nonce + 16 tag minimum
        raise ValueError("Data too short")

    nonce = data[:_NONCE_SIZE]
    ct_and_tag = data[_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, aad or None)
    except Exception:
        with _LOCK:
            _ST.errors += 1
        raise ValueError("Authentication failed — data tampered")

    with _LOCK:
        _ST.decryptions += 1
        _ST.total_ops += 1
        _ST.ops_by_type["decrypt"] += 1

    return plaintext


def _hmac_sign(message: bytes, key: bytes, algorithm: str = "sha256") -> str:
    """Firma messaggio con HMAC."""
    if algorithm == "sha512":
        sig = hmac.new(key, message, hashlib.sha512).hexdigest()
    else:
        sig = hmac.new(key, message, hashlib.sha256).hexdigest()

    with _LOCK:
        _ST.signatures += 1
        _ST.total_ops += 1
        _ST.ops_by_type["sign"] += 1

    return sig


def _hmac_verify(message: bytes, signature: str, key: bytes, algorithm: str = "sha256") -> bool:
    """Verifica firma HMAC con confronto constant-time."""
    if algorithm == "sha512":
        expected = hmac.new(key, message, hashlib.sha512).hexdigest()
    else:
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()

    result = hmac.compare_digest(expected, signature)

    with _LOCK:
        _ST.verifications += 1
        _ST.total_ops += 1
        _ST.ops_by_type["verify"] += 1

    return result


def _checksum(data: bytes, algorithm: str = "sha256") -> str:
    """Calcola checksum di dati."""
    if algorithm == "sha512":
        h = hashlib.sha512(data).hexdigest()
    elif algorithm == "blake2b":
        h = hashlib.blake2b(data).hexdigest()
    elif algorithm == "md5":
        h = hashlib.md5(data).hexdigest()
    else:
        h = hashlib.sha256(data).hexdigest()

    with _LOCK:
        _ST.checksums += 1
        _ST.total_ops += 1
        _ST.ops_by_type["checksum"] += 1

    return h


def _generate_token(length: int = 32) -> str:
    """Genera token crittograficamente sicuro."""
    with _LOCK:
        _ST.tokens_generated += 1
        _ST.total_ops += 1
        _ST.ops_by_type["token_gen"] += 1
    return secrets.token_urlsafe(length)


def _seal_data(payload: dict, key: bytes) -> str:
    """
    Sigilla dati: encrypt + sign + timestamp + nonce per anti-replay.
    Formato: base64(version || timestamp || nonce || encrypted_payload || hmac_tag)
    """
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # Header con versione e timestamp
    header = struct.pack(">BQ", _SEAL_VERSION, timestamp) + nonce.encode("utf-8")
    encrypted = _encrypt_aes256_gcm(plaintext, key, aad=header)
    sealed = header + encrypted

    with _LOCK:
        _ST.seals_created += 1
        _ST.total_ops += 1
        _ST.ops_by_type["seal"] += 1

    return base64.urlsafe_b64encode(sealed).decode("ascii")


def _unseal_data(sealed_b64: str, key: bytes) -> dict:
    """Apre dati sigillati con verifica anti-replay."""
    try:
        sealed = base64.urlsafe_b64decode(sealed_b64)
    except Exception:
        raise ValueError("Invalid sealed data format")

    if len(sealed) < 41:  # 1 (ver) + 8 (ts) + 32 (nonce) = 41 min header
        raise ValueError("Sealed data too short")

    version = sealed[0]
    if version != _SEAL_VERSION:
        raise ValueError(f"Unsupported seal version: {version}")

    timestamp = struct.unpack(">Q", sealed[1:9])[0]
    nonce = sealed[9:41].decode("utf-8")
    encrypted = sealed[41:]

    # Anti-replay check
    now = int(time.time())
    if abs(now - timestamp) > _REPLAY_WINDOW:
        with _LOCK:
            _ST.replay_blocked += 1
            _ST.errors += 1
        raise ValueError("Sealed data expired (anti-replay)")

    with _LOCK:
        if nonce in _used_nonces:
            _ST.replay_blocked += 1
            _ST.errors += 1
            raise ValueError("Replay attack detected")
        _used_nonces[nonce] = now
        # Pulizia nonces vecchi
        expired = [n for n, t in _used_nonces.items() if now - t > _REPLAY_WINDOW * 2]
        for n in expired:
            del _used_nonces[n]

    header = sealed[:41]
    try:
        plaintext = _decrypt_aes256_gcm(encrypted, key, aad=header)
        payload = json.loads(plaintext.decode("utf-8"))
    except ValueError:
        with _LOCK:
            _ST.seal_failures += 1
            _ST.errors += 1
        raise
    except Exception as e:
        with _LOCK:
            _ST.seal_failures += 1
            _ST.errors += 1
        raise ValueError(f"Unseal failed: {e}")

    with _LOCK:
        _ST.seals_verified += 1
        _ST.total_ops += 1
        _ST.ops_by_type["unseal"] += 1

    return payload


# ─── Pydantic Models ─────────────────────────────────────────────────────────

class EncryptRequest(BaseModel):
    plaintext: constr(min_length=1, max_length=100_000)
    key: str | None = None  # optional custom key, uses master if None

class DecryptRequest(BaseModel):
    ciphertext: constr(min_length=1, max_length=200_000)  # base64
    key: str | None = None

class SignRequest(BaseModel):
    message: constr(min_length=1, max_length=100_000)
    algorithm: constr(pattern="^(sha256|sha512)$") = "sha256"
    key: str | None = None

class VerifyRequest(BaseModel):
    message: constr(min_length=1, max_length=100_000)
    signature: constr(min_length=1, max_length=256)
    algorithm: constr(pattern="^(sha256|sha512)$") = "sha256"
    key: str | None = None

class HashRequest(BaseModel):
    data: constr(min_length=1, max_length=100_000)
    algorithm: constr(pattern="^(sha256|sha512|blake2b|md5)$") = "sha256"

class DeriveKeyRequest(BaseModel):
    password: constr(min_length=1, max_length=256)
    method: constr(pattern="^(pbkdf2|scrypt)$") = "pbkdf2"
    length: int = 32

class SealRequest(BaseModel):
    payload: dict
    key: str | None = None

class UnsealRequest(BaseModel):
    sealed: constr(min_length=1, max_length=500_000)
    key: str | None = None

class TokenRequest(BaseModel):
    length: int = 32
    count: int = 1


# ═══════════════════════════════════════════════════════════════════════════════
#  REGISTER
# ═══════════════════════════════════════════════════════════════════════════════
def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]

    # Expose per altri engine
    app.state.encryption_engine = {
        "encrypt": lambda data, key=None: base64.urlsafe_b64encode(
            _encrypt_aes256_gcm(data.encode("utf-8") if isinstance(data, str) else data, _get_encryption_key(key))
        ).decode("ascii"),
        "decrypt": lambda data, key=None: _decrypt_aes256_gcm(
            base64.urlsafe_b64decode(data), _get_encryption_key(key)
        ).decode("utf-8"),
        "sign": lambda msg, key=None: _hmac_sign(
            msg.encode("utf-8") if isinstance(msg, str) else msg, _get_encryption_key(key)
        ),
        "verify": lambda msg, sig, key=None: _hmac_verify(
            msg.encode("utf-8") if isinstance(msg, str) else msg, sig, _get_encryption_key(key)
        ),
        "seal": lambda payload, key=None: _seal_data(payload, _get_encryption_key(key)),
        "unseal": lambda sealed, key=None: _unseal_data(sealed, _get_encryption_key(key)),
        "hash": _checksum,
        "token": _generate_token,
        "derive_key": _derive_key,
    }

    # ═══ API ENDPOINTS ════════════════════════════════════════════════════

    @app.get("/encryption/status")
    async def encryption_status(_: dict = Depends(require_admin)):
        with _LOCK:
            uptime = time.time() - _ST.uptime_start
            return {
                "engine": "active",
                "algorithms": {
                    "encryption": "AES-256-GCM (cryptography library)",
                    "signing": ["HMAC-SHA256", "HMAC-SHA512"],
                    "hashing": ["SHA-256", "SHA-512", "BLAKE2b", "MD5"],
                    "key_derivation": ["PBKDF2-HMAC-SHA256", "scrypt"],
                    "sealing": "AES-256-GCM + HMAC + anti-replay",
                },
                "config": {
                    "key_iterations": _KEY_ITERATIONS,
                    "nonce_size": _NONCE_SIZE,
                    "tag_size": _TAG_SIZE,
                    "replay_window": _REPLAY_WINDOW,
                    "scrypt_n": _SCRYPT_N,
                    "scrypt_r": _SCRYPT_R,
                    "scrypt_p": _SCRYPT_P,
                },
                "stats": {
                    "total_ops": _ST.total_ops,
                    "encryptions": _ST.encryptions,
                    "decryptions": _ST.decryptions,
                    "signatures": _ST.signatures,
                    "verifications": _ST.verifications,
                    "key_derivations": _ST.key_derivations,
                    "tokens_generated": _ST.tokens_generated,
                    "checksums": _ST.checksums,
                    "seals_created": _ST.seals_created,
                    "seals_verified": _ST.seals_verified,
                    "seal_failures": _ST.seal_failures,
                    "replay_blocked": _ST.replay_blocked,
                    "errors": _ST.errors,
                    "ops_by_type": dict(_ST.ops_by_type),
                },
                "keys": {
                    "active": _ST.active_keys,
                    "rotated": _ST.keys_rotated,
                    "last_rotation": int(_ST.last_rotation) if _ST.last_rotation else None,
                },
                "uptime_seconds": int(uptime),
            }

    @app.post("/encryption/encrypt")
    async def api_encrypt(x: EncryptRequest, _: dict = Depends(require_admin)):
        try:
            key = _get_encryption_key(x.key)
            encrypted = _encrypt_aes256_gcm(x.plaintext.encode("utf-8"), key)
            ct_b64 = base64.urlsafe_b64encode(encrypted).decode("ascii")
            return {
                "ok": True,
                "ciphertext": ct_b64,
                "algorithm": "AES-256-GCM",
                "size_plaintext": len(x.plaintext),
                "size_ciphertext": len(ct_b64),
            }
        except Exception as e:
            raise HTTPException(400, f"Encryption failed: {e}")

    @app.post("/encryption/decrypt")
    async def api_decrypt(x: DecryptRequest, _: dict = Depends(require_admin)):
        try:
            key = _get_encryption_key(x.key)
            data = base64.urlsafe_b64decode(x.ciphertext)
            plaintext = _decrypt_aes256_gcm(data, key)
            return {
                "ok": True,
                "plaintext": plaintext.decode("utf-8"),
                "verified": True,
            }
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            raise HTTPException(400, f"Decryption failed: {e}")

    @app.post("/encryption/sign")
    async def api_sign(x: SignRequest, _: dict = Depends(require_admin)):
        key = _get_encryption_key(x.key)
        sig = _hmac_sign(x.message.encode("utf-8"), key, x.algorithm)
        return {
            "ok": True,
            "signature": sig,
            "algorithm": f"HMAC-{x.algorithm.upper()}",
        }

    @app.post("/encryption/verify")
    async def api_verify(x: VerifyRequest, _: dict = Depends(require_admin)):
        key = _get_encryption_key(x.key)
        valid = _hmac_verify(x.message.encode("utf-8"), x.signature, key, x.algorithm)
        return {
            "ok": True,
            "valid": valid,
            "algorithm": f"HMAC-{x.algorithm.upper()}",
        }

    @app.post("/encryption/hash")
    async def api_hash(x: HashRequest, _: dict = Depends(require_admin)):
        h = _checksum(x.data.encode("utf-8"), x.algorithm)
        return {
            "ok": True,
            "hash": h,
            "algorithm": x.algorithm.upper(),
            "length": len(h),
        }

    @app.post("/encryption/derive")
    async def api_derive_key(x: DeriveKeyRequest, _: dict = Depends(require_admin)):
        salt = os.urandom(16)
        try:
            derived = _derive_key(x.password, salt, x.length, x.method)
            return {
                "ok": True,
                "derived_key": base64.urlsafe_b64encode(derived).decode("ascii"),
                "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
                "method": x.method,
                "iterations": _KEY_ITERATIONS if x.method == "pbkdf2" else f"N={_SCRYPT_N}",
            }
        except Exception as e:
            raise HTTPException(400, f"Key derivation failed: {e}")

    @app.post("/encryption/token")
    async def api_generate_token(x: TokenRequest, _: dict = Depends(require_admin)):
        count = max(1, min(x.count, 20))
        length = max(8, min(x.length, 128))
        tokens = [_generate_token(length) for _ in range(count)]
        return {
            "ok": True,
            "tokens": tokens,
            "length": length,
            "entropy_bits": length * 6,  # ~6 bits per urlsafe char
        }

    @app.post("/encryption/seal")
    async def api_seal(x: SealRequest, _: dict = Depends(require_admin)):
        try:
            key = _get_encryption_key(x.key)
            sealed = _seal_data(x.payload, key)
            return {
                "ok": True,
                "sealed": sealed,
                "timestamp": int(time.time()),
                "replay_window": _REPLAY_WINDOW,
            }
        except Exception as e:
            raise HTTPException(400, f"Seal failed: {e}")

    @app.post("/encryption/unseal")
    async def api_unseal(x: UnsealRequest, _: dict = Depends(require_admin)):
        try:
            key = _get_encryption_key(x.key)
            payload = _unseal_data(x.sealed, key)
            return {
                "ok": True,
                "payload": payload,
                "verified": True,
                "anti_replay": True,
            }
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            raise HTTPException(400, f"Unseal failed: {e}")

    @app.post("/encryption/rotate")
    async def api_rotate_key(request: Request, _: dict = Depends(require_admin)):
        """Registra una rotazione chiave.
        La rotazione effettiva richiede:
        1. Generare una nuova chiave: ./run.sh rotate-secrets
        2. Re-seal dei dati cifrati con la nuova chiave.
        Questo endpoint aggiorna lo stato interno e registra l'audit event.
        """
        with _LOCK:
            _ST.keys_rotated += 1
            _ST.last_rotation = time.time()
        audit(request, "encryption.key_rotated", "info",
              _.get("sub", "admin"),
              {"total_rotations": _ST.keys_rotated})
        return {
            "ok": True,
            "rotated": True,
            "total_rotations": _ST.keys_rotated,
            "timestamp": int(time.time()),
            "note": "Stato rotazione aggiornato. Eseguire './run.sh rotate-secrets' per rigenerare le chiavi su disco.",
        }

    @app.get("/encryption/benchmark")
    async def api_benchmark(_: dict = Depends(require_admin)):
        """Benchmark delle operazioni crittografiche."""
        results = {}

        # Encrypt/Decrypt benchmark
        test_data = os.urandom(1024)  # 1KB
        key = _get_encryption_key()

        start = time.perf_counter()
        for _ in range(100):
            enc = _encrypt_aes256_gcm(test_data, key)
        enc_time = (time.perf_counter() - start) / 100

        start = time.perf_counter()
        for _ in range(100):
            _decrypt_aes256_gcm(enc, key)
        dec_time = (time.perf_counter() - start) / 100

        # Hash benchmark
        start = time.perf_counter()
        for _ in range(1000):
            hashlib.sha256(test_data).hexdigest()
        hash_time = (time.perf_counter() - start) / 1000

        # HMAC benchmark
        start = time.perf_counter()
        for _ in range(1000):
            hmac.new(key, test_data, hashlib.sha256).hexdigest()
        hmac_time = (time.perf_counter() - start) / 1000

        results = {
            "encrypt_1kb_ms": round(enc_time * 1000, 3),
            "decrypt_1kb_ms": round(dec_time * 1000, 3),
            "sha256_1kb_us": round(hash_time * 1_000_000, 1),
            "hmac_sha256_1kb_us": round(hmac_time * 1_000_000, 1),
            "encrypt_throughput_mbps": round((1024 / enc_time) / 1_000_000, 1) if enc_time > 0 else 0,
            "hash_throughput_mbps": round((1024 / hash_time) / 1_000_000, 1) if hash_time > 0 else 0,
        }

        return {"ok": True, "benchmark": results, "test_size_bytes": 1024}
