"""
TPL Module Update Engine — v1.0.0
Read-only API for bundle info, release management, update history,
and security checklist. Module installation happens ONLY via tpl-modules CLI.

No shell execution, no subprocess calls, no write operations to modules/.
"""

import json
import os
import time
import hashlib
import re
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx["root"]  # /data

    STATE_FILE = os.path.join(root, ".tpl_state.json")
    BUNDLE_LOG = os.path.join(root, ".tpl_bundle_history.jsonl")
    MODULES_DIR = "/work/modules"
    MODULES_BASE = os.getenv("TPL_MODULES_BASE", "/var/lib/tpl/modules")
    RELEASES_DIR = os.path.join(MODULES_BASE, "releases")
    CURRENT_LINK = os.path.join(MODULES_BASE, "current")

    # ── Helpers ────────────────────────────────────────────────────────

    def _load_state() -> dict:
        if not os.path.isfile(STATE_FILE):
            return {"installed": {}, "updated": 0}
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"installed": {}, "updated": 0}

    def _file_hash(filepath: str) -> str:
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()

    def _read_manifest(release_dir: str) -> Optional[dict]:
        mf = os.path.join(release_dir, ".manifest.json")
        if not os.path.isfile(mf):
            return None
        try:
            with open(mf, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _read_signature(release_dir: str) -> Optional[dict]:
        sf = os.path.join(release_dir, ".signature.sig")
        if not os.path.isfile(sf):
            return None
        try:
            with open(sf, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _current_release_dir() -> Optional[str]:
        """Resolve the current symlink to an actual directory."""
        if os.path.islink(CURRENT_LINK):
            target = os.path.realpath(CURRENT_LINK)
            if os.path.isdir(target):
                return target
        elif os.path.isdir(CURRENT_LINK):
            return CURRENT_LINK
        return None

    def _list_releases() -> list:
        """List all releases sorted by timestamp (newest first)."""
        releases = []
        if not os.path.isdir(RELEASES_DIR):
            return releases
        current = _current_release_dir()
        for d in sorted(os.listdir(RELEASES_DIR), reverse=True):
            full = os.path.join(RELEASES_DIR, d)
            if not os.path.isdir(full):
                continue
            manifest = _read_manifest(full)
            signature = _read_signature(full)
            is_current = (current and os.path.realpath(full) == current)
            mod_count = len([f for f in os.listdir(full) if f.endswith(".sh")]) if os.path.isdir(full) else 0
            releases.append({
                "id": d,
                "path": full,
                "is_current": is_current,
                "modules_count": manifest.get("modules_count", mod_count) if manifest else mod_count,
                "version": manifest.get("version", "?") if manifest else "?",
                "channel": manifest.get("channel", "?") if manifest else "?",
                "created": manifest.get("created", "?") if manifest else "?",
                "created_ts": manifest.get("created_ts", 0) if manifest else 0,
                "signed": (signature.get("signed", False) if signature else False),
                "signature_algorithm": (signature.get("algorithm", "") if signature else ""),
                "key_fingerprint": (signature.get("key_fingerprint", "") if signature else ""),
            })
        return releases

    def _read_bundle_history(limit: int = 50) -> list:
        if not os.path.isfile(BUNDLE_LOG):
            return []
        entries = []
        try:
            with open(BUNDLE_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            return []
        return entries[-limit:]

    def _verify_checksums(release_dir: str) -> dict:
        """Verify file checksums against manifest."""
        manifest = _read_manifest(release_dir)
        if not manifest:
            return {"status": "no_manifest", "verified": 0, "errors": 0, "files": []}

        files_info = manifest.get("files", {})
        results = []
        verified = 0
        errors = 0

        for fname, info in files_info.items():
            fpath = os.path.join(release_dir, fname)
            expected = info.get("sha256", "")
            if not os.path.isfile(fpath):
                results.append({"file": fname, "status": "missing", "expected": expected[:16]})
                errors += 1
                continue
            actual = _file_hash(fpath)
            if actual == expected:
                results.append({"file": fname, "status": "ok", "hash": actual[:16]})
                verified += 1
            else:
                results.append({"file": fname, "status": "mismatch", "expected": expected[:16], "actual": actual[:16]})
                errors += 1

        return {
            "status": "ok" if errors == 0 else "integrity_error",
            "verified": verified,
            "errors": errors,
            "total": len(files_info),
            "files": results,
        }

    def _security_checklist() -> dict:
        """Compute security checklist for module distribution."""
        checks = []

        # 1. Signature enforcement
        require_sig = os.getenv("TPL_REQUIRE_SIGNATURE", "1") == "1"
        checks.append({
            "id": "require_signature",
            "label": "Firma obbligatoria",
            "description": "TPL_REQUIRE_SIGNATURE=1 richiede che tutti i bundle siano firmati",
            "status": "pass" if require_sig else "fail",
            "severity": "critical",
        })

        # 2. Control plane disabled
        cp = os.getenv("ENABLE_CONTROL_PLANE", "0") == "1"
        checks.append({
            "id": "control_plane",
            "label": "Control plane disabilitato",
            "description": "ENABLE_CONTROL_PLANE=0 impedisce esecuzione script via API",
            "status": "pass" if not cp else "fail",
            "severity": "critical",
        })

        # 3. Current release has valid signature
        current = _current_release_dir()
        if current:
            sig = _read_signature(current)
            signed = sig.get("signed", False) if sig else False
            checks.append({
                "id": "current_signed",
                "label": "Release corrente firmata",
                "description": "La release attiva ha una firma valida",
                "status": "pass" if signed else "warn",
                "severity": "high",
            })
        else:
            checks.append({
                "id": "current_signed",
                "label": "Release corrente firmata",
                "description": "Nessuna release corrente (bundle non installato)",
                "status": "info",
                "severity": "medium",
            })

        # 4. Current release integrity
        if current:
            integrity = _verify_checksums(current)
            checks.append({
                "id": "integrity",
                "label": "Integrità file moduli",
                "description": f"{integrity['verified']}/{integrity['total']} file verificati",
                "status": "pass" if integrity["status"] == "ok" else "fail",
                "severity": "critical",
            })

        # 5. HTTPS enforced
        force_https = os.getenv("FORCE_HTTPS", "false").lower() in ("true", "1", "yes")
        checks.append({
            "id": "https",
            "label": "HTTPS forzato",
            "description": "FORCE_HTTPS=true per connessioni sicure",
            "status": "pass" if force_https else "warn",
            "severity": "medium",
        })

        # 6. Modules directory read-only mount
        modules_ro = not os.access(MODULES_DIR, os.W_OK) if os.path.isdir(MODULES_DIR) else True
        checks.append({
            "id": "modules_readonly",
            "label": "Moduli montati in sola lettura",
            "description": "Il container non può scrivere nella directory moduli",
            "status": "pass" if modules_ro else "warn",
            "severity": "high",
        })

        # 7. Update channel
        channel = os.getenv("TPL_UPDATE_CHANNEL", "stable")
        checks.append({
            "id": "update_channel",
            "label": "Canale aggiornamenti",
            "description": f"Canale corrente: {channel}",
            "status": "pass" if channel == "stable" else "info",
            "severity": "low",
        })

        # Compute score
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        max_score = sum(severity_weights.get(c["severity"], 5) for c in checks)
        earned = sum(
            severity_weights.get(c["severity"], 5)
            for c in checks
            if c["status"] == "pass"
        )
        score = round((earned / max_score) * 100) if max_score > 0 else 0
        grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "F"

        return {
            "checks": checks,
            "score": score,
            "grade": grade,
            "pass_count": sum(1 for c in checks if c["status"] == "pass"),
            "fail_count": sum(1 for c in checks if c["status"] == "fail"),
            "warn_count": sum(1 for c in checks if c["status"] == "warn"),
            "total": len(checks),
            "checked_at": int(time.time()),
        }

    # ── Endpoints ─────────────────────────────────────────────────────

    @app.get("/modules/bundle")
    async def modules_bundle_info(_u=Depends(require_admin)):
        """Current bundle info: manifest, signature, integrity."""
        current = _current_release_dir()
        state = _load_state()
        bundle_info = state.get("bundle", {})

        if not current:
            # No bundle system — using legacy modules/ mount
            mod_dir = MODULES_DIR
            mod_count = 0
            if os.path.isdir(mod_dir):
                mod_count = len([f for f in os.listdir(mod_dir) if f.endswith(".sh")])
            return {
                "mode": "legacy",
                "message": "Bundle system non attivo — moduli serviti da mount diretto",
                "modules_dir": mod_dir,
                "modules_count": mod_count,
                "bundle": None,
                "manifest": None,
                "signature": None,
                "integrity": None,
            }

        manifest = _read_manifest(current)
        signature = _read_signature(current)
        integrity = _verify_checksums(current)

        return {
            "mode": "bundle",
            "release_id": os.path.basename(current),
            "release_path": current,
            "modules_count": manifest.get("modules_count", 0) if manifest else 0,
            "bundle": bundle_info,
            "manifest": manifest,
            "signature": {
                "signed": signature.get("signed", False) if signature else False,
                "algorithm": signature.get("algorithm", "") if signature else "",
                "key_fingerprint": signature.get("key_fingerprint", "") if signature else "",
                "signed_at": signature.get("signed_at", "") if signature else "",
            } if signature else None,
            "integrity": integrity,
        }

    @app.get("/modules/releases")
    async def modules_releases(_u=Depends(require_admin)):
        """List all installed releases with metadata."""
        releases = _list_releases()
        return {
            "releases": releases,
            "total": len(releases),
            "current": next((r["id"] for r in releases if r["is_current"]), None),
            "releases_dir": RELEASES_DIR,
        }

    @app.get("/modules/update-history")
    async def modules_update_history(limit: int = 50, _u=Depends(require_admin)):
        """Bundle install/rollback history log."""
        entries = _read_bundle_history(min(limit, 200))
        entries.reverse()
        return {"entries": entries, "total": len(entries)}

    @app.get("/modules/security-checklist")
    async def modules_security_checklist(_u=Depends(require_admin)):
        """Security checklist for module distribution."""
        return _security_checklist()

    @app.get("/modules/integrity")
    async def modules_integrity(_u=Depends(require_admin)):
        """Verify integrity of the current release against its manifest."""
        current = _current_release_dir()
        if not current:
            # Legacy mode: hash all modules in MODULES_DIR
            if not os.path.isdir(MODULES_DIR):
                return {"mode": "legacy", "status": "no_modules_dir", "files": []}
            files = []
            for f in sorted(os.listdir(MODULES_DIR)):
                if f.endswith(".sh"):
                    full = os.path.join(MODULES_DIR, f)
                    files.append({
                        "file": f,
                        "hash": _file_hash(full)[:16],
                        "size": os.path.getsize(full),
                        "status": "unverified",
                    })
            return {"mode": "legacy", "status": "unverified", "files": files, "total": len(files)}

        result = _verify_checksums(current)
        result["mode"] = "bundle"
        result["release_id"] = os.path.basename(current)
        return result

    @app.get("/modules/distribution-config")
    async def modules_distribution_config(_u=Depends(require_admin)):
        """Current distribution configuration (non-secret values only)."""
        return {
            "modules_base": MODULES_BASE,
            "releases_dir": RELEASES_DIR,
            "current_link": CURRENT_LINK,
            "modules_dir": MODULES_DIR,
            "require_signature": os.getenv("TPL_REQUIRE_SIGNATURE", "1") == "1",
            "update_channel": os.getenv("TPL_UPDATE_CHANNEL", "stable"),
            "update_url": os.getenv("TPL_UPDATE_URL", ""),
            "max_releases": int(os.getenv("TPL_MAX_RELEASES", "5")),
            "control_plane_enabled": os.getenv("ENABLE_CONTROL_PLANE", "0") == "1",
            "bundle_active": _current_release_dir() is not None,
        }
