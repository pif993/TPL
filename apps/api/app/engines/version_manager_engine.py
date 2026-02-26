"""
TPL Version Manager Engine — v1.0.0
Controllo versione piattaforma, aggiornamenti OTA/locali, changelog,
confronto versioni, rollback sicuro con preservazione stato.
"""

import json, os, time, hashlib, shutil, subprocess, re
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from urllib.parse import urlparse

_ALLOWED_GIT_SCHEMES = frozenset({"https", "http", "ssh", "git"})


# ── Models ──────────────────────────────────────────────────────────────

PLATFORM_VERSION = "2.1.0"
PLATFORM_CODENAME = "Resilience"
PLATFORM_BUILD = os.getenv("TPL_BUILD_DATE", datetime.now().strftime("%Y%m%d"))

class OTAConfig(BaseModel):
    url: str = Field(..., min_length=5, max_length=500)
    branch: str = Field(default="main", max_length=50)

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        parsed = urlparse(v.strip())
        if parsed.scheme not in _ALLOWED_GIT_SCHEMES:
            raise ValueError(f"URL scheme '{parsed.scheme}' not allowed. Use: {', '.join(sorted(_ALLOWED_GIT_SCHEMES))}")
        # Block file:// for local file access, localhost/internal ranges
        host = (parsed.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".local"):
            raise ValueError(f"URL host '{host}' is not allowed for OTA updates")
        return v.strip()

class RollbackRequest(BaseModel):
    point_id: str = Field(..., min_length=1, max_length=64)
    confirm: bool = False


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx["root"]

    STATE_FILE = os.path.join(root, ".tpl_state.json")
    CHANGELOG_FILE = os.path.join(root, ".tpl_changelog.jsonl")
    ROLLBACK_DIR = os.path.join(root, ".tpl_rollback_points")
    MODULES_DIR = ctx.get("modules_dir", os.path.join(root, "modules"))
    ENGINES_DIR = ctx.get("engines_dir", os.path.join(root, "apps", "api", "app", "engines"))
    # Staged engines are saved to the data volume (container FS is read-only)
    ENGINES_STAGING = os.path.join(root, "engines", "staging")

    # ── Helpers ────────────────────────────────────────────────────────

    def _load_state() -> dict:
        if not os.path.isfile(STATE_FILE):
            return {"installed": {}, "updated": 0}
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"installed": {}, "updated": 0}

    def _save_state(data: dict):
        data["updated"] = int(time.time())
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))

    def _append_changelog(entry: dict):
        row = {"ts": int(time.time()), **entry}
        with open(CHANGELOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    def _read_changelog(limit: int = 100) -> list:
        if not os.path.isfile(CHANGELOG_FILE):
            return []
        lines = []
        with open(CHANGELOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except Exception:
                    continue
        return lines[-limit:]

    def _extract_meta(filepath: str) -> dict:
        """Extract metadata from a shell module file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            m = re.search(
                r"meta\s*\(\)\s*\{[\s\S]*?cat\s+<<[\'\"]JSON[\'\"]\s*\n([\s\S]*?)\nJSON",
                content,
            )
            if m:
                return json.loads(m.group(1))
        except Exception:
            pass
        return {}

    def _file_hash(filepath: str) -> str:
        """SHA-256 of a file."""
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()

    def _scan_available_modules() -> dict:
        """Scan modules/ directory for available shell modules."""
        mods = {}
        if not os.path.isdir(MODULES_DIR):
            return mods
        for f in sorted(os.listdir(MODULES_DIR)):
            if f.endswith(".sh"):
                full = os.path.join(MODULES_DIR, f)
                meta = _extract_meta(full)
                mid = meta.get("id", f.replace(".sh", ""))
                mods[mid] = {
                    "id": mid,
                    "version": meta.get("ver", "0.0.0"),
                    "desc": meta.get("desc", ""),
                    "deps": meta.get("deps", []),
                    "file": f,
                    "hash": _file_hash(full),
                    "size": os.path.getsize(full),
                }
        return mods

    def _scan_engines() -> list:
        """Scan engines/ directory for loaded engines."""
        engines = []
        if not os.path.isdir(ENGINES_DIR):
            return engines
        for f in sorted(os.listdir(ENGINES_DIR)):
            if f.endswith("_engine.py") and not f.startswith("__"):
                full = os.path.join(ENGINES_DIR, f)
                engines.append({
                    "engine": f.replace("_engine.py", ""),
                    "name": f.replace("_engine.py", ""),
                    "file": f,
                    "hash": _file_hash(full),
                    "size": os.path.getsize(full),
                    "lines": sum(1 for _ in open(full, "r", encoding="utf-8")),
                    "status": "ok",
                })
        return engines

    def _version_compare(v1: str, v2: str) -> int:
        """Compare semver strings. Returns -1, 0, or 1."""
        def _parts(v):
            return [int(x) for x in re.findall(r"\d+", v)][:3]
        a, b = _parts(v1), _parts(v2)
        while len(a) < 3:
            a.append(0)
        while len(b) < 3:
            b.append(0)
        for x, y in zip(a, b):
            if x < y:
                return -1
            if x > y:
                return 1
        return 0

    # ── Rollback points ───────────────────────────────────────────────

    def _create_rollback_point(label: str) -> str:
        os.makedirs(ROLLBACK_DIR, exist_ok=True)
        point_id = f"{int(time.time())}_{hashlib.md5(label.encode()).hexdigest()[:8]}"
        point_dir = os.path.join(ROLLBACK_DIR, point_id)
        os.makedirs(point_dir, exist_ok=True)

        # Save state file
        if os.path.isfile(STATE_FILE):
            shutil.copy2(STATE_FILE, os.path.join(point_dir, "state.json"))

        # Save all engine files
        engines_backup = os.path.join(point_dir, "engines")
        os.makedirs(engines_backup, exist_ok=True)
        if os.path.isdir(ENGINES_DIR):
            for f in os.listdir(ENGINES_DIR):
                if f.endswith(".py"):
                    shutil.copy2(
                        os.path.join(ENGINES_DIR, f),
                        os.path.join(engines_backup, f),
                    )

        # Save metadata
        meta = {
            "id": point_id,
            "label": label,
            "created": int(time.time()),
            "platform_version": PLATFORM_VERSION,
            "modules_count": len(_load_state().get("installed", {})),
            "engines_count": len(os.listdir(engines_backup)),
        }
        with open(os.path.join(point_dir, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        return point_id

    def _list_rollback_points() -> list:
        points = []
        if not os.path.isdir(ROLLBACK_DIR):
            return points
        for d in sorted(os.listdir(ROLLBACK_DIR), reverse=True):
            meta_file = os.path.join(ROLLBACK_DIR, d, "meta.json")
            if os.path.isfile(meta_file):
                try:
                    with open(meta_file) as f:
                        points.append(json.load(f))
                except Exception:
                    pass
        return points[:20]  # max 20

    # ── Endpoints ─────────────────────────────────────────────────────

    @app.get("/version/info")
    async def version_info(_u=Depends(ctx["auth_me"])):
        """Platform version, build info, uptime."""
        state = _load_state()
        installed = state.get("installed", {})
        return {
            "platform": {
                "version": PLATFORM_VERSION,
                "codename": PLATFORM_CODENAME,
                "build": PLATFORM_BUILD,
            },
            "modules_installed": len(installed),
            "engines_loaded": len(_scan_engines()),
            "last_update": state.get("updated", 0),
            "uptime_seconds": int(time.time() - app.state._start_time)
            if hasattr(app.state, "_start_time")
            else 0,
        }

    @app.get("/version/modules")
    async def version_modules(_u=Depends(require_admin)):
        """All modules with installed vs available version comparison."""
        state = _load_state()
        installed = state.get("installed", {})
        available = _scan_available_modules()
        engines = {e["name"]: e for e in _scan_engines()}

        result = []
        all_ids = sorted(set(list(installed.keys()) + list(available.keys())))
        for mid in all_ids:
            inst = installed.get(mid, {})
            avail = available.get(mid, {})
            engine_name = mid.split("_", 1)[-1] if "_" in mid else mid
            eng = engines.get(engine_name)

            inst_ver = inst.get("ver", "") if isinstance(inst, dict) else ""
            avail_ver = avail.get("version", "")
            needs_update = False
            if inst_ver and avail_ver:
                needs_update = _version_compare(inst_ver, avail_ver) < 0

            result.append({
                "id": mid,
                "desc": avail.get("desc", ""),
                "installed_version": inst_ver,
                "available_version": avail_ver,
                "installed_at": inst.get("ts", 0) if isinstance(inst, dict) else 0,
                "needs_update": needs_update,
                "has_engine": eng is not None,
                "engine_file": eng["file"] if eng else None,
                "engine_hash": eng["hash"] if eng else None,
                "deps": avail.get("deps", []),
            })
        return {"modules": result, "total": len(result)}

    @app.get("/version/engines")
    async def version_engines(_u=Depends(require_admin)):
        """List all loaded engine files with hashes."""
        return {"engines": _scan_engines()}

    @app.get("/version/changelog")
    async def version_changelog(limit: int = 50, _u=Depends(require_admin)):
        """Change history."""
        entries = _read_changelog(min(limit, 200))
        entries.reverse()
        return {"changelog": entries, "total": len(entries)}

    @app.post("/version/check-updates")
    async def version_check_updates(
        request: Request, cfg: Optional[OTAConfig] = None, _u=Depends(require_admin)
    ):
        """Check for OTA updates from a remote git URL."""
        url = (cfg.url if cfg and cfg.url else os.getenv("TPL_UPDATE_URL", "")).strip()
        branch = (cfg.branch if cfg else None) or "main"
        if not url:
            return {
                "current_version": PLATFORM_VERSION,
                "latest_version": None,
                "update_available": False,
                "remote_tags": [],
                "checked_at": int(time.time()),
                "note": "Nessun URL di aggiornamento configurato. Impostare TPL_UPDATE_URL.",
            }
        try:
            # Try git ls-remote to check remote version
            result = subprocess.run(
                ["git", "ls-remote", "--tags", url],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=root,
            )
            tags = []
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if "refs/tags/" in line:
                        tag = line.split("refs/tags/")[-1].replace("^{}", "")
                        if re.match(r"^v?\d+\.\d+", tag):
                            tags.append(tag.lstrip("v"))

            tags.sort(key=lambda v: [int(x) for x in re.findall(r"\d+", v)][:3])
            latest = tags[-1] if tags else None
            update_available = (
                _version_compare(PLATFORM_VERSION, latest) < 0 if latest else False
            )

            audit(
                request,
                "version.check_updates",
                "success",
                _u.get("sub", "admin"),
                {
                    "url": url,
                    "latest": latest,
                    "update_available": update_available,
                },
            )

            return {
                "current_version": PLATFORM_VERSION,
                "latest_version": latest,
                "update_available": update_available,
                "remote_tags": tags[-10:],
                "checked_at": int(time.time()),
            }
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Remote check timed out")
        except Exception as e:
            raise HTTPException(502, f"Update check failed: {str(e)}")

    @app.post("/version/update/local")
    async def version_update_local(
        request: Request,
        module_file: UploadFile = File(...),
        _u=Depends(require_admin),
    ):
        """Upload and apply a local module update."""
        fname = module_file.filename or ""
        if not fname.endswith(".sh"):
            raise HTTPException(400, "Module file must be a .sh script")
        if not re.fullmatch(r"[0-9A-Za-z_.-]+\.sh", fname):
            raise HTTPException(400, "Invalid filename")

        content = await module_file.read()
        if len(content) > 512_000:
            raise HTTPException(400, "Module file too large (max 512KB)")

        # Create rollback point before update
        point_id = _create_rollback_point(f"pre-update-{fname}")

        # Write module file
        dest = os.path.join(MODULES_DIR, fname)
        with open(dest, "wb") as f:
            f.write(content)
        os.chmod(dest, 0o755)

        # Extract meta
        meta = _extract_meta(dest)

        _append_changelog({
            "action": "local_update",
            "module": fname,
            "version": meta.get("ver", "?"),
            "actor": _u.get("sub", "admin"),
            "rollback_point": point_id,
        })

        audit(
            request,
            "version.local_update",
            "success",
            _u.get("sub", "admin"),
            {"module": fname, "version": meta.get("ver", "?")},
        )

        return {
            "status": "uploaded",
            "module": fname,
            "meta": meta,
            "rollback_point": point_id,
            "note": "Module uploaded. Use /modules/apply to activate it.",
        }

    @app.post("/version/update/ota")
    async def version_update_ota(
        request: Request, cfg: OTAConfig, _u=Depends(require_admin)
    ):
        """Attempt OTA pull from a remote git repository."""
        # Create rollback point first
        point_id = _create_rollback_point("pre-ota-update")

        engines_staged = False
        try:
            # Check if .git exists
            git_dir = os.path.join(root, ".git")
            if os.path.isdir(git_dir):
                # Git pull
                result = subprocess.run(
                    ["git", "pull", "origin", cfg.branch],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=root,
                )
            else:
                # Shallow clone to temp, copy modules
                import tempfile

                with tempfile.TemporaryDirectory() as tmp:
                    result = subprocess.run(
                        [
                            "git",
                            "clone",
                            "--depth=1",
                            "--branch",
                            cfg.branch,
                            cfg.url,
                            tmp,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        # Copy new modules to data volume
                        src_modules = os.path.join(tmp, "modules")
                        if os.path.isdir(src_modules):
                            os.makedirs(MODULES_DIR, exist_ok=True)
                            for f in os.listdir(src_modules):
                                if f.endswith(".sh"):
                                    shutil.copy2(
                                        os.path.join(src_modules, f),
                                        os.path.join(MODULES_DIR, f),
                                    )
                        # Stage new engines on data volume (container FS is read-only)
                        src_engines = os.path.join(
                            tmp, "apps", "api", "app", "engines"
                        )
                        engines_staged = False
                        if os.path.isdir(src_engines):
                            os.makedirs(ENGINES_STAGING, exist_ok=True)
                            for f in os.listdir(src_engines):
                                if f.endswith("_engine.py"):
                                    shutil.copy2(
                                        os.path.join(src_engines, f),
                                        os.path.join(ENGINES_STAGING, f),
                                    )
                                    engines_staged = True

            success = result.returncode == 0
            _append_changelog({
                "action": "ota_update",
                "url": cfg.url,
                "branch": cfg.branch,
                "success": success,
                "actor": _u.get("sub", "admin"),
                "rollback_point": point_id,
                "engines_staged": engines_staged,
                "output": result.stdout[-500:] if success else result.stderr[-500:],
            })

            audit(
                request,
                "version.ota_update",
                "success" if success else "failed",
                _u.get("sub", "admin"),
                {"url": cfg.url, "branch": cfg.branch},
            )

            if not success:
                raise HTTPException(
                    500,
                    {
                        "error": "OTA update failed",
                        "stderr": result.stderr[-1000:],
                        "rollback_point": point_id,
                    },
                )

            return {
                "status": "updated",
                "rollback_point": point_id,
                "output": result.stdout[-500:],
                "note": "OTA update applied. Restart containers to load new engines.",
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"OTA failed: {str(e)}")

    @app.get("/version/rollback-points")
    async def version_rollback_points(_u=Depends(require_admin)):
        """List available rollback points."""
        return {"points": _list_rollback_points()}

    @app.post("/version/rollback")
    async def version_rollback(
        request: Request, req: RollbackRequest, _u=Depends(require_admin)
    ):
        """Rollback to a specific point."""
        if not req.confirm:
            raise HTTPException(428, "Set confirm=true to proceed with rollback")

        point_dir = os.path.join(ROLLBACK_DIR, req.point_id)
        if not os.path.isdir(point_dir):
            raise HTTPException(404, "Rollback point not found")

        # Create a new rollback point of current state before rolling back
        pre_id = _create_rollback_point(f"pre-rollback-to-{req.point_id}")

        try:
            # Restore state
            saved_state = os.path.join(point_dir, "state.json")
            if os.path.isfile(saved_state):
                shutil.copy2(saved_state, STATE_FILE)

            # Stage engines for restore on data volume (container FS is read-only)
            saved_engines = os.path.join(point_dir, "engines")
            if os.path.isdir(saved_engines):
                os.makedirs(ENGINES_STAGING, exist_ok=True)
                for f in os.listdir(saved_engines):
                    if f.endswith(".py"):
                        shutil.copy2(
                            os.path.join(saved_engines, f),
                            os.path.join(ENGINES_STAGING, f),
                        )

            _append_changelog({
                "action": "rollback",
                "to_point": req.point_id,
                "pre_rollback_point": pre_id,
                "actor": _u.get("sub", "admin"),
            })

            audit(
                request,
                "version.rollback",
                "success",
                _u.get("sub", "admin"),
                {"to_point": req.point_id},
            )

            return {
                "status": "rolled_back",
                "to_point": req.point_id,
                "pre_rollback_point": pre_id,
                "note": "Rollback completed. Engines staged in /data/engines/staging/. Rebuild container to apply engine changes.",
            }
        except Exception as e:
            raise HTTPException(500, f"Rollback failed: {str(e)}")

    @app.get("/version/dependencies")
    async def version_dependencies(_u=Depends(require_admin)):
        """Full dependency graph of all modules."""
        available = _scan_available_modules()
        state = _load_state()
        installed = state.get("installed", {})

        graph = {}
        issues = []
        for mid, mod in available.items():
            deps = mod.get("deps", [])
            graph[mid] = {
                "deps": deps,
                "installed": mid in installed,
                "version": mod.get("version", "?"),
            }
            # Check for missing deps
            for dep in deps:
                if dep not in available:
                    issues.append({
                        "type": "missing_dep",
                        "module": mid,
                        "missing": dep,
                    })
                elif dep not in installed:
                    issues.append({
                        "type": "uninstalled_dep",
                        "module": mid,
                        "dep": dep,
                    })

        # Check for orphan engines (no shell module)
        engines = _scan_engines()
        mod_ids = set(available.keys())
        for eng in engines:
            has_shell = False
            for mid in mod_ids:
                if eng["name"] in mid or mid.split("_", 1)[-1].startswith(
                    eng["name"].split("_")[0]
                ):
                    has_shell = True
                    break
            if not has_shell:
                issues.append({
                    "type": "orphan_engine",
                    "engine": eng["file"],
                })

        return {"graph": graph, "issues": issues}

    # Record startup time
    if not hasattr(app.state, "_start_time"):
        app.state._start_time = time.time()
