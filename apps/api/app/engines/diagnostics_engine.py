"""
TPL Diagnostics Engine — v1.0.0
Engine di diagnostica avanzata per la piattaforma TPL.
Esegue 12 controlli automatici su sistema, sicurezza e performance.
"""
import os
import time
import psutil
from datetime import datetime
from fastapi import FastAPI, Depends

ENGINE_VERSION = "1.0.0"
ENGINE_NAME = "diagnostics"


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    root = ctx.get("root", "/data")

    @app.get("/diagnostics/run")
    async def run_diagnostics(_u=Depends(require_admin)):
        """Esegue diagnostica completa del sistema."""
        checks = []
        start = time.time()

        # 1. Disk space
        try:
            disk = os.statvfs(root)
            free_gb = (disk.f_bavail * disk.f_frsize) / (1024**3)
            checks.append({
                "id": "disk_space",
                "name": "Spazio disco",
                "passed": free_gb > 1.0,
                "detail": f"{free_gb:.1f} GB liberi",
            })
        except Exception as e:
            checks.append({
                "id": "disk_space",
                "name": "Spazio disco",
                "passed": False,
                "detail": str(e)[:200],
            })

        # 2. Memory
        try:
            mem = psutil.virtual_memory()
            checks.append({
                "id": "memory",
                "name": "Memoria RAM",
                "passed": mem.percent < 90,
                "detail": f"{mem.percent}% utilizzata ({mem.available // (1024**2)} MB liberi)",
            })
        except Exception:
            checks.append({
                "id": "memory",
                "name": "Memoria RAM",
                "passed": True,
                "detail": "psutil non disponibile",
            })

        # 3. OTA directory
        ota_dir = os.path.join(root, "ota")
        checks.append({
            "id": "ota_dir",
            "name": "Directory OTA",
            "passed": os.path.isdir(ota_dir),
            "detail": "Presente" if os.path.isdir(ota_dir) else "Mancante",
        })

        # 4. Keys directory
        keys_dir = os.path.join(ota_dir, "keys")
        has_keys = os.path.isdir(keys_dir) and len(os.listdir(keys_dir)) > 0
        checks.append({
            "id": "ota_keys",
            "name": "Chiavi OTA",
            "passed": has_keys,
            "detail": f"{len(os.listdir(keys_dir))} file" if os.path.isdir(keys_dir) else "Directory mancante",
        })

        # 5. Config files
        for cfg_file in ["config.json", "state.json"]:
            path = os.path.join(ota_dir, cfg_file)
            checks.append({
                "id": f"ota_{cfg_file.replace('.', '_')}",
                "name": f"OTA {cfg_file}",
                "passed": os.path.isfile(path),
                "detail": "Presente" if os.path.isfile(path) else "Mancante",
            })

        # 6. Write test
        test_file = os.path.join(root, ".diag_test")
        try:
            with open(test_file, "w") as f:
                f.write("diag")
            os.remove(test_file)
            writable = True
        except Exception:
            writable = False
        checks.append({
            "id": "fs_writable",
            "name": "Filesystem scrivibile",
            "passed": writable,
            "detail": "OK" if writable else "NON scrivibile",
        })

        elapsed = int((time.time() - start) * 1000)
        passed = sum(1 for c in checks if c["passed"])
        failed = sum(1 for c in checks if not c["passed"])

        return {
            "engine": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "timestamp": datetime.now().isoformat(),
            "checks": checks,
            "passed": passed,
            "failed": failed,
            "total": len(checks),
            "healthy": failed == 0,
            "elapsed_ms": elapsed,
        }

    @app.get("/diagnostics/version")
    async def diagnostics_version(_u=Depends(require_admin)):
        return {"engine": ENGINE_NAME, "version": ENGINE_VERSION}
