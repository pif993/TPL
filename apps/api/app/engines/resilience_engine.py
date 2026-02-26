"""
TPL Resilience Engine — v2.0.0
Deep health probes, backup/restore, monitoraggio risorse con AI,
predizioni capacità, trend analysis, failure pattern detection,
smart alerting thresholds, readiness check, metriche persistenti.
"""

import json, os, time, hashlib, shutil, gzip, math, threading
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional


class RestoreRequest(BaseModel):
    backup_id: str = Field(..., min_length=1, max_length=128)
    confirm: bool = False


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx["root"]

    BACKUP_DIR = os.path.join(root, ".tpl_backups")
    METRICS_FILE = os.path.join(root, ".tpl_resilience_metrics.json")

    # State files to protect
    STATE_FILES = [
        ".tpl_state.json",
        ".tpl_audit.jsonl",
        ".tpl_events.jsonl",
        ".tpl_comm.jsonl",
        ".tpl_security.jsonl",
        ".tpl_changelog.jsonl",
        ".tpl_users.json",
    ]

    # ── Resilience metrics (persistent) ───────────────────────────────
    _lock = threading.Lock()

    def _load_metrics() -> dict:
        if not os.path.isfile(METRICS_FILE):
            return _default_metrics()
        try:
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return _default_metrics()

    def _save_metrics(data: dict):
        with _lock:
            with open(METRICS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))

    def _default_metrics():
        return {
            "health_checks": 0,
            "last_health_check": 0,
            "backups_created": 0,
            "backups_restored": 0,
            "last_backup": 0,
            "errors_caught": 0,
            "uptime_start": int(time.time()),
            "consecutive_healthy": 0,
            "daily_snapshots": {},
        }

    # Initialize metrics on load
    m = _load_metrics()
    if m.get("uptime_start", 0) == 0:
        m["uptime_start"] = int(time.time())
        _save_metrics(m)

    # ── AI helpers ────────────────────────────────────────────────────

    RESOURCE_HISTORY_FILE = os.path.join(root, ".tpl_resource_history.jsonl")

    def _mean(vals: list) -> float:
        return sum(vals) / len(vals) if vals else 0

    def _stddev(vals: list) -> float:
        if len(vals) < 2:
            return 0
        m = _mean(vals)
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))

    def _linear_regression(points: list) -> tuple:
        n = len(points)
        if n < 2:
            return (0, 0, 0)
        sx = sum(p[0] for p in points)
        sy = sum(p[1] for p in points)
        sxy = sum(p[0] * p[1] for p in points)
        sx2 = sum(p[0] ** 2 for p in points)
        d = n * sx2 - sx ** 2
        if d == 0:
            return (0, sy / n, 0)
        slope = (n * sxy - sx * sy) / d
        intercept = (sy - slope * sx) / n
        ym = sy / n
        ss_tot = sum((p[1] - ym) ** 2 for p in points)
        ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in points)
        r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
        return (slope, intercept, max(0, r2))

    def _record_resource_snapshot():
        """Record current resource state for trend analysis."""
        res = _get_resources()
        entry = {
            "ts": int(time.time()),
            "cpu_pct": res["cpu"].get("usage_pct", -1),
            "mem_pct": res["memory"].get("usage_pct", -1),
            "disk_pct": res["disk"].get("usage_pct", -1),
            "load_1": res["load_avg"].get("1min", -1),
        }
        try:
            with open(RESOURCE_HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            # Trim to 4320 entries (3 days at 1-min intervals)
            _trim_history(4320)
        except Exception:
            pass

    def _trim_history(max_lines: int):
        if not os.path.isfile(RESOURCE_HISTORY_FILE):
            return
        try:
            with open(RESOURCE_HISTORY_FILE, "r") as f:
                lines = f.readlines()
            if len(lines) > max_lines:
                with open(RESOURCE_HISTORY_FILE, "w") as f:
                    f.writelines(lines[-max_lines:])
        except Exception:
            pass

    def _read_resource_history(limit: int = 500) -> list:
        if not os.path.isfile(RESOURCE_HISTORY_FILE):
            return []
        entries = []
        try:
            with open(RESOURCE_HISTORY_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            continue
        except Exception:
            pass
        return entries[-limit:]

    def _predict_capacity() -> dict:
        """AI capacity prediction based on resource history."""
        history = _read_resource_history(500)
        if len(history) < 5:
            return {"status": "insufficient_data", "predictions": {}}

        predictions = {}
        threshold = 90  # critical threshold

        for metric in ("cpu_pct", "mem_pct", "disk_pct"):
            points = [(h["ts"], h[metric]) for h in history if h.get(metric, -1) >= 0]
            if len(points) < 5:
                continue

            slope, intercept, r2 = _linear_regression(points)
            current = points[-1][1]
            now = int(time.time())

            # Hours until threshold
            hours_to_threshold = None
            if slope > 0 and current < threshold:
                remaining = threshold - current
                seconds = remaining / slope
                hours_to_threshold = round(seconds / 3600, 1)

            # Forecasts
            forecasts = {}
            for hours in (1, 6, 24):
                future_ts = now + hours * 3600
                predicted = slope * future_ts + intercept
                predicted = max(0, min(100, predicted))
                forecasts[f"{hours}h"] = round(predicted, 1)

            # Anomaly detection
            values = [p[1] for p in points]
            mean_val = _mean(values)
            std_val = _stddev(values)
            is_anomaly = std_val > 0 and abs(current - mean_val) > 2.5 * std_val

            label = metric.replace("_pct", "").upper()
            predictions[label] = {
                "current": round(current, 1),
                "trend": "rising" if slope > 0.001 else "falling" if slope < -0.001 else "stable",
                "slope_per_hour": round(slope * 3600, 3),
                "r2": round(r2, 3),
                "hours_to_threshold": hours_to_threshold,
                "forecasts": forecasts,
                "is_anomaly": is_anomaly,
                "mean": round(mean_val, 1),
                "std": round(std_val, 1),
            }

        return {"status": "ok", "predictions": predictions, "data_points": len(history)}

    def _failure_patterns() -> list:
        """Detect recurring failure patterns in metrics history."""
        history = _read_resource_history(500)
        if len(history) < 10:
            return []

        patterns = []

        # Detect repeated spikes
        for metric in ("cpu_pct", "mem_pct"):
            values = [h[metric] for h in history if h.get(metric, -1) >= 0]
            if len(values) < 10:
                continue

            mean_val = _mean(values)
            std_val = _stddev(values)
            if std_val == 0:
                continue

            spike_count = sum(1 for v in values if v > mean_val + 2 * std_val)
            if spike_count >= 3:
                label = metric.replace("_pct", "").upper()
                patterns.append({
                    "type": f"{label}_spikes",
                    "description": f"{spike_count} picchi anomali di {label} (>{mean_val + 2 * std_val:.0f}%)",
                    "severity": "high" if spike_count >= 5 else "medium",
                    "spike_count": spike_count,
                    "threshold": round(mean_val + 2 * std_val, 1),
                })

        # Detect monotonic growth (disk filling)
        disk_values = [h["disk_pct"] for h in history if h.get("disk_pct", -1) >= 0]
        if len(disk_values) >= 20:
            # Check if last 20 values are mostly increasing
            increases = sum(1 for i in range(1, len(disk_values[-20:])) if disk_values[-20:][i] >= disk_values[-20:][i-1])
            if increases >= 15:
                patterns.append({
                    "type": "disk_filling",
                    "description": f"Disco in crescita costante ({increases}/19 incrementi)",
                    "severity": "high" if disk_values[-1] > 80 else "medium",
                    "current": round(disk_values[-1], 1),
                })

        return patterns

    # ── System resource monitoring ────────────────────────────────────

    def _get_resources() -> dict:
        resources = {
            "cpu": _cpu_info(),
            "memory": _memory_info(),
            "disk": _disk_info(),
            "load_avg": _load_avg(),
            "collected_at": int(time.time()),
        }
        return resources

    def _cpu_info() -> dict:
        try:
            with open("/proc/stat", "r") as f:
                line = f.readline()
            parts = line.split()
            if len(parts) >= 5:
                user, nice, system, idle = (
                    int(parts[1]),
                    int(parts[2]),
                    int(parts[3]),
                    int(parts[4]),
                )
                total = user + nice + system + idle
                usage = round((1 - idle / max(total, 1)) * 100, 1)
                return {
                    "usage_pct": usage,
                    "user": user,
                    "system": system,
                    "idle": idle,
                    "cores": os.cpu_count() or 1,
                }
        except Exception:
            pass
        return {"usage_pct": -1, "cores": os.cpu_count() or 1}

    def _memory_info() -> dict:
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = int(parts[1].strip().split()[0]) * 1024  # KB to bytes
                    info[key] = val
            total = info.get("MemTotal", 0)
            available = info.get("MemAvailable", 0)
            used = total - available
            return {
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "usage_pct": round(used / max(total, 1) * 100, 1),
                "swap_total": info.get("SwapTotal", 0),
                "swap_used": info.get("SwapTotal", 0) - info.get("SwapFree", 0),
            }
        except Exception:
            return {"total_bytes": 0, "used_bytes": 0, "usage_pct": -1}

    def _disk_info() -> dict:
        try:
            st = os.statvfs(root)
            total = st.f_blocks * st.f_frsize
            free = st.f_bfree * st.f_frsize
            used = total - free
            return {
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "usage_pct": round(used / max(total, 1) * 100, 1),
                "path": root,
            }
        except Exception:
            return {"total_bytes": 0, "used_bytes": 0, "usage_pct": -1}

    def _load_avg() -> dict:
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
            return {
                "1min": float(parts[0]),
                "5min": float(parts[1]),
                "15min": float(parts[2]),
            }
        except Exception:
            return {"1min": -1, "5min": -1, "15min": -1}

    # ── Engine health probing ─────────────────────────────────────────

    def _probe_engines() -> list:
        """Probe each loaded engine by checking known app.state markers."""
        probes = []

        engine_markers = {
            "log_engine": {
                "state_key": "log_engine_append",
                "test": "callable",
            },
            "security_engine": {
                "state_key": "security_engine_alert",
                "test": "callable",
            },
            "user_management": {
                "state_key": "user_mgmt",
                "test": "exists",
            },
        }

        for name, marker in engine_markers.items():
            obj = getattr(app.state, marker["state_key"], None)
            if marker["test"] == "callable":
                healthy = callable(obj) if obj is not None else False
            else:
                healthy = obj is not None
            probes.append({
                "engine": name,
                "healthy": healthy,
                "marker": marker["state_key"],
            })

        # Check engine files exist
        engines_dir = ctx.get("engines_dir", "")
        if engines_dir and os.path.isdir(engines_dir):
            for f in sorted(os.listdir(engines_dir)):
                if f.endswith("_engine.py") and not f.startswith("__"):
                    name = f.replace("_engine.py", "")
                    if not any(p["engine"] == name for p in probes):
                        probes.append({
                            "engine": name,
                            "healthy": True,
                            "marker": "file_exists",
                        })

        return probes

    def _check_state_files() -> list:
        """Check health of critical state files."""
        results = []
        for sf in STATE_FILES:
            full = os.path.join(root, sf)
            exists = os.path.isfile(full)
            size = os.path.getsize(full) if exists else 0
            writable = os.access(full, os.W_OK) if exists else os.access(root, os.W_OK)
            corrupted = False

            if exists and sf.endswith(".json"):
                try:
                    with open(full, "r") as f:
                        json.load(f)
                except Exception:
                    corrupted = True
            elif exists and sf.endswith(".jsonl"):
                try:
                    with open(full, "r") as f:
                        last_line = ""
                        for line in f:
                            if line.strip():
                                last_line = line.strip()
                        if last_line:
                            json.loads(last_line)
                except Exception:
                    corrupted = True

            results.append({
                "file": sf,
                "exists": exists,
                "size_bytes": size,
                "writable": writable,
                "corrupted": corrupted,
            })
        return results

    # ── Backup management ─────────────────────────────────────────────

    def _get_enc():
        """Get encryption engine if available."""
        return getattr(app.state, "encryption_engine", None)

    def _get_comm():
        """Get communication engine alert function if available."""
        return getattr(app.state, "security_engine_alert", None)

    def _notify(action: str, detail: str):
        """Send notification via communication engine if available."""
        alert_fn = _get_comm()
        if callable(alert_fn):
            try:
                alert_fn({"source": "resilience", "action": action, "detail": detail, "ts": time.time()})
            except Exception:
                pass

    def _create_backup(label: str = "") -> dict:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = int(time.time())
        bid = f"backup_{ts}"
        bdir = os.path.join(BACKUP_DIR, bid)
        os.makedirs(bdir, exist_ok=True)

        enc = _get_enc()
        encrypted = enc is not None

        saved = []
        total_size = 0
        for sf in STATE_FILES:
            full = os.path.join(root, sf)
            if os.path.isfile(full):
                dest = os.path.join(bdir, sf + ".gz")
                with open(full, "rb") as fin:
                    raw = fin.read()
                orig_size = len(raw)

                # Gzip compress
                import io
                buf = io.BytesIO()
                with gzip.open(buf, "wb") as gz:
                    gz.write(raw)
                compressed = buf.getvalue()

                # Encrypt if encryption engine available
                if enc:
                    try:
                        compressed = enc["encrypt"](compressed)
                        if isinstance(compressed, str):
                            compressed = compressed.encode("ascii")
                        dest = dest + ".enc"
                    except Exception:
                        encrypted = False

                with open(dest, "wb") as fout:
                    if isinstance(compressed, str):
                        fout.write(compressed.encode("ascii"))
                    else:
                        fout.write(compressed)

                comp_size = os.path.getsize(dest)
                saved.append({
                    "file": sf,
                    "original_size": orig_size,
                    "compressed_size": comp_size,
                    "encrypted": encrypted,
                })
                total_size += orig_size

        meta = {
            "id": bid,
            "label": label or f"Auto backup {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "created": ts,
            "files": saved,
            "total_size": total_size,
            "file_count": len(saved),
            "encrypted": encrypted,
        }
        with open(os.path.join(bdir, "_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        # Update metrics
        metrics = _load_metrics()
        metrics["backups_created"] = metrics.get("backups_created", 0) + 1
        metrics["last_backup"] = ts
        _save_metrics(metrics)

        _notify("backup_created", f"Backup {bid} created ({len(saved)} files, encrypted={encrypted})")

        return meta

    def _list_backups() -> list:
        backups = []
        if not os.path.isdir(BACKUP_DIR):
            return backups
        for d in sorted(os.listdir(BACKUP_DIR), reverse=True):
            meta_file = os.path.join(BACKUP_DIR, d, "_meta.json")
            if os.path.isfile(meta_file):
                try:
                    with open(meta_file) as f:
                        backups.append(json.load(f))
                except Exception:
                    pass
        return backups[:30]

    def _restore_backup(bid: str) -> dict:
        bdir = os.path.join(BACKUP_DIR, bid)
        if not os.path.isdir(bdir):
            raise ValueError(f"Backup {bid} not found")

        enc = _get_enc()
        restored = []
        temp_files = []  # Track temp files for atomic swap

        try:
            for sf in STATE_FILES:
                # Check encrypted version first, then plain gzip
                enc_file = os.path.join(bdir, sf + ".gz.enc")
                gz_file = os.path.join(bdir, sf + ".gz")
                dest = os.path.join(root, sf)
                # Write to temp file first, then swap atomically
                temp_dest = dest + ".restore_tmp"

                if os.path.isfile(enc_file) and enc:
                    # Decrypt then decompress
                    with open(enc_file, "rb") as fin:
                        data = fin.read()
                    try:
                        decrypted = enc["decrypt"](data.decode("ascii") if isinstance(data, bytes) else data)
                        if isinstance(decrypted, str):
                            decrypted = decrypted.encode("latin-1")
                        import io
                        buf = io.BytesIO(decrypted)
                        with gzip.open(buf, "rb") as gz:
                            plain = gz.read()
                        # Verify JSON integrity before writing
                        if sf.endswith(".json"):
                            json.loads(plain)  # validate
                        elif sf.endswith(".jsonl"):
                            for line in plain.decode("utf-8").strip().split("\n"):
                                if line.strip():
                                    json.loads(line)  # validate each line
                        with open(temp_dest, "wb") as fout:
                            fout.write(plain)
                            fout.flush()
                            os.fsync(fout.fileno())
                        temp_files.append((temp_dest, dest, sf))
                    except Exception:
                        # Fallback: try plain gz
                        if os.path.isfile(gz_file):
                            with gzip.open(gz_file, "rb") as fin:
                                plain = fin.read()
                            with open(temp_dest, "wb") as fout:
                                fout.write(plain)
                                fout.flush()
                                os.fsync(fout.fileno())
                            temp_files.append((temp_dest, dest, sf))
                elif os.path.isfile(gz_file):
                    with gzip.open(gz_file, "rb") as fin:
                        plain = fin.read()
                    with open(temp_dest, "wb") as fout:
                        fout.write(plain)
                        fout.flush()
                        os.fsync(fout.fileno())
                    temp_files.append((temp_dest, dest, sf))

            # All temp files written successfully — now do atomic swap
            for temp_path, final_path, sf_name in temp_files:
                os.replace(temp_path, final_path)
                restored.append(sf_name)

        except Exception:
            # Cleanup temp files on failure
            for temp_path, _, _ in temp_files:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

        # Update metrics
        metrics = _load_metrics()
        metrics["backups_restored"] = metrics.get("backups_restored", 0) + 1
        _save_metrics(metrics)

        _notify("backup_restored", f"Backup {bid} restored ({len(restored)} files)")

        return {"restored_files": restored, "count": len(restored)}

    # ── Cleanup old backups (keep last 10) ────────────────────────────

    def _cleanup_backups(keep: int = 10):
        if not os.path.isdir(BACKUP_DIR):
            return
        dirs = sorted(
            [
                d
                for d in os.listdir(BACKUP_DIR)
                if os.path.isdir(os.path.join(BACKUP_DIR, d))
            ]
        )
        while len(dirs) > keep:
            old = dirs.pop(0)
            shutil.rmtree(os.path.join(BACKUP_DIR, old), ignore_errors=True)

    # ── Endpoints ─────────────────────────────────────────────────────

    @app.get("/resilience/health")
    async def resilience_health(_u=Depends(require_admin)):
        """Deep health probe — checks all engines, state files, resources."""
        engines = _probe_engines()
        state_files = _check_state_files()
        resources = _get_resources()

        all_engines_ok = all(e["healthy"] for e in engines)
        no_corruption = not any(sf["corrupted"] for sf in state_files)
        mem_ok = resources["memory"].get("usage_pct", 0) < 90
        disk_ok = resources["disk"].get("usage_pct", 0) < 90

        overall = "healthy"
        issues = []
        if not all_engines_ok:
            overall = "degraded"
            issues.append("One or more engines are unhealthy")
        if not no_corruption:
            overall = "degraded"
            issues.append("Corrupted state file detected")
        if not mem_ok:
            overall = "warning" if overall == "healthy" else overall
            issues.append(f"Memory usage high: {resources['memory'].get('usage_pct')}%")
        if not disk_ok:
            overall = "warning" if overall == "healthy" else overall
            issues.append(f"Disk usage high: {resources['disk'].get('usage_pct')}%")

        # Update metrics
        metrics = _load_metrics()
        metrics["health_checks"] = metrics.get("health_checks", 0) + 1
        metrics["last_health_check"] = int(time.time())
        if overall == "healthy":
            metrics["consecutive_healthy"] = (
                metrics.get("consecutive_healthy", 0) + 1
            )
        else:
            metrics["consecutive_healthy"] = 0
        _save_metrics(metrics)

        return {
            "status": overall,
            "issues": issues,
            "engines": engines,
            "state_files": state_files,
            "resources": resources,
            "checked_at": int(time.time()),
        }

    @app.get("/resilience/readiness")
    async def resilience_readiness():
        """Quick readiness probe (no auth required — for Docker healthcheck)."""
        try:
            # Quick check: can we read state file?
            state_file = os.path.join(root, ".tpl_state.json")
            if os.path.isfile(state_file):
                with open(state_file, "r") as f:
                    json.load(f)
            # Check disk writability
            test_file = os.path.join(root, ".tpl_readiness_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            return {"ready": True, "ts": int(time.time())}
        except Exception as e:
            raise HTTPException(503, {"ready": False, "error": str(e)})

    @app.get("/resilience/resources")
    async def resilience_resources(_u=Depends(require_admin)):
        """System resource monitoring — CPU, memory, disk, load."""
        resources = _get_resources()
        metrics = _load_metrics()

        # Compute alerts
        alerts = []
        mem_pct = resources["memory"].get("usage_pct", 0)
        disk_pct = resources["disk"].get("usage_pct", 0)
        load_1 = resources["load_avg"].get("1min", 0)
        cores = resources["cpu"].get("cores", 1)

        if mem_pct > 90:
            alerts.append({"level": "critical", "msg": f"Memory at {mem_pct}%"})
        elif mem_pct > 75:
            alerts.append({"level": "warning", "msg": f"Memory at {mem_pct}%"})

        if disk_pct > 90:
            alerts.append({"level": "critical", "msg": f"Disk at {disk_pct}%"})
        elif disk_pct > 75:
            alerts.append({"level": "warning", "msg": f"Disk at {disk_pct}%"})

        if load_1 > cores * 2:
            alerts.append({"level": "critical", "msg": f"Load avg {load_1} (cores: {cores})"})
        elif load_1 > cores:
            alerts.append({"level": "warning", "msg": f"Load avg {load_1} (cores: {cores})"})

        return {
            **resources,
            "alerts": alerts,
            "metrics": {
                "health_checks": metrics.get("health_checks", 0),
                "consecutive_healthy": metrics.get("consecutive_healthy", 0),
                "uptime_seconds": int(time.time()) - metrics.get("uptime_start", int(time.time())),
            },
        }

    @app.post("/resilience/backup")
    async def resilience_backup(
        request: Request, label: str = "", _u=Depends(require_admin)
    ):
        """Create a backup of all state files."""
        try:
            meta = _create_backup(label)
            _cleanup_backups(10)

            audit(
                request,
                "resilience.backup",
                "success",
                _u.get("sub", "admin"),
                {"backup_id": meta["id"], "files": meta["file_count"]},
            )

            return {"status": "created", **meta}
        except Exception as e:
            raise HTTPException(500, f"Backup failed: {str(e)}")

    @app.get("/resilience/backups")
    async def resilience_backups(_u=Depends(require_admin)):
        """List available backups."""
        backups = _list_backups()
        total_size = sum(
            sum(f.get("compressed_size", 0) for f in b.get("files", []))
            for b in backups
        )
        return {
            "backups": backups,
            "total": len(backups),
            "total_compressed_size": total_size,
        }

    @app.post("/resilience/restore")
    async def resilience_restore(
        request: Request, req: RestoreRequest, _u=Depends(require_admin)
    ):
        """Restore state from a backup."""
        if not req.confirm:
            raise HTTPException(
                428, "Set confirm=true to proceed with restore"
            )
        try:
            # Auto-backup before restore
            _create_backup("pre-restore-auto")
            result = _restore_backup(req.backup_id)

            audit(
                request,
                "resilience.restore",
                "success",
                _u.get("sub", "admin"),
                {"backup_id": req.backup_id, **result},
            )

            return {"status": "restored", **result}
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            raise HTTPException(500, f"Restore failed: {str(e)}")

    @app.get("/resilience/status")
    async def resilience_status(_u=Depends(require_admin)):
        """Overall resilience status — health + resources + backup age."""
        metrics = _load_metrics()
        resources = _get_resources()
        backups = _list_backups()
        state_files = _check_state_files()

        last_backup_age = (
            int(time.time()) - metrics.get("last_backup", 0)
            if metrics.get("last_backup", 0)
            else -1
        )

        # Score resilience 0-100
        score = 100
        issues = []

        # Backup freshness (max -30)
        if last_backup_age < 0:
            score -= 30
            issues.append("No backups exist")
        elif last_backup_age > 86400:
            score -= 20
            issues.append(f"Last backup is {last_backup_age // 3600}h old")
        elif last_backup_age > 43200:
            score -= 10
            issues.append(f"Last backup is {last_backup_age // 3600}h old")

        # State file health (max -30)
        for sf in state_files:
            if sf["corrupted"]:
                score -= 15
                issues.append(f"Corrupted: {sf['file']}")
            if not sf["writable"]:
                score -= 10
                issues.append(f"Not writable: {sf['file']}")

        # Resource health (max -20)
        mem_pct = resources["memory"].get("usage_pct", 0)
        disk_pct = resources["disk"].get("usage_pct", 0)
        if mem_pct > 90:
            score -= 15
            issues.append(f"Memory critical: {mem_pct}%")
        elif mem_pct > 75:
            score -= 5
        if disk_pct > 90:
            score -= 15
            issues.append(f"Disk critical: {disk_pct}%")
        elif disk_pct > 75:
            score -= 5

        # Uptime stability (max -20)
        if metrics.get("consecutive_healthy", 0) < 3:
            score -= 10
            issues.append("Insufficient consecutive healthy checks")

        score = max(0, min(100, score))
        grade = (
            "A+"
            if score >= 95
            else "A"
            if score >= 85
            else "B"
            if score >= 70
            else "C"
            if score >= 55
            else "D"
            if score >= 40
            else "F"
        )

        return {
            "score": score,
            "grade": grade,
            "issues": issues,
            "last_backup_age_seconds": last_backup_age,
            "backups_available": len(backups),
            "health_checks_total": metrics.get("health_checks", 0),
            "consecutive_healthy": metrics.get("consecutive_healthy", 0),
            "uptime_seconds": int(time.time())
            - metrics.get("uptime_start", int(time.time())),
            "resources_summary": {
                "cpu_pct": resources["cpu"].get("usage_pct", -1),
                "mem_pct": mem_pct,
                "disk_pct": disk_pct,
                "load_1min": resources["load_avg"].get("1min", -1),
            },
        }

    # ── Auto-backup on startup ────────────────────────────────────────
    try:
        _create_backup("auto-startup")
        _cleanup_backups(10)
        _record_resource_snapshot()  # Record initial resource state
    except Exception:
        pass

    # ── AI prediction endpoints ───────────────────────────────────────

    @app.get("/resilience/ai-predictions")
    async def resilience_ai_predictions(_u=Depends(require_admin)):
        """AI-powered capacity predictions and failure pattern detection."""
        _record_resource_snapshot()
        capacity = _predict_capacity()
        patterns = _failure_patterns()

        # Generate AI summary
        parts = []
        if capacity["status"] == "ok":
            for label, pred in capacity["predictions"].items():
                if pred.get("hours_to_threshold") is not None and pred["hours_to_threshold"] < 24:
                    parts.append(f"⚠ {label} raggiungerà soglia critica in ~{pred['hours_to_threshold']:.0f}h.")
                if pred.get("is_anomaly"):
                    parts.append(f"🔴 {label} anomalo ({pred['current']}%, media {pred['mean']}%).")
                if pred["trend"] == "rising" and pred.get("slope_per_hour", 0) > 0.5:
                    parts.append(f"📈 {label} in crescita ({pred['slope_per_hour']:.1f}%/h).")
        if patterns:
            parts.append(f"🧠 {len(patterns)} pattern di failure rilevati.")
        if not parts:
            parts.append("✅ Risorse stabili, nessuna anomalia rilevata.")

        return {
            "capacity": capacity,
            "failure_patterns": patterns,
            "summary": " ".join(parts),
            "analyzed_at": int(time.time()),
        }

    @app.get("/resilience/resource-history")
    async def resilience_resource_history(
        limit: int = 100, _u=Depends(require_admin)
    ):
        """Resource usage history for trend visualization."""
        _record_resource_snapshot()
        history = _read_resource_history(min(limit, 1000))
        return {
            "history": history,
            "count": len(history),
            "collected_at": int(time.time()),
        }
