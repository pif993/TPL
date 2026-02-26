"""
TPL System Monitoring AI Engine — v2.0.0
Monitoraggio risorse con time-series, capacity forecasting,
rilevamento anomalie, health scoring e alerting intelligente.
"""

import json, os, time, math, threading
from collections import defaultdict
from fastapi import FastAPI, Depends, Query


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    root = ctx["root"]

    METRICS_FILE = os.path.join(root, ".tpl_monitoring_metrics.json")
    HISTORY_FILE = os.path.join(root, ".tpl_monitoring_history.jsonl")
    MAX_HISTORY = 4320  # ~3 days at 1-min intervals

    _lock = threading.Lock()

    # ── Metric collection ──────────────────────────────────────────────

    def _cpu_info() -> dict:
        try:
            with open("/proc/stat", "r") as f:
                line = f.readline()
            parts = line.split()
            if len(parts) >= 8:
                user, nice, system, idle, iowait = (
                    int(parts[1]), int(parts[2]), int(parts[3]),
                    int(parts[4]), int(parts[5]) if len(parts) > 5 else 0,
                )
                total = user + nice + system + idle + iowait
                usage = round((1 - idle / max(total, 1)) * 100, 1)
                return {
                    "usage_pct": usage, "user_pct": round(user / max(total, 1) * 100, 1),
                    "system_pct": round(system / max(total, 1) * 100, 1),
                    "iowait_pct": round(iowait / max(total, 1) * 100, 1),
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
                    val = int(parts[1].strip().split()[0]) * 1024
                    info[key] = val
            total = info.get("MemTotal", 0)
            available = info.get("MemAvailable", 0)
            buffers = info.get("Buffers", 0)
            cached = info.get("Cached", 0)
            used = total - available
            return {
                "total_bytes": total, "used_bytes": used,
                "available_bytes": available, "buffers_bytes": buffers,
                "cached_bytes": cached,
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
            avail = st.f_bavail * st.f_frsize
            used = total - free
            inodes_total = st.f_files
            inodes_free = st.f_ffree
            return {
                "total_bytes": total, "used_bytes": used, "free_bytes": free,
                "available_bytes": avail,
                "usage_pct": round(used / max(total, 1) * 100, 1),
                "inodes_total": inodes_total, "inodes_free": inodes_free,
                "inodes_usage_pct": round((inodes_total - inodes_free) / max(inodes_total, 1) * 100, 1),
                "path": root,
            }
        except Exception:
            return {"total_bytes": 0, "used_bytes": 0, "usage_pct": -1}

    def _load_avg() -> dict:
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
            return {"1min": float(parts[0]), "5min": float(parts[1]), "15min": float(parts[2])}
        except Exception:
            return {"1min": -1, "5min": -1, "15min": -1}

    def _process_count() -> int:
        try:
            return len([d for d in os.listdir("/proc") if d.isdigit()])
        except Exception:
            return -1

    def _uptime() -> float:
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.read().split()[0])
        except Exception:
            return -1

    def _network_stats() -> dict:
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()[2:]
            total_rx = total_tx = 0
            interfaces = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    total_rx += rx_bytes
                    total_tx += tx_bytes
                    interfaces[iface] = {"rx_bytes": rx_bytes, "tx_bytes": tx_bytes}
            return {"total_rx_bytes": total_rx, "total_tx_bytes": total_tx, "interfaces": interfaces}
        except Exception:
            return {"total_rx_bytes": 0, "total_tx_bytes": 0, "interfaces": {}}

    def _collect_snapshot() -> dict:
        return {
            "ts": int(time.time()),
            "cpu": _cpu_info(),
            "memory": _memory_info(),
            "disk": _disk_info(),
            "load": _load_avg(),
            "processes": _process_count(),
            "uptime_seconds": _uptime(),
            "network": _network_stats(),
        }

    # ── History persistence ────────────────────────────────────────────

    def _append_history(snapshot: dict):
        compact = {
            "ts": snapshot["ts"],
            "cpu": snapshot["cpu"].get("usage_pct", -1),
            "mem": snapshot["memory"].get("usage_pct", -1),
            "disk": snapshot["disk"].get("usage_pct", -1),
            "load1": snapshot["load"].get("1min", -1),
            "procs": snapshot["processes"],
            "swap": snapshot["memory"].get("swap_used", 0),
            "iowait": snapshot["cpu"].get("iowait_pct", 0),
        }
        with _lock:
            try:
                with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(compact, separators=(",", ":")) + "\n")
            except Exception:
                pass
            # Trim history
            _trim_history()

    def _trim_history():
        if not os.path.isfile(HISTORY_FILE):
            return
        try:
            size = os.path.getsize(HISTORY_FILE)
            if size > 2_000_000:  # >2MB → keep last MAX_HISTORY
                with open(HISTORY_FILE, "r") as f:
                    lines = f.readlines()
                if len(lines) > MAX_HISTORY:
                    with open(HISTORY_FILE, "w") as f:
                        f.writelines(lines[-MAX_HISTORY:])
        except Exception:
            pass

    def _read_history(limit: int = 500) -> list:
        if not os.path.isfile(HISTORY_FILE):
            return []
        entries = []
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
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

    # ── Statistical helpers ────────────────────────────────────────────

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
        return (slope, intercept, r2)

    # ── Capacity forecasting ──────────────────────────────────────────

    def _capacity_forecast(history: list, metric: str, threshold: float = 90) -> dict:
        """Predict when a resource metric will cross threshold."""
        values = [(i, h.get(metric, -1)) for i, h in enumerate(history) if h.get(metric, -1) >= 0]
        if len(values) < 10:
            return {"metric": metric, "forecast": "insufficient_data"}

        slope, intercept, r2 = _linear_regression(values)

        if slope <= 0:
            return {
                "metric": metric, "forecast": "stable_or_decreasing",
                "current": round(values[-1][1], 1), "slope": round(slope, 4), "r_squared": round(r2, 3),
            }

        current = values[-1][1]
        if current >= threshold:
            return {
                "metric": metric, "forecast": "already_exceeded",
                "current": round(current, 1), "threshold": threshold,
            }

        # Points until threshold
        points_to_threshold = (threshold - current) / slope if slope > 0 else float("inf")
        # Estimate interval between points (minutes)
        if len(history) >= 2:
            ts_diff = history[-1].get("ts", 0) - history[0].get("ts", 0)
            interval_min = ts_diff / max(len(history) - 1, 1) / 60
        else:
            interval_min = 1

        hours_to_threshold = points_to_threshold * interval_min / 60

        confidence = "high" if r2 > 0.7 else "medium" if r2 > 0.3 else "low"

        return {
            "metric": metric, "forecast": "computed",
            "current": round(current, 1), "threshold": threshold,
            "hours_to_threshold": round(hours_to_threshold, 1),
            "slope_per_point": round(slope, 4), "r_squared": round(r2, 3),
            "confidence": confidence,
            "estimated_at_1h": round(min(100, current + slope * (60 / max(interval_min, 0.1))), 1),
            "estimated_at_6h": round(min(100, current + slope * (360 / max(interval_min, 0.1))), 1),
            "estimated_at_24h": round(min(100, current + slope * (1440 / max(interval_min, 0.1))), 1),
        }

    # ── Anomaly detection on metrics ───────────────────────────────────

    def _detect_metric_anomalies(history: list, metric: str) -> dict:
        values = [h.get(metric, -1) for h in history if h.get(metric, -1) >= 0]
        if len(values) < 10:
            return {"metric": metric, "anomalies": [], "status": "insufficient_data"}

        mean = _mean(values)
        std = _stddev(values)
        anomalies = []

        for i, v in enumerate(values):
            z = (v - mean) / std if std > 0 else 0
            if abs(z) > 2.5:
                ts = history[i].get("ts", 0) if i < len(history) else 0
                anomalies.append({
                    "index": i, "ts": ts, "value": round(v, 1),
                    "z_score": round(z, 2),
                    "type": "high" if z > 0 else "low",
                })

        return {
            "metric": metric, "anomalies": anomalies[-20:],
            "mean": round(mean, 2), "stddev": round(std, 2),
            "min": round(min(values), 1), "max": round(max(values), 1),
            "current": round(values[-1], 1),
        }

    # ── Health scoring ─────────────────────────────────────────────────

    def _compute_health_score(snapshot: dict) -> dict:
        score = 100
        issues = []

        # CPU
        cpu_pct = snapshot["cpu"].get("usage_pct", 0)
        if cpu_pct > 90:
            score -= 25
            issues.append({"severity": "critical", "type": "cpu_critical", "message": f"CPU al {cpu_pct}%"})
        elif cpu_pct > 75:
            score -= 10
            issues.append({"severity": "high", "type": "cpu_high", "message": f"CPU al {cpu_pct}%"})
        elif cpu_pct > 60:
            score -= 3
            issues.append({"severity": "medium", "type": "cpu_elevated", "message": f"CPU al {cpu_pct}%"})

        # Memory
        mem_pct = snapshot["memory"].get("usage_pct", 0)
        if mem_pct > 90:
            score -= 25
            issues.append({"severity": "critical", "type": "memory_critical", "message": f"Memoria al {mem_pct}%"})
        elif mem_pct > 80:
            score -= 12
            issues.append({"severity": "high", "type": "memory_high", "message": f"Memoria al {mem_pct}%"})
        elif mem_pct > 70:
            score -= 5
            issues.append({"severity": "medium", "type": "memory_elevated", "message": f"Memoria al {mem_pct}%"})

        # Disk
        disk_pct = snapshot["disk"].get("usage_pct", 0)
        if disk_pct > 90:
            score -= 25
            issues.append({"severity": "critical", "type": "disk_critical", "message": f"Disco al {disk_pct}%"})
        elif disk_pct > 80:
            score -= 10
            issues.append({"severity": "high", "type": "disk_high", "message": f"Disco al {disk_pct}%"})

        # Load average
        cores = snapshot["cpu"].get("cores", 1)
        load1 = snapshot["load"].get("1min", 0)
        if load1 > cores * 3:
            score -= 15
            issues.append({"severity": "critical", "type": "load_critical", "message": f"Load avg {load1} (cores: {cores})"})
        elif load1 > cores * 1.5:
            score -= 5
            issues.append({"severity": "medium", "type": "load_high", "message": f"Load avg {load1} (cores: {cores})"})

        # IO Wait
        iowait = snapshot["cpu"].get("iowait_pct", 0)
        if iowait > 20:
            score -= 10
            issues.append({"severity": "high", "type": "iowait_high", "message": f"IO Wait al {iowait}%"})

        # Swap
        swap_used = snapshot["memory"].get("swap_used", 0)
        swap_total = snapshot["memory"].get("swap_total", 0)
        if swap_total > 0 and swap_used / swap_total > 0.5:
            score -= 8
            pct = round(swap_used / swap_total * 100, 1)
            issues.append({"severity": "medium", "type": "swap_usage", "message": f"Swap al {pct}%"})

        # Inode usage
        inode_pct = snapshot["disk"].get("inodes_usage_pct", 0)
        if inode_pct > 80:
            score -= 10
            issues.append({"severity": "high", "type": "inodes_high", "message": f"Inode usage al {inode_pct}%"})

        score = max(0, min(100, score))
        grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

        return {
            "score": score, "grade": grade, "issues": issues,
            "status": "healthy" if score >= 70 else "degraded" if score >= 40 else "critical",
        }

    # ── Predictive issues ──────────────────────────────────────────────

    def _predict_issues(history: list, snapshot: dict) -> list:
        issues = []

        # Capacity forecasts
        for metric, label in [("cpu", "CPU"), ("mem", "Memoria"), ("disk", "Disco")]:
            fc = _capacity_forecast(history, metric, 90)
            if fc.get("forecast") == "computed" and fc.get("hours_to_threshold", 999) < 24:
                issues.append({
                    "severity": "high" if fc["hours_to_threshold"] < 6 else "medium",
                    "type": f"{metric}_capacity_warning",
                    "message": f"{label} raggiungerà il 90% in ~{fc['hours_to_threshold']:.0f}h",
                    "forecast": fc,
                })
            elif fc.get("forecast") == "already_exceeded":
                issues.append({
                    "severity": "critical", "type": f"{metric}_exceeded",
                    "message": f"{label} già sopra la soglia ({fc['current']}%)",
                })

        # Log file growth
        log_files = {
            "audit": os.path.join(root, ".tpl_audit.jsonl"),
            "events": os.path.join(root, ".tpl_events.jsonl"),
            "security": os.path.join(root, ".tpl_security.jsonl"),
        }
        for name, path in log_files.items():
            if os.path.isfile(path):
                size = os.path.getsize(path)
                if size > 50_000_000:
                    issues.append({
                        "severity": "high", "type": "log_size_critical",
                        "message": f"Log {name} supera 50MB ({size // 1_000_000}MB)",
                    })
                elif size > 10_000_000:
                    issues.append({
                        "severity": "medium", "type": "log_size_warning",
                        "message": f"Log {name} supera 10MB ({size // 1_000_000}MB)",
                    })

        # State file check
        state_file = os.path.join(root, ".tpl_state.json")
        if os.path.isfile(state_file):
            try:
                with open(state_file, "r") as f:
                    json.load(f)
            except Exception:
                issues.append({
                    "severity": "critical", "type": "state_corrupted",
                    "message": "File di stato .tpl_state.json corrotto",
                })

        return issues

    # ── Service dependency mapping ─────────────────────────────────────

    def _service_map() -> dict:
        """Map of platform services and dependencies."""
        engines_dir = ctx.get("engines_dir", "")
        engines = []
        if engines_dir and os.path.isdir(engines_dir):
            engines = sorted(f.replace("_engine.py", "") for f in os.listdir(engines_dir)
                           if f.endswith("_engine.py") and not f.startswith("__"))

        return {
            "core": {
                "api": {"status": "running", "depends_on": ["traefik"], "type": "service"},
                "web": {"status": "running", "depends_on": ["traefik"], "type": "service"},
                "traefik": {"status": "running", "depends_on": [], "type": "proxy"},
            },
            "engines": {name: {"status": "loaded", "type": "engine"} for name in engines},
            "total_engines": len(engines),
        }

    # ── Generate monitoring summary ────────────────────────────────────

    def _monitoring_summary(snapshot: dict, health: dict, predictions: list) -> str:
        parts = []
        sc = health["score"]
        if sc >= 85:
            parts.append(f"✅ Sistema sano (score: {sc}/100).")
        elif sc >= 70:
            parts.append(f"📊 Sistema operativo con lievi avvertimenti (score: {sc}/100).")
        elif sc >= 40:
            parts.append(f"⚡ Sistema degradato (score: {sc}/100) — attenzione richiesta.")
        else:
            parts.append(f"⚠ CRITICO (score: {sc}/100) — intervento immediato.")

        cpu = snapshot["cpu"].get("usage_pct", -1)
        mem = snapshot["memory"].get("usage_pct", -1)
        disk = snapshot["disk"].get("usage_pct", -1)
        parts.append(f"CPU: {cpu}% | Memoria: {mem}% | Disco: {disk}%.")

        crit = [p for p in predictions if p["severity"] == "critical"]
        high = [p for p in predictions if p["severity"] == "high"]
        if crit:
            parts.append(f"🔴 {len(crit)} problemi critici previsti.")
        if high:
            parts.append(f"🟠 {len(high)} problemi da monitorare.")

        return " ".join(parts)

    # ── Endpoints ──────────────────────────────────────────────────────

    @app.get("/monitoring/health")
    async def system_health(_u=Depends(require_admin)):
        """Comprehensive system health with scoring."""
        snapshot = _collect_snapshot()
        health = _compute_health_score(snapshot)
        _append_history(snapshot)
        return {**health, "snapshot": snapshot}

    @app.get("/monitoring/predictions")
    async def predict_problems(
        limit: int = Query(500, ge=50, le=4000),
        _u=Depends(require_admin),
    ):
        """AI-powered predictive issue detection."""
        snapshot = _collect_snapshot()
        history = _read_history(limit)
        predictions = _predict_issues(history, snapshot)
        health = _compute_health_score(snapshot)

        actions = []
        for p in predictions:
            if "log_size" in p.get("type", ""):
                actions.append("Ruotare/archiviare i log")
            elif "capacity" in p.get("type", ""):
                actions.append(f"Verificare risorse: {p['type'].split('_')[0]}")
            elif "corrupted" in p.get("type", ""):
                actions.append("Verificare integrità file di stato")

        return {
            "predictions": predictions,
            "overall_status": health["status"],
            "health_score": health["score"],
            "recommended_actions": list(set(actions)),
            "summary": _monitoring_summary(snapshot, health, predictions),
        }

    @app.get("/monitoring/resources")
    async def monitor_resources(_u=Depends(require_admin)):
        """Real-time system resources with extended metrics."""
        snapshot = _collect_snapshot()
        _append_history(snapshot)
        return snapshot

    @app.get("/monitoring/history")
    async def monitor_history(
        limit: int = Query(200, ge=10, le=4000),
        metric: str = Query("all"),
        _u=Depends(require_admin),
    ):
        """Historical resource metrics."""
        history = _read_history(limit)
        if metric != "all" and metric in ("cpu", "mem", "disk", "load1", "procs", "swap", "iowait"):
            return {
                "metric": metric, "count": len(history),
                "data": [{"ts": h.get("ts", 0), "value": h.get(metric, -1)} for h in history],
            }
        return {"count": len(history), "data": history}

    @app.get("/monitoring/capacity")
    async def capacity_forecast_ep(
        limit: int = Query(500, ge=50, le=4000),
        _u=Depends(require_admin),
    ):
        """Capacity forecasting for CPU, memory, disk."""
        history = _read_history(limit)
        return {
            "cpu": _capacity_forecast(history, "cpu", 90),
            "memory": _capacity_forecast(history, "mem", 90),
            "disk": _capacity_forecast(history, "disk", 90),
            "data_points": len(history),
        }

    @app.get("/monitoring/anomalies")
    async def detect_metric_anomalies(
        metric: str = Query("cpu"),
        limit: int = Query(500, ge=50, le=4000),
        _u=Depends(require_admin),
    ):
        """Anomaly detection on resource metrics."""
        history = _read_history(limit)
        return _detect_metric_anomalies(history, metric)

    @app.get("/monitoring/services")
    async def service_map(_u=Depends(require_admin)):
        """Service dependency map."""
        return _service_map()

    @app.get("/monitoring/summary")
    async def monitoring_summary_ep(
        limit: int = Query(300, ge=50, le=2000),
        _u=Depends(require_admin),
    ):
        """AI-generated monitoring summary."""
        snapshot = _collect_snapshot()
        health = _compute_health_score(snapshot)
        history = _read_history(limit)
        predictions = _predict_issues(history, snapshot)
        return {
            "summary": _monitoring_summary(snapshot, health, predictions),
            "health_score": health["score"],
            "health_grade": health["grade"],
            "status": health["status"],
            "predictions_count": len(predictions),
            "critical_count": sum(1 for p in predictions if p["severity"] == "critical"),
        }

    # Record initial snapshot on startup
    try:
        _append_history(_collect_snapshot())
    except Exception:
        pass
