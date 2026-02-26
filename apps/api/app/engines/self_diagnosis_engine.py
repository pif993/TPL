"""
TPL Self-Diagnosis Engine — v2.0.0
Correlazione cross-log con AI, root cause analysis statistica,
verifica salute engines, drift configurazione, remediation automatica,
metriche unificate, anomaly scoring, pattern recognition, raccomandazioni
operative con confidence rating.
"""

import json, os, time, re, hashlib, math, threading
from collections import Counter, defaultdict
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx["root"]

    LOG_FILES = {
        "audit":    os.path.join(root, ".tpl_audit.jsonl"),
        "events":   os.path.join(root, ".tpl_events.jsonl"),
        "comm":     os.path.join(root, ".tpl_comm.jsonl"),
        "security": os.path.join(root, ".tpl_security.jsonl"),
    }
    DIAG_HISTORY_FILE = os.path.join(root, ".tpl_diagnosis.jsonl")
    CONFIG_BASELINE_FILE = os.path.join(root, ".tpl_config_baseline.json")
    ENGINES_DIR = ctx.get("engines_dir", os.path.join(root, "apps", "api", "app", "engines"))
    MODULES_DIR = ctx.get("modules_dir", os.path.join(root, "modules"))

    # ── Unified log reader ────────────────────────────────────────────

    def _read_log(filepath: str, limit: int = 500) -> list:
        if not os.path.isfile(filepath):
            return []
        entries = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            pass
        return entries[-limit:]

    def _read_all_logs(limit: int = 300) -> dict:
        return {name: _read_log(path, limit) for name, path in LOG_FILES.items()}

    def _append_diag(entry: dict):
        row = {"ts": int(time.time()), **entry}
        with open(DIAG_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    # ── Statistical helpers ───────────────────────────────────────────

    def _mean(vals: list) -> float:
        return sum(vals) / len(vals) if vals else 0

    def _stddev(vals: list) -> float:
        if len(vals) < 2:
            return 0
        m = _mean(vals)
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))

    def _zscore(val: float, vals: list) -> float:
        s = _stddev(vals)
        return (val - _mean(vals)) / s if s > 0 else 0

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

    def _entropy(counts: dict) -> float:
        """Shannon entropy - higher = more diverse."""
        total = sum(counts.values())
        if total == 0:
            return 0
        probs = [c / total for c in counts.values() if c > 0]
        return -sum(p * math.log2(p) for p in probs)

    def _ts(entry: dict) -> int:
        ts = entry.get("ts", entry.get("timestamp", 0))
        if isinstance(ts, str):
            try:
                return int(datetime.fromisoformat(ts).timestamp())
            except Exception:
                return 0
        return int(ts) if ts else 0

    # ── AI-enhanced pattern recognition ───────────────────────────────

    def _detect_event_patterns(logs: dict) -> list:
        """AI pattern recognition across log sources."""
        patterns = []

        for source, entries in logs.items():
            if len(entries) < 5:
                continue

            # 1. Temporal clustering - detect bursts
            timestamps = sorted([_ts(e) for e in entries if _ts(e) > 0])
            if len(timestamps) >= 5:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                avg_interval = _mean(intervals)
                std_interval = _stddev(intervals)

                # Find burst windows (intervals much shorter than normal)
                for i, iv in enumerate(intervals):
                    if std_interval > 0 and iv < avg_interval - 2 * std_interval and iv > 0:
                        patterns.append({
                            "type": "temporal_burst",
                            "source": source,
                            "confidence": min(0.99, 0.5 + abs(_zscore(iv, intervals)) * 0.1),
                            "detail": f"Burst rilevato: intervallo {iv}s vs media {avg_interval:.0f}s",
                        })
                        break  # One burst per source is enough

            # 2. Event type distribution anomaly
            types = Counter(e.get("event", e.get("action", e.get("type", "?"))) for e in entries)
            entropy = _entropy(types)
            if len(types) >= 3:
                # Low entropy = dominated by one type (potentially repetitive attack)
                max_type, max_count = types.most_common(1)[0]
                dominance = max_count / len(entries)
                if dominance > 0.7 and len(entries) > 10:
                    patterns.append({
                        "type": "dominant_event",
                        "source": source,
                        "event": max_type,
                        "dominance": round(dominance, 2),
                        "entropy": round(entropy, 3),
                        "confidence": round(min(0.95, dominance), 2),
                        "detail": f"Evento '{max_type}' domina {source} ({dominance:.0%})",
                    })

            # 3. Rate acceleration
            if len(timestamps) >= 10:
                mid = len(timestamps) // 2
                first_half_rate = mid / max(timestamps[mid] - timestamps[0], 1) * 3600
                second_half_rate = (len(timestamps) - mid) / max(timestamps[-1] - timestamps[mid], 1) * 3600
                if first_half_rate > 0:
                    acceleration = (second_half_rate - first_half_rate) / first_half_rate
                    if acceleration > 0.5:
                        patterns.append({
                            "type": "rate_acceleration",
                            "source": source,
                            "first_half_rate": round(first_half_rate, 1),
                            "second_half_rate": round(second_half_rate, 1),
                            "acceleration_pct": round(acceleration * 100, 0),
                            "confidence": round(min(0.9, 0.4 + acceleration * 0.2), 2),
                            "detail": f"{source}: tasso eventi in aumento del {acceleration:.0%}",
                        })

        return patterns

    def _compute_diagnosis_score(causes: list, recs: list, drift: dict,
                                 engines: list, patterns: list) -> dict:
        """AI-computed diagnosis score with breakdown."""
        score = 100
        breakdown = {}

        # Root causes (-5 to -20 each, max -40)
        cause_penalty = 0
        for c in causes:
            sev = c.get("severity", "low")
            cause_penalty += {"critical": 20, "high": 10, "medium": 5, "warning": 2, "low": 1}.get(sev, 1)
        cause_penalty = min(40, cause_penalty)
        score -= cause_penalty
        breakdown["root_causes"] = {"penalty": cause_penalty, "count": len(causes)}

        # Recommendations (-3 to -15 each, max -25)
        rec_penalty = 0
        for r in recs:
            prio = r.get("priority", "low")
            rec_penalty += {"critical": 15, "high": 8, "medium": 3, "low": 1}.get(prio, 1)
        rec_penalty = min(25, rec_penalty)
        score -= rec_penalty
        breakdown["recommendations"] = {"penalty": rec_penalty, "count": len(recs)}

        # Config drift (-1 to -15)
        drift_count = drift.get("drift_count", 0)
        drift_penalty = min(15, drift_count * 3)
        score -= drift_penalty
        breakdown["config_drift"] = {"penalty": drift_penalty, "drifts": drift_count}

        # Engine health (-15 per broken engine, max -30)
        bad_engines = sum(1 for e in engines if e["status"] != "ok")
        eng_penalty = min(30, bad_engines * 15)
        score -= eng_penalty
        breakdown["engines"] = {"penalty": eng_penalty, "broken": bad_engines, "total": len(engines)}

        # AI patterns (-2 to -10 each, max -20)
        pattern_penalty = 0
        for p in patterns:
            conf = p.get("confidence", 0.5)
            pattern_penalty += int(conf * 10)
        pattern_penalty = min(20, pattern_penalty)
        score -= pattern_penalty
        breakdown["ai_patterns"] = {"penalty": pattern_penalty, "count": len(patterns)}

        score = max(0, min(100, score))
        grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

        return {"score": score, "grade": grade, "breakdown": breakdown}

    # ── Cross-log correlation ─────────────────────────────────────────

    def _correlate_events(logs: dict, window: int = 60) -> list:
        """Find events across multiple logs that happened within the same
        time window, suggesting causal relationships."""
        all_events = []
        for source, entries in logs.items():
            for e in entries:
                ts = e.get("ts", e.get("timestamp", 0))
                if isinstance(ts, str):
                    try:
                        ts = int(datetime.fromisoformat(ts).timestamp())
                    except Exception:
                        ts = 0
                all_events.append({
                    "source": source,
                    "ts": ts,
                    "event": e.get("event", e.get("action", e.get("type", "?"))),
                    "level": e.get("level", e.get("severity", e.get("outcome", "info"))),
                    "detail": _extract_detail(e),
                })

        # Sort by timestamp
        all_events.sort(key=lambda x: x["ts"])

        # Group into correlation windows
        correlations = []
        i = 0
        while i < len(all_events):
            group = [all_events[i]]
            j = i + 1
            while j < len(all_events) and all_events[j]["ts"] - all_events[i]["ts"] <= window:
                if all_events[j]["source"] != all_events[i]["source"]:
                    group.append(all_events[j])
                j += 1
            if len(group) >= 2:
                sources = set(e["source"] for e in group)
                if len(sources) >= 2:
                    correlations.append({
                        "window_start": group[0]["ts"],
                        "window_end": group[-1]["ts"],
                        "sources": list(sources),
                        "events": group,
                        "event_count": len(group),
                    })
            i = j if j > i + 1 else i + 1

        return correlations[-50:]  # last 50 correlations

    def _extract_detail(entry: dict) -> str:
        for key in ["message", "msg", "detail", "desc", "description", "error"]:
            if key in entry and entry[key]:
                return str(entry[key])[:120]
        return ""

    # ── Root cause analysis ───────────────────────────────────────────

    def _analyze_root_causes(logs: dict) -> list:
        """Pattern-based root cause analysis across all log sources."""
        causes = []

        # 1. Auth failure cascades
        auth_events = logs.get("audit", [])
        auth_failures = [
            e for e in auth_events
            if e.get("outcome") == "failed" and "auth" in e.get("action", "")
        ]
        if len(auth_failures) >= 5:
            ips = Counter(e.get("ip", "?") for e in auth_failures[-20:])
            top_ip = ips.most_common(1)[0] if ips else ("?", 0)
            causes.append({
                "type": "auth_cascade",
                "severity": "high" if len(auth_failures) >= 15 else "medium",
                "description": f"{len(auth_failures)} login failures detected",
                "detail": f"Top offending IP: {top_ip[0]} ({top_ip[1]} attempts)",
                "recommendation": "Verify if brute-force protection is active. Consider IP block.",
                "remediation": "block_ip" if len(auth_failures) >= 15 else None,
                "evidence_count": len(auth_failures),
            })

        # 2. Security event spikes
        sec_events = logs.get("security", [])
        if len(sec_events) >= 10:
            recent = sec_events[-50:]
            types = Counter(e.get("type", "?") for e in recent)
            for evt_type, count in types.most_common(3):
                if count >= 5:
                    causes.append({
                        "type": "security_spike",
                        "severity": "high" if count >= 15 else "medium",
                        "description": f"Alert spike: {evt_type} ({count} events)",
                        "detail": f"Cluster of {count} '{evt_type}' alerts in recent window",
                        "recommendation": "Check WAF rules and IP block policy",
                        "remediation": None,
                        "evidence_count": count,
                    })

        # 3. Event log error concentration
        events = logs.get("events", [])
        error_events = [e for e in events if e.get("level") in ("error", "critical")]
        if len(error_events) >= 5:
            sources = Counter(e.get("source", "?") for e in error_events[-30:])
            top_source = sources.most_common(1)[0] if sources else ("?", 0)
            causes.append({
                "type": "error_concentration",
                "severity": "medium",
                "description": f"Error cluster in source: {top_source[0]}",
                "detail": f"{top_source[1]} errors from {top_source[0]}",
                "recommendation": f"Investigate {top_source[0]} module for systematic issues",
                "remediation": None,
                "evidence_count": len(error_events),
            })

        # 4. Communication failures
        comm_events = logs.get("comm", [])
        comm_errors = [e for e in comm_events if e.get("status") == "error"]
        if len(comm_errors) >= 3:
            causes.append({
                "type": "comm_failure",
                "severity": "medium",
                "description": f"Inter-module communication failures: {len(comm_errors)}",
                "detail": "Communication engine reporting delivery errors",
                "recommendation": "Check target modules are loaded and responding",
                "remediation": None,
                "evidence_count": len(comm_errors),
            })

        # 5. Log file size warnings
        for name, path in LOG_FILES.items():
            if os.path.isfile(path):
                size = os.path.getsize(path)
                if size > 10_000_000:  # 10MB
                    causes.append({
                        "type": "log_growth",
                        "severity": "warning",
                        "description": f"Log file {name} is large: {size // 1_000_000}MB",
                        "detail": f"{path} needs rotation",
                        "recommendation": "Configure log rotation or archive old entries",
                        "remediation": "rotate_logs",
                        "evidence_count": 1,
                    })

        return causes

    # ── Engine health verification ────────────────────────────────────

    def _verify_engines() -> list:
        """Check that all engine files parse correctly and have register()."""
        results = []
        if not os.path.isdir(ENGINES_DIR):
            return results

        for f in sorted(os.listdir(ENGINES_DIR)):
            if not f.endswith("_engine.py") or f.startswith("__"):
                continue
            full = os.path.join(ENGINES_DIR, f)
            name = f.replace("_engine.py", "")
            try:
                with open(full, "r", encoding="utf-8") as fp:
                    source = fp.read()
                # Syntax check
                compile(source, f, "exec")
                has_register = "def register(" in source
                lines = source.count("\n") + 1
                results.append({
                    "engine": name,
                    "file": f,
                    "status": "ok" if has_register else "missing_register",
                    "lines": lines,
                    "has_register": has_register,
                    "size_bytes": len(source),
                })
            except SyntaxError as e:
                results.append({
                    "engine": name,
                    "file": f,
                    "status": "syntax_error",
                    "error": str(e),
                    "has_register": False,
                })
            except Exception as e:
                results.append({
                    "engine": name,
                    "file": f,
                    "status": "error",
                    "error": str(e),
                    "has_register": False,
                })
        return results

    # ── Configuration drift detection ─────────────────────────────────

    def _build_config_snapshot() -> dict:
        """Build a snapshot of current configuration state."""
        snapshot = {
            "engines": {},
            "modules": {},
            "compose_files": [],
            "env": {},
        }

        # Engine file hashes
        if os.path.isdir(ENGINES_DIR):
            for f in sorted(os.listdir(ENGINES_DIR)):
                if f.endswith(".py"):
                    full = os.path.join(ENGINES_DIR, f)
                    h = hashlib.sha256()
                    with open(full, "rb") as fp:
                        for chunk in iter(lambda: fp.read(8192), b""):
                            h.update(chunk)
                    snapshot["engines"][f] = {
                        "hash": h.hexdigest(),
                        "size": os.path.getsize(full),
                    }

        # Module file hashes
        if os.path.isdir(MODULES_DIR):
            for f in sorted(os.listdir(MODULES_DIR)):
                if f.endswith(".sh"):
                    full = os.path.join(MODULES_DIR, f)
                    h = hashlib.sha256()
                    with open(full, "rb") as fp:
                        for chunk in iter(lambda: fp.read(8192), b""):
                            h.update(chunk)
                    snapshot["modules"][f] = {
                        "hash": h.hexdigest(),
                        "size": os.path.getsize(full),
                    }

        # Compose files
        compose_dir = os.path.join(root, "compose.d")
        if os.path.isdir(compose_dir):
            snapshot["compose_files"] = sorted(os.listdir(compose_dir))

        # Env vars that matter
        for var in [
            "AUTH_MODE",
            "API_SECRET",
            "PORT",
            "CORS_ORIGINS",
            "ENABLE_TRAEFIK",
        ]:
            val = os.environ.get(var, "")
            # Don't store actual secret values, just whether they're set and non-default
            if var == "API_SECRET":
                # Use secret_loader for validation — never check raw env
                try:
                    from ..secret_loader import get_secret
                    get_secret("API_SECRET")
                    snapshot["env"][var] = "configured_secure"
                except Exception:
                    snapshot["env"][var] = "DEFAULT_INSECURE"
            else:
                snapshot["env"][var] = val or "(unset)"

        snapshot["timestamp"] = int(time.time())
        return snapshot

    def _detect_drift() -> dict:
        """Compare current config against saved baseline."""
        current = _build_config_snapshot()

        if not os.path.isfile(CONFIG_BASELINE_FILE):
            # First run: save baseline
            with open(CONFIG_BASELINE_FILE, "w") as f:
                json.dump(current, f, indent=2)
            return {"status": "baseline_created", "drifts": []}

        try:
            with open(CONFIG_BASELINE_FILE, "r") as f:
                baseline = json.load(f)
        except Exception:
            return {"status": "baseline_corrupt", "drifts": []}

        drifts = []

        # Engine changes
        for eng, info in current["engines"].items():
            if eng not in baseline.get("engines", {}):
                drifts.append({"type": "engine_added", "file": eng})
            elif info["hash"] != baseline["engines"][eng].get("hash"):
                drifts.append({"type": "engine_modified", "file": eng})
        for eng in baseline.get("engines", {}):
            if eng not in current["engines"]:
                drifts.append({"type": "engine_removed", "file": eng})

        # Module changes
        for mod, info in current["modules"].items():
            if mod not in baseline.get("modules", {}):
                drifts.append({"type": "module_added", "file": mod})
            elif info["hash"] != baseline["modules"][mod].get("hash"):
                drifts.append({"type": "module_modified", "file": mod})
        for mod in baseline.get("modules", {}):
            if mod not in current["modules"]:
                drifts.append({"type": "module_removed", "file": mod})

        # Env changes
        for var, val in current["env"].items():
            base_val = baseline.get("env", {}).get(var, "(unset)")
            if val != base_val:
                drifts.append({
                    "type": "env_changed",
                    "var": var,
                    "from": base_val,
                    "to": val,
                })

        return {
            "status": "checked",
            "drifts": drifts,
            "drift_count": len(drifts),
            "baseline_age": int(time.time()) - baseline.get("timestamp", 0),
        }

    # ── Automated remediation ─────────────────────────────────────────

    def _execute_remediation(action: str) -> dict:
        """Execute a predefined remediation action."""
        if action == "rotate_logs":
            rotated = []
            for name, path in LOG_FILES.items():
                if os.path.isfile(path):
                    size = os.path.getsize(path)
                    if size > 5_000_000:  # 5MB threshold
                        archive = f"{path}.{int(time.time())}.bak"
                        os.rename(path, archive)
                        rotated.append(name)
            return {
                "action": "rotate_logs",
                "success": True,
                "rotated": rotated,
            }

        elif action == "rebuild_baseline":
            snapshot = _build_config_snapshot()
            with open(CONFIG_BASELINE_FILE, "w") as f:
                json.dump(snapshot, f, indent=2)
            return {
                "action": "rebuild_baseline",
                "success": True,
                "engines": len(snapshot["engines"]),
                "modules": len(snapshot["modules"]),
            }

        elif action == "cleanup_old_data":
            cleaned = []
            for name, path in LOG_FILES.items():
                if os.path.isfile(path):
                    lines = []
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            lines.append(line)
                    if len(lines) > 5000:
                        # Keep last 2000 lines
                        with open(path, "w", encoding="utf-8") as f:
                            f.writelines(lines[-2000:])
                        cleaned.append({
                            "file": name,
                            "before": len(lines),
                            "after": 2000,
                        })
            return {
                "action": "cleanup_old_data",
                "success": True,
                "cleaned": cleaned,
            }

        elif action == "verify_integrity":
            engines = _verify_engines()
            issues = [e for e in engines if e["status"] != "ok"]
            return {
                "action": "verify_integrity",
                "success": len(issues) == 0,
                "engines_checked": len(engines),
                "issues": issues,
            }

        else:
            return {"action": action, "success": False, "error": "Unknown action"}

    # ── Recommendations engine ────────────────────────────────────────

    def _generate_recommendations(logs: dict, engines: list) -> list:
        recs = []

        # Check API_SECRET
        try:
            from ..secret_loader import get_secret, is_vault_mode
            get_secret("API_SECRET")
        except Exception:
            recs.append({
                "priority": "critical",
                "category": "security",
                "title": "API Secret non configurato o debole",
                "description": "Configurare API_SECRET via Vault o .env con valore sicuro (almeno 32 caratteri random)",
                "action": None,
            })

        # Check CORS
        cors = os.environ.get("CORS_ORIGINS", "")
        if cors == "*" or not cors:
            recs.append({
                "priority": "high",
                "category": "security",
                "title": "CORS troppo permissivo",
                "description": "Configurare CORS_ORIGINS con i domini specifici ammessi",
                "action": None,
            })

        # Check backup status
        backup_dir = os.path.join(root, ".tpl_backups")
        if not os.path.isdir(backup_dir) or len(os.listdir(backup_dir)) == 0:
            recs.append({
                "priority": "high",
                "category": "resilience",
                "title": "Nessun backup disponibile",
                "description": "Creare un backup tramite /resilience/backup",
                "action": "create_backup",
            })

        # Check log sizes
        for name, path in LOG_FILES.items():
            if os.path.isfile(path) and os.path.getsize(path) > 10_000_000:
                recs.append({
                    "priority": "medium",
                    "category": "maintenance",
                    "title": f"Log {name} supera 10MB",
                    "description": "Eseguire rotazione log per risparmiare spazio disco",
                    "action": "rotate_logs",
                })

        # Check engine health
        bad_engines = [e for e in engines if e["status"] != "ok"]
        for eng in bad_engines:
            recs.append({
                "priority": "critical",
                "category": "stability",
                "title": f"Engine {eng['engine']} ha problemi",
                "description": f"Stato: {eng['status']} — {eng.get('error', '')}",
                "action": "verify_integrity",
            })

        # Check auth failures
        auth_events = logs.get("audit", [])
        recent_failures = [
            e for e in auth_events[-100:]
            if e.get("outcome") == "failed"
        ]
        if len(recent_failures) >= 10:
            recs.append({
                "priority": "high",
                "category": "security",
                "title": f"{len(recent_failures)} tentativi di login falliti recenti",
                "description": "Verificare che la protezione brute force sia attiva",
                "action": None,
            })

        # Generic maintenance
        state_file = os.path.join(root, ".tpl_state.json")
        if os.path.isfile(state_file):
            try:
                with open(state_file) as f:
                    state = json.load(f)
                installed = state.get("installed", {})
                if len(installed) < 10:
                    recs.append({
                        "priority": "low",
                        "category": "completeness",
                        "title": "Pochi moduli installati",
                        "description": f"Solo {len(installed)} moduli attivi. Considerare installazione completa.",
                        "action": None,
                    })
            except Exception:
                recs.append({
                    "priority": "high",
                    "category": "stability",
                    "title": "File di stato corrotto",
                    "description": ".tpl_state.json non è un JSON valido",
                    "action": "verify_integrity",
                })

        # Sort by priority
        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recs.sort(key=lambda r: prio_order.get(r["priority"], 99))

        return recs

    # ── Unified metrics aggregator ────────────────────────────────────

    def _aggregate_metrics() -> dict:
        """Collect metrics from all engines via app.state."""
        metrics = {}

        # Security metrics
        sec_alert = getattr(app.state, "security_engine_alert", None)
        sec_status = getattr(app.state, "security_engine_status", None)
        if callable(sec_status):
            try:
                metrics["security"] = sec_status()
            except Exception:
                metrics["security"] = {"error": "unavailable"}
        else:
            metrics["security"] = {"status": "engine_not_loaded"}

        # Log metrics
        events_file = LOG_FILES["events"]
        if os.path.isfile(events_file):
            try:
                count = sum(1 for _ in open(events_file, "r"))
                size = os.path.getsize(events_file)
                metrics["events"] = {"count": count, "size_bytes": size}
            except Exception:
                metrics["events"] = {"error": "unreadable"}

        # Audit metrics
        audit_file = LOG_FILES["audit"]
        if os.path.isfile(audit_file):
            try:
                count = sum(1 for _ in open(audit_file, "r"))
                size = os.path.getsize(audit_file)
                metrics["audit"] = {"count": count, "size_bytes": size}
            except Exception:
                metrics["audit"] = {"error": "unreadable"}

        # Engines loaded
        engine_files = []
        if os.path.isdir(ENGINES_DIR):
            engine_files = [
                f for f in os.listdir(ENGINES_DIR)
                if f.endswith("_engine.py") and not f.startswith("__")
            ]
        metrics["engines_loaded"] = len(engine_files)

        # State summary
        state_file = os.path.join(root, ".tpl_state.json")
        if os.path.isfile(state_file):
            try:
                with open(state_file) as f:
                    state = json.load(f)
                metrics["modules_installed"] = len(state.get("installed", {}))
                metrics["last_state_update"] = state.get("updated", 0)
            except Exception:
                pass

        metrics["collected_at"] = int(time.time())
        return metrics

    # ── Endpoints ─────────────────────────────────────────────────────

    @app.get("/diagnosis/run")
    async def diagnosis_run(_u=Depends(require_admin)):
        """Run full system diagnosis."""
        logs = _read_all_logs(300)
        engines = _verify_engines()
        causes = _analyze_root_causes(logs)
        drift = _detect_drift()
        recs = _generate_recommendations(logs, engines)

        # Count log entries
        log_summary = {}
        for name, entries in logs.items():
            levels = Counter(
                e.get("level", e.get("severity", e.get("outcome", "info")))
                for e in entries
            )
            log_summary[name] = {
                "total": len(entries),
                "levels": dict(levels),
            }

        overall = "healthy"
        if any(c["severity"] == "high" for c in causes):
            overall = "attention_required"
        if any(c["severity"] == "critical" for c in causes) or any(
            r["priority"] == "critical" for r in recs
        ):
            overall = "critical"

        result = {
            "status": overall,
            "root_causes": causes,
            "engines": engines,
            "drift": drift,
            "recommendations": recs,
            "log_summary": log_summary,
            "diagnosed_at": int(time.time()),
        }

        # Save to history
        _append_diag({
            "type": "full_diagnosis",
            "status": overall,
            "causes_count": len(causes),
            "recs_count": len(recs),
            "drift_count": drift.get("drift_count", 0),
        })

        return result

    @app.get("/diagnosis/correlate")
    async def diagnosis_correlate(window: int = 60, _u=Depends(require_admin)):
        """Cross-log event correlation."""
        window = max(10, min(window, 600))
        logs = _read_all_logs(500)
        correlations = _correlate_events(logs, window)
        return {
            "correlations": correlations,
            "total": len(correlations),
            "window_seconds": window,
            "logs_analyzed": {k: len(v) for k, v in logs.items()},
        }

    @app.get("/diagnosis/engines")
    async def diagnosis_engines(_u=Depends(require_admin)):
        """Verify health of all loaded engines."""
        engines = _verify_engines()
        healthy = sum(1 for e in engines if e["status"] == "ok")
        total = len(engines)
        return {
            "engines": engines,
            "healthy": healthy,
            "total": total,
            "all_ok": healthy == total,
        }

    @app.get("/diagnosis/config-drift")
    async def diagnosis_config_drift(_u=Depends(require_admin)):
        """Detect configuration drift from baseline."""
        return _detect_drift()

    @app.get("/diagnosis/recommendations")
    async def diagnosis_recommendations(_u=Depends(require_admin)):
        """AI-like recommendations based on current state."""
        logs = _read_all_logs(200)
        engines = _verify_engines()
        recs = _generate_recommendations(logs, engines)
        return {
            "recommendations": recs,
            "total": len(recs),
            "critical": sum(1 for r in recs if r["priority"] == "critical"),
            "high": sum(1 for r in recs if r["priority"] == "high"),
        }

    @app.post("/diagnosis/remediate")
    async def diagnosis_remediate(
        request: Request, action: str = "", _u=Depends(require_admin)
    ):
        """Execute automated remediation for a specific issue."""
        valid_actions = [
            "rotate_logs",
            "rebuild_baseline",
            "cleanup_old_data",
            "verify_integrity",
        ]
        if action not in valid_actions:
            raise HTTPException(
                400,
                f"Invalid action. Valid: {', '.join(valid_actions)}",
            )

        result = _execute_remediation(action)

        audit(
            request,
            "diagnosis.remediate",
            "success" if result["success"] else "failed",
            _u.get("sub", "admin"),
            {"action": action},
        )

        _append_diag({
            "type": "remediation",
            "action": action,
            "success": result["success"],
        })

        return result

    @app.get("/diagnosis/report")
    async def diagnosis_report(_u=Depends(require_admin)):
        """Full diagnostic report — aggregated view."""
        logs = _read_all_logs(200)
        engines = _verify_engines()
        causes = _analyze_root_causes(logs)
        drift = _detect_drift()
        recs = _generate_recommendations(logs, engines)
        metrics = _aggregate_metrics()

        # Score 0-100
        score = 100
        for c in causes:
            if c["severity"] == "critical":
                score -= 20
            elif c["severity"] == "high":
                score -= 10
            elif c["severity"] == "medium":
                score -= 5
        for r in recs:
            if r["priority"] == "critical":
                score -= 15
            elif r["priority"] == "high":
                score -= 8
        if drift.get("drift_count", 0) > 5:
            score -= 10
        elif drift.get("drift_count", 0) > 0:
            score -= 3

        bad_engines = sum(1 for e in engines if e["status"] != "ok")
        score -= bad_engines * 15
        score = max(0, min(100, score))

        grade = (
            "A+" if score >= 95
            else "A" if score >= 85
            else "B" if score >= 70
            else "C" if score >= 55
            else "D" if score >= 40
            else "F"
        )

        return {
            "score": score,
            "grade": grade,
            "status": "healthy" if score >= 70 else "degraded" if score >= 40 else "critical",
            "summary": {
                "root_causes": len(causes),
                "recommendations": len(recs),
                "config_drifts": drift.get("drift_count", 0),
                "engines_ok": sum(1 for e in engines if e["status"] == "ok"),
                "engines_total": len(engines),
            },
            "root_causes": causes,
            "recommendations": recs[:10],
            "drift": drift,
            "metrics": metrics,
            "diagnosed_at": int(time.time()),
        }

    @app.get("/diagnosis/metrics")
    async def diagnosis_metrics(_u=Depends(require_admin)):
        """Unified metrics from all engines."""
        return _aggregate_metrics()

    @app.post("/diagnosis/baseline")
    async def diagnosis_save_baseline(
        request: Request, _u=Depends(require_admin)
    ):
        """Save current configuration as the new baseline."""
        snapshot = _build_config_snapshot()
        with open(CONFIG_BASELINE_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)

        audit(
            request,
            "diagnosis.save_baseline",
            "success",
            _u.get("sub", "admin"),
            {"engines": len(snapshot["engines"]), "modules": len(snapshot["modules"])},
        )

        return {
            "status": "baseline_saved",
            "engines": len(snapshot["engines"]),
            "modules": len(snapshot["modules"]),
            "timestamp": snapshot["timestamp"],
        }

    @app.get("/diagnosis/ai-analysis")
    async def diagnosis_ai_analysis(_u=Depends(require_admin)):
        """Full AI-powered system analysis with statistical scoring."""
        logs = _read_all_logs(500)
        engines = _verify_engines()
        causes = _analyze_root_causes(logs)
        drift = _detect_drift()
        recs = _generate_recommendations(logs, engines)
        patterns = _detect_event_patterns(logs)
        scoring = _compute_diagnosis_score(causes, recs, drift, engines, patterns)

        # Generate AI summary
        parts = []
        if scoring["score"] >= 85:
            parts.append(f"✅ Sistema in ottima salute ({scoring['score']}/100, {scoring['grade']}).")
        elif scoring["score"] >= 70:
            parts.append(f"📊 Sistema operativo ({scoring['score']}/100, {scoring['grade']}).")
        elif scoring["score"] >= 40:
            parts.append(f"⚡ Sistema degradato ({scoring['score']}/100, {scoring['grade']}). Attenzione richiesta.")
        else:
            parts.append(f"⚠ CRITICO ({scoring['score']}/100, {scoring['grade']}). Intervento immediato.")

        if causes:
            high_causes = [c for c in causes if c["severity"] in ("high", "critical")]
            if high_causes:
                parts.append(f"🔴 {len(high_causes)} problemi gravi rilevati.")
        if patterns:
            parts.append(f"🧠 {len(patterns)} pattern anomali identificati dall'AI.")
        if drift.get("drift_count", 0) > 0:
            parts.append(f"📋 {drift['drift_count']} drift di configurazione.")

        summary = " ".join(parts)

        _append_diag({
            "type": "ai_analysis",
            "score": scoring["score"],
            "grade": scoring["grade"],
            "patterns_found": len(patterns),
            "causes_found": len(causes),
        })

        return {
            "score": scoring["score"],
            "grade": scoring["grade"],
            "summary": summary,
            "breakdown": scoring["breakdown"],
            "patterns": patterns,
            "root_causes": causes,
            "recommendations": recs[:10],
            "drift": drift,
            "engines": {
                "ok": sum(1 for e in engines if e["status"] == "ok"),
                "total": len(engines),
            },
            "analyzed_at": int(time.time()),
        }
