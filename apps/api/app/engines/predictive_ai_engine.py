"""
TPL Predictive AI Engine — v1.0.0
Cervello AI centrale: health score unificato, analisi comportamentale,
previsione minacce, risk assessment, incident timeline, smart alerting.
"""

import json, os, time, math, hashlib, threading
from collections import Counter, defaultdict
from datetime import datetime
from fastapi import FastAPI, Depends, Query


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx["root"]

    LOG_FILES = {
        "audit":    os.path.join(root, ".tpl_audit.jsonl"),
        "events":   os.path.join(root, ".tpl_events.jsonl"),
        "security": os.path.join(root, ".tpl_security.jsonl"),
        "comm":     os.path.join(root, ".tpl_comm.jsonl"),
    }
    AI_STATE_FILE = os.path.join(root, ".tpl_ai_state.json")
    ALERT_HISTORY_FILE = os.path.join(root, ".tpl_ai_alerts.jsonl")

    _lock = threading.Lock()

    # ── Helpers ────────────────────────────────────────────────────────

    def _read_log(filepath: str, limit: int = 1000) -> list:
        if not os.path.isfile(filepath):
            return []
        entries = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
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

    def _read_all_logs(limit: int = 500) -> dict:
        return {name: _read_log(path, limit) for name, path in LOG_FILES.items()}

    def _ts(entry: dict) -> int:
        ts = entry.get("ts", entry.get("timestamp", 0))
        if isinstance(ts, str):
            try:
                return int(datetime.fromisoformat(ts).timestamp())
            except Exception:
                return 0
        return int(ts) if ts else 0

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

    def _load_ai_state() -> dict:
        if not os.path.isfile(AI_STATE_FILE):
            return _default_state()
        try:
            with open(AI_STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return _default_state()

    def _save_ai_state(state: dict):
        with _lock:
            try:
                with open(AI_STATE_FILE, "w") as f:
                    json.dump(state, f, separators=(",", ":"))
            except Exception:
                pass

    def _default_state():
        return {
            "last_analysis": 0,
            "analysis_count": 0,
            "baseline_behavior": {},
            "risk_history": [],
            "alert_count": 0,
        }

    def _append_alert(alert: dict):
        row = {"ts": int(time.time()), **alert}
        try:
            with open(ALERT_HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, separators=(",", ":")) + "\n")
        except Exception:
            pass

    # ── Behavioral analysis ────────────────────────────────────────────

    def _analyze_user_behavior(audit_logs: list) -> dict:
        """Detect unusual user behavior patterns."""
        if not audit_logs:
            return {"users": {}, "anomalies": []}

        user_stats: dict = defaultdict(lambda: {
            "actions": Counter(), "ips": Counter(), "hours": Counter(),
            "total": 0, "failures": 0, "first_seen": 0, "last_seen": 0,
        })

        for e in audit_logs:
            user = e.get("user", e.get("sub", "unknown"))
            action = e.get("action", "?")
            ip = e.get("ip", "?")
            ts_val = _ts(e)
            outcome = e.get("outcome", "success")

            u = user_stats[user]
            u["actions"][action] += 1
            u["ips"][ip] += 1
            if ts_val > 0:
                u["hours"][datetime.fromtimestamp(ts_val).hour] += 1
            u["total"] += 1
            if outcome == "failed":
                u["failures"] += 1
            if u["first_seen"] == 0 or ts_val < u["first_seen"]:
                u["first_seen"] = ts_val
            if ts_val > u["last_seen"]:
                u["last_seen"] = ts_val

        anomalies = []
        user_summaries = {}

        for user, stats in user_stats.items():
            failure_rate = stats["failures"] / max(stats["total"], 1)
            ip_count = len(stats["ips"])
            actions_variety = len(stats["actions"])

            # Anomaly: high failure rate
            if failure_rate > 0.4 and stats["total"] >= 5:
                anomalies.append({
                    "type": "high_failure_rate", "user": user,
                    "failure_rate": round(failure_rate, 2),
                    "total_actions": stats["total"],
                    "severity": "high" if failure_rate > 0.7 else "medium",
                    "description": f"Utente {user}: {failure_rate:.0%} azioni fallite",
                })

            # Anomaly: many IPs (potential credential sharing/compromise)
            if ip_count >= 5:
                anomalies.append({
                    "type": "multi_ip", "user": user, "ip_count": ip_count,
                    "severity": "medium",
                    "description": f"Utente {user} accede da {ip_count} IP diversi",
                })

            # Anomaly: unusual hours
            hours = stats["hours"]
            night_actions = sum(hours.get(h, 0) for h in range(0, 6))
            if night_actions > stats["total"] * 0.3 and stats["total"] >= 5:
                anomalies.append({
                    "type": "unusual_hours", "user": user,
                    "night_actions": night_actions,
                    "severity": "low",
                    "description": f"Utente {user}: {night_actions} azioni notturne (00-06)",
                })

            user_summaries[user] = {
                "total_actions": stats["total"], "failures": stats["failures"],
                "failure_rate": round(failure_rate, 3),
                "unique_ips": ip_count, "actions_variety": actions_variety,
                "top_actions": dict(stats["actions"].most_common(5)),
                "top_ips": dict(stats["ips"].most_common(3)),
                "active_hours": dict(stats["hours"].most_common(5)),
                "first_seen": stats["first_seen"], "last_seen": stats["last_seen"],
            }

        return {"users": user_summaries, "anomalies": anomalies}

    # ── Threat prediction ──────────────────────────────────────────────

    def _predict_threats(security_logs: list, audit_logs: list) -> dict:
        """Predict security threats based on patterns."""
        if not security_logs and not audit_logs:
            return {"threats": [], "risk_level": "low", "risk_score": 0}

        threats = []
        risk_score = 0

        # 1. Brute force trend
        auth_failures = [e for e in audit_logs if e.get("outcome") == "failed" and "auth" in e.get("action", "")]
        if len(auth_failures) >= 3:
            # Rate of failures
            ts_list = sorted([_ts(e) for e in auth_failures if _ts(e) > 0])
            if len(ts_list) >= 3:
                recent = ts_list[-10:]
                intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
                avg_interval = _mean(intervals) if intervals else 9999
                if avg_interval < 10:
                    risk_score += 30
                    threats.append({
                        "type": "brute_force_active", "severity": "critical",
                        "confidence": "high",
                        "description": f"Attacco brute force in corso ({len(auth_failures)} tentativi, avg {avg_interval:.0f}s tra tentativi)",
                        "recommendation": "Verificare IP block e protezione brute force",
                        "evidence_count": len(auth_failures),
                    })
                elif avg_interval < 60:
                    risk_score += 15
                    threats.append({
                        "type": "brute_force_slow", "severity": "high",
                        "confidence": "medium",
                        "description": f"Possibile brute force lento ({len(auth_failures)} tentativi)",
                        "recommendation": "Monitorare e verificare whitelisting IP",
                        "evidence_count": len(auth_failures),
                    })

        # 2. Security event density trend
        if len(security_logs) >= 5:
            sec_ts = sorted([_ts(e) for e in security_logs if _ts(e) > 0])
            if len(sec_ts) >= 5:
                # Bucket into 5-min windows
                min_t = sec_ts[0]
                buckets = defaultdict(int)
                for t in sec_ts:
                    buckets[(t - min_t) // 300] += 1
                counts = list(buckets.values())
                mean = _mean(counts)
                std = _stddev(counts)

                # Check if recent activity is above normal
                recent_bucket = max(buckets.keys()) if buckets else 0
                recent_count = buckets.get(recent_bucket, 0)
                if std > 0 and recent_count > mean + 2 * std:
                    risk_score += 20
                    threats.append({
                        "type": "security_spike", "severity": "high",
                        "confidence": "high" if (recent_count - mean) / std > 3 else "medium",
                        "description": f"Picco anomalo di eventi security ({recent_count} vs media {mean:.0f})",
                        "recommendation": "Verificare WAF e firewall rules",
                        "evidence_count": recent_count,
                    })

        # 3. Attack vector distribution
        if security_logs:
            types = Counter(e.get("type", e.get("category", "?")) for e in security_logs)
            for attack_type, count in types.most_common(5):
                if count >= 10:
                    risk_score += min(10, count // 5)
                    threats.append({
                        "type": f"attack_vector_{attack_type}", "severity": "medium",
                        "confidence": "medium",
                        "description": f"Vettore di attacco attivo: {attack_type} ({count} eventi)",
                        "recommendation": f"Rafforzare protezione contro {attack_type}",
                        "evidence_count": count,
                    })

        # 4. IP concentration
        if security_logs:
            ips = Counter(e.get("ip", "?") for e in security_logs if e.get("ip"))
            for ip, count in ips.most_common(3):
                if count >= 10 and ip != "?":
                    risk_score += 5
                    threats.append({
                        "type": "ip_concentration", "severity": "medium",
                        "confidence": "high",
                        "description": f"IP sospetto: {ip} ({count} eventi security)",
                        "recommendation": f"Considerare blocco IP {ip}",
                        "evidence_count": count,
                    })

        # 5. Privilege escalation attempts
        priv_actions = [e for e in audit_logs if any(kw in e.get("action", "") for kw in ("admin", "role", "user.create", "user.delete"))]
        failed_priv = [e for e in priv_actions if e.get("outcome") == "failed"]
        if len(failed_priv) >= 3:
            risk_score += 15
            threats.append({
                "type": "privilege_escalation", "severity": "high",
                "confidence": "medium",
                "description": f"Tentativi di escalation privilegi ({len(failed_priv)} falliti)",
                "recommendation": "Verificare account e permessi",
                "evidence_count": len(failed_priv),
            })

        risk_score = min(100, risk_score)
        risk_level = "critical" if risk_score >= 60 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low"

        return {
            "threats": sorted(threats, key=lambda t: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t["severity"], 9)),
            "risk_level": risk_level,
            "risk_score": risk_score,
        }

    # ── Risk assessment ────────────────────────────────────────────────

    def _risk_assessment(all_logs: dict) -> dict:
        """Comprehensive risk assessment across all dimensions."""
        dimensions = {}

        # 1. Authentication security
        audit = all_logs.get("audit", [])
        total_auth = len([e for e in audit if "auth" in e.get("action", "")])
        failed_auth = len([e for e in audit if e.get("outcome") == "failed" and "auth" in e.get("action", "")])
        auth_risk = min(100, int(failed_auth / max(total_auth, 1) * 200))
        dimensions["authentication"] = {
            "score": auth_risk, "total_events": total_auth, "failures": failed_auth,
            "status": "critical" if auth_risk > 60 else "warning" if auth_risk > 30 else "ok",
        }

        # 2. Network security
        sec = all_logs.get("security", [])
        net_events = len(sec)
        waf_blocks = len([e for e in sec if e.get("category") in ("xss", "sqli", "traversal", "cmdi", "ssrf")])
        net_risk = min(100, waf_blocks * 3 + len([e for e in sec if e.get("category") == "brute_force"]) * 5)
        dimensions["network"] = {
            "score": net_risk, "total_events": net_events, "waf_blocks": waf_blocks,
            "status": "critical" if net_risk > 60 else "warning" if net_risk > 30 else "ok",
        }

        # 3. Data integrity
        state_files = [
            ".tpl_state.json", ".tpl_users.json", ".tpl_audit.jsonl", ".tpl_events.jsonl",
        ]
        corrupted = 0
        missing = 0
        for sf in state_files:
            path = os.path.join(root, sf)
            if not os.path.isfile(path):
                missing += 1
            elif sf.endswith(".json"):
                try:
                    with open(path, "r") as f:
                        json.load(f)
                except Exception:
                    corrupted += 1
        integrity_risk = min(100, corrupted * 30 + missing * 10)
        dimensions["data_integrity"] = {
            "score": integrity_risk, "corrupted": corrupted, "missing": missing,
            "status": "critical" if integrity_risk > 50 else "warning" if integrity_risk > 20 else "ok",
        }

        # 4. Operational health
        events = all_logs.get("events", [])
        error_events = len([e for e in events if e.get("level") in ("error", "critical")])
        op_risk = min(100, int(error_events / max(len(events), 1) * 150))
        dimensions["operational"] = {
            "score": op_risk, "total_events": len(events), "errors": error_events,
            "status": "critical" if op_risk > 60 else "warning" if op_risk > 30 else "ok",
        }

        # 5. Communication health
        comm = all_logs.get("comm", [])
        comm_errors = len([e for e in comm if e.get("status") == "error"])
        comm_risk = min(100, int(comm_errors / max(len(comm), 1) * 200))
        dimensions["communication"] = {
            "score": comm_risk, "total_events": len(comm), "errors": comm_errors,
            "status": "critical" if comm_risk > 60 else "warning" if comm_risk > 30 else "ok",
        }

        # Overall risk score (weighted average)
        weights = {"authentication": 0.3, "network": 0.25, "data_integrity": 0.2, "operational": 0.15, "communication": 0.1}
        overall = sum(dimensions[d]["score"] * weights.get(d, 0.1) for d in dimensions)
        overall = min(100, int(overall))

        return {
            "overall_risk": overall,
            "risk_level": "critical" if overall > 60 else "high" if overall > 40 else "medium" if overall > 20 else "low",
            "dimensions": dimensions,
            "weights": weights,
        }

    # ── Incident timeline ──────────────────────────────────────────────

    def _build_timeline(all_logs: dict, window_minutes: int = 60) -> dict:
        """AI-driven forensic timeline of recent incidents."""
        cutoff = int(time.time()) - window_minutes * 60
        timeline = []

        for source, logs in all_logs.items():
            for e in logs:
                ts_val = _ts(e)
                if ts_val < cutoff:
                    continue

                level = e.get("level", e.get("severity", e.get("outcome", "info")))
                is_significant = level in ("error", "critical", "failed", "high", "blocked")

                if is_significant:
                    timeline.append({
                        "ts": ts_val,
                        "source": source,
                        "event": e.get("event", e.get("action", e.get("type", "?"))),
                        "level": level,
                        "detail": _extract_detail(e),
                        "ip": e.get("ip", ""),
                        "user": e.get("user", e.get("sub", "")),
                    })

        timeline.sort(key=lambda x: x["ts"])

        # Group into incident clusters (events within 30s of each other)
        incidents = []
        current_incident = None
        for event in timeline:
            if current_incident is None or event["ts"] - current_incident["last_ts"] > 30:
                if current_incident:
                    incidents.append(current_incident)
                current_incident = {
                    "start_ts": event["ts"], "last_ts": event["ts"],
                    "events": [event], "sources": {event["source"]},
                    "severity": event["level"],
                }
            else:
                current_incident["last_ts"] = event["ts"]
                current_incident["events"].append(event)
                current_incident["sources"].add(event["source"])
                # Escalate severity
                severity_order = {"critical": 0, "high": 1, "failed": 2, "blocked": 2, "error": 3}
                if severity_order.get(event["level"], 9) < severity_order.get(current_incident["severity"], 9):
                    current_incident["severity"] = event["level"]
        if current_incident:
            incidents.append(current_incident)

        # Serialize
        for inc in incidents:
            inc["sources"] = list(inc["sources"])
            inc["event_count"] = len(inc["events"])
            inc["duration_seconds"] = inc["last_ts"] - inc["start_ts"]

        return {
            "incidents": incidents[-50:],
            "total_incidents": len(incidents),
            "total_events": len(timeline),
            "window_minutes": window_minutes,
        }

    def _extract_detail(entry: dict) -> str:
        for key in ("message", "msg", "detail", "description", "error", "path"):
            if key in entry and entry[key]:
                return str(entry[key])[:150]
        return ""

    # ── Smart alerting ─────────────────────────────────────────────────

    def _smart_alerts(all_logs: dict) -> dict:
        """Reduced-noise alerting: correlate, deduplicate, prioritize."""
        raw_alerts = []

        # Collect all significant events
        for source, logs in all_logs.items():
            for e in logs:
                level = e.get("level", e.get("severity", e.get("outcome", "info")))
                if level in ("error", "critical", "failed", "high"):
                    raw_alerts.append({
                        "source": source, "event": e.get("event", e.get("action", e.get("type", "?"))),
                        "level": level, "ts": _ts(e), "ip": e.get("ip", ""),
                    })

        if not raw_alerts:
            return {"alerts": [], "suppressed": 0, "total_raw": 0}

        # Deduplicate: group by source+event
        groups: dict = defaultdict(list)
        for a in raw_alerts:
            key = f"{a['source']}:{a['event']}"
            groups[key].append(a)

        # Build deduplicated alerts
        deduped = []
        suppressed = 0
        for key, events in groups.items():
            count = len(events)
            latest = max(events, key=lambda x: x["ts"])
            severity = max(events, key=lambda x: {"critical": 0, "high": 1, "failed": 2, "error": 3}.get(x["level"], 9))["level"]

            if count == 1:
                deduped.append({
                    "id": hashlib.md5(key.encode()).hexdigest()[:12],
                    "source": latest["source"], "event": latest["event"],
                    "severity": severity, "count": 1,
                    "last_ts": latest["ts"], "first_ts": latest["ts"],
                })
            else:
                # Suppress if many identical low-severity events
                if count > 5 and severity in ("error",):
                    suppressed += count - 1
                deduped.append({
                    "id": hashlib.md5(key.encode()).hexdigest()[:12],
                    "source": latest["source"], "event": latest["event"],
                    "severity": severity, "count": count,
                    "last_ts": latest["ts"], "first_ts": min(e["ts"] for e in events),
                    "unique_ips": len(set(e["ip"] for e in events if e["ip"])),
                })

        # Sort by severity then count
        severity_order_map = {"critical": 0, "high": 1, "failed": 2, "error": 3}
        deduped.sort(key=lambda a: (severity_order_map.get(a["severity"], 9), -a["count"]))

        return {
            "alerts": deduped[:30],
            "total_alerts": len(deduped),
            "suppressed": suppressed,
            "total_raw": len(raw_alerts),
            "dedup_ratio": round(1 - len(deduped) / max(len(raw_alerts), 1), 2),
        }

    # ── Unified platform health score ──────────────────────────────────

    def _unified_health(all_logs: dict) -> dict:
        """Compute a unified AI platform health score 0-100."""
        risk = _risk_assessment(all_logs)
        threats = _predict_threats(all_logs.get("security", []), all_logs.get("audit", []))
        behavior = _analyze_user_behavior(all_logs.get("audit", []))

        # Base: invert risk score (low risk = high health)
        health = max(0, 100 - risk["overall_risk"])

        # Deduct for active threats
        threat_penalty = min(30, threats["risk_score"] // 3)
        health -= threat_penalty

        # Deduct for behavioral anomalies
        anomaly_penalty = min(15, len(behavior.get("anomalies", [])) * 3)
        health -= anomaly_penalty

        health = max(0, min(100, health))
        grade = "A+" if health >= 95 else "A" if health >= 85 else "B" if health >= 70 else "C" if health >= 55 else "D" if health >= 40 else "F"

        # Generate text summary
        parts = []
        if health >= 85:
            parts.append(f"✅ Piattaforma in ottima salute ({health}/100, {grade}).")
        elif health >= 70:
            parts.append(f"📊 Piattaforma operativa ({health}/100, {grade}).")
        elif health >= 40:
            parts.append(f"⚡ Piattaforma degradata ({health}/100, {grade}).")
        else:
            parts.append(f"⚠ CRITICO ({health}/100, {grade}). Intervento immediato.")

        # Risk dimensions
        crit_dims = [d for d, info in risk["dimensions"].items() if info["status"] == "critical"]
        if crit_dims:
            parts.append(f"Dimensioni critiche: {', '.join(crit_dims)}.")

        # Threats
        crit_threats = [t for t in threats["threats"] if t["severity"] == "critical"]
        if crit_threats:
            parts.append(f"🔴 {len(crit_threats)} minacce critiche attive.")

        # Behavior
        behav_anomalies = behavior.get("anomalies", [])
        if behav_anomalies:
            parts.append(f"👤 {len(behav_anomalies)} anomalie comportamentali rilevate.")

        return {
            "score": health, "grade": grade,
            "status": "healthy" if health >= 70 else "degraded" if health >= 40 else "critical",
            "summary": " ".join(parts),
            "components": {
                "risk_score": risk["overall_risk"],
                "threat_score": threats["risk_score"],
                "behavior_anomalies": len(behav_anomalies),
                "threat_penalty": threat_penalty,
                "anomaly_penalty": anomaly_penalty,
            },
        }

    # ── Optimization recommendations ───────────────────────────────────

    def _performance_recommendations(all_logs: dict) -> list:
        """AI-generated optimization recommendations."""
        recs = []

        # Check log volumes
        for name, path in LOG_FILES.items():
            if os.path.isfile(path):
                size = os.path.getsize(path)
                if size > 20_000_000:
                    recs.append({
                        "category": "performance", "priority": "high",
                        "title": f"Log {name} troppo grande ({size // 1_000_000}MB)",
                        "description": "File di log di grandi dimensioni rallentano le analisi. Eseguire rotazione.",
                        "action": "rotate_logs",
                    })

        # Check event diversity
        events = all_logs.get("events", [])
        if events:
            unique_sources = len(set(e.get("source", "?") for e in events))
            if unique_sources < 3 and len(events) > 50:
                recs.append({
                    "category": "observability", "priority": "medium",
                    "title": "Bassa diversità sorgenti log",
                    "description": f"Solo {unique_sources} sorgenti attive. Abilitare più engine di logging.",
                    "action": None,
                })

        # Check audit completeness
        audit = all_logs.get("audit", [])
        if not audit:
            recs.append({
                "category": "security", "priority": "high",
                "title": "Nessun audit log rilevato",
                "description": "L'audit trail è fondamentale per la sicurezza. Verificare la configurazione.",
                "action": None,
            })
        elif len(audit) < 10:
            recs.append({
                "category": "security", "priority": "medium",
                "title": "Audit log scarso",
                "description": "Pochi eventi di audit. Verificare che tutte le operazioni critiche siano tracciate.",
                "action": None,
            })

        # Check security events
        sec = all_logs.get("security", [])
        if sec:
            types = Counter(e.get("type", e.get("category", "?")) for e in sec)
            dominant = types.most_common(1)
            if dominant and dominant[0][1] > len(sec) * 0.7:
                recs.append({
                    "category": "security", "priority": "medium",
                    "title": f"Vettore di attacco dominante: {dominant[0][0]}",
                    "description": f"Il {dominant[0][1]}/{len(sec)} ({dominant[0][1]/len(sec):.0%}) degli eventi security riguarda '{dominant[0][0]}'. Rafforzare questa difesa.",
                    "action": None,
                })

        # Check communication health
        comm = all_logs.get("comm", [])
        if comm:
            errors = [e for e in comm if e.get("status") == "error"]
            if len(errors) > len(comm) * 0.2:
                recs.append({
                    "category": "reliability", "priority": "high",
                    "title": "Alto tasso errori comunicazione inter-modulo",
                    "description": f"{len(errors)}/{len(comm)} messaggi con errore. Verificare salute dei moduli destinatari.",
                    "action": None,
                })

        # Backup recommendation
        backup_dir = os.path.join(root, ".tpl_backups")
        if not os.path.isdir(backup_dir) or not os.listdir(backup_dir):
            recs.append({
                "category": "resilience", "priority": "critical",
                "title": "Nessun backup rilevato",
                "description": "Creare un backup immediato tramite /resilience/backup.",
                "action": "create_backup",
            })

        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recs.sort(key=lambda r: prio_order.get(r["priority"], 9))
        return recs

    # ── Endpoints ──────────────────────────────────────────────────────

    @app.get("/ai/platform-health")
    async def platform_health(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """Unified AI platform health score."""
        all_logs = _read_all_logs(limit)
        health = _unified_health(all_logs)

        # Update state
        state = _load_ai_state()
        state["last_analysis"] = int(time.time())
        state["analysis_count"] = state.get("analysis_count", 0) + 1
        state["risk_history"].append({"ts": int(time.time()), "score": health["score"]})
        state["risk_history"] = state["risk_history"][-100:]
        _save_ai_state(state)

        return health

    @app.get("/ai/behavior")
    async def user_behavior(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """User behavioral analysis and anomaly detection."""
        audit = _read_log(LOG_FILES["audit"], limit)
        return _analyze_user_behavior(audit)

    @app.get("/ai/threats")
    async def threat_prediction(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """AI-powered threat prediction."""
        sec = _read_log(LOG_FILES["security"], limit)
        audit = _read_log(LOG_FILES["audit"], limit)
        return _predict_threats(sec, audit)

    @app.get("/ai/risk")
    async def risk_assessment(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """Comprehensive multi-dimensional risk assessment."""
        return _risk_assessment(_read_all_logs(limit))

    @app.get("/ai/timeline")
    async def incident_timeline(
        window: int = Query(60, ge=5, le=1440),
        _u=Depends(require_admin),
    ):
        """AI-driven incident timeline."""
        return _build_timeline(_read_all_logs(1000), window)

    @app.get("/ai/smart-alerts")
    async def smart_alerts(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """Noise-reduced, deduplicated smart alerting."""
        return _smart_alerts(_read_all_logs(limit))

    @app.get("/ai/recommendations")
    async def ai_recommendations(
        limit: int = Query(500, ge=50, le=3000),
        _u=Depends(require_admin),
    ):
        """AI performance and security optimization recommendations."""
        recs = _performance_recommendations(_read_all_logs(limit))
        return {
            "recommendations": recs, "total": len(recs),
            "critical": sum(1 for r in recs if r["priority"] == "critical"),
            "high": sum(1 for r in recs if r["priority"] == "high"),
        }

    @app.get("/ai/dashboard")
    async def ai_dashboard(
        limit: int = Query(500, ge=50, le=2000),
        _u=Depends(require_admin),
    ):
        """Full AI dashboard data in a single call."""
        all_logs = _read_all_logs(limit)
        health = _unified_health(all_logs)
        threats = _predict_threats(all_logs.get("security", []), all_logs.get("audit", []))
        risk = _risk_assessment(all_logs)
        behavior = _analyze_user_behavior(all_logs.get("audit", []))
        alerts = _smart_alerts(all_logs)
        timeline = _build_timeline(all_logs, 60)
        recs = _performance_recommendations(all_logs)

        return {
            "health": health,
            "threats": threats,
            "risk": risk,
            "behavior": {
                "users_count": len(behavior["users"]),
                "anomalies": behavior["anomalies"],
            },
            "alerts": alerts,
            "timeline": {
                "total_incidents": timeline["total_incidents"],
                "recent_incidents": timeline["incidents"][-10:],
            },
            "recommendations": recs[:5],
            "analyzed_at": int(time.time()),
        }
