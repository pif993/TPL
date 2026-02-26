"""
TPL AI Log Analysis Engine — v2.0.0
Analisi avanzata dei log con rilevamento anomalie statistico,
clustering temporale, analisi trend, previsione e scoring.
"""

import json, os, math, time, hashlib
from collections import Counter, defaultdict
from datetime import datetime
from fastapi import FastAPI, Depends, Query


def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    root = ctx["root"]

    LOG_FILES = {
        "events":   os.path.join(root, ".tpl_events.jsonl"),
        "audit":    os.path.join(root, ".tpl_audit.jsonl"),
        "security": os.path.join(root, ".tpl_security.jsonl"),
        "comm":     os.path.join(root, ".tpl_comm.jsonl"),
    }

    # ── Helpers ────────────────────────────────────────────────────────

    def _read_log(filepath: str, limit: int = 2000) -> list:
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

    def _read_all_logs(limit: int = 1000) -> dict:
        return {name: _read_log(path, limit) for name, path in LOG_FILES.items()}

    def _extract_ts(entry: dict) -> int:
        ts = entry.get("ts", entry.get("timestamp", 0))
        if isinstance(ts, str):
            try:
                return int(datetime.fromisoformat(ts).timestamp())
            except Exception:
                return 0
        return int(ts) if ts else 0

    # ── Statistical functions ──────────────────────────────────────────

    def _mean(values: list) -> float:
        return sum(values) / len(values) if values else 0

    def _stddev(values: list) -> float:
        if len(values) < 2:
            return 0
        m = _mean(values)
        return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))

    def _z_score(value: float, mean: float, std: float) -> float:
        return (value - mean) / std if std > 0 else 0

    def _percentile(values: list, p: float) -> float:
        if not values:
            return 0
        s = sorted(values)
        idx = (len(s) - 1) * p / 100
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            return s[lo]
        return s[lo] + (s[hi] - s[lo]) * (idx - lo)

    def _linear_regression(points: list) -> tuple:
        """Returns (slope, intercept, r_squared) for [(x, y), ...]."""
        n = len(points)
        if n < 2:
            return (0, 0, 0)
        sum_x = sum(p[0] for p in points)
        sum_y = sum(p[1] for p in points)
        sum_xy = sum(p[0] * p[1] for p in points)
        sum_x2 = sum(p[0] ** 2 for p in points)
        denom = n * sum_x2 - sum_x ** 2
        if denom == 0:
            return (0, _mean([p[1] for p in points]), 0)
        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n
        y_mean = sum_y / n
        ss_tot = sum((p[1] - y_mean) ** 2 for p in points)
        ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in points)
        r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
        return (slope, intercept, r2)

    def _pearson(x: list, y: list) -> float:
        n = len(x)
        if n < 2:
            return 0
        mx, my = _mean(x), _mean(y)
        sx, sy = _stddev(x), _stddev(y)
        if sx == 0 or sy == 0:
            return 0
        cov = sum((x[i] - mx) * (y[i] - my) for i in range(n)) / (n - 1)
        return cov / (sx * sy)

    # ── Time-series anomaly detection ──────────────────────────────────

    def _time_series_anomalies(logs: list, bucket_seconds: int = 300) -> dict:
        """Bucket events into time windows and detect statistical anomalies."""
        if not logs:
            return {"anomalies": [], "buckets": [], "stats": {}}

        timestamps = [_extract_ts(e) for e in logs]
        timestamps = [t for t in timestamps if t > 0]
        if not timestamps:
            return {"anomalies": [], "buckets": [], "stats": {}}

        min_ts, max_ts = min(timestamps), max(timestamps)
        if max_ts == min_ts:
            return {"anomalies": [], "buckets": [{"ts": min_ts, "count": len(timestamps)}], "stats": {}}

        buckets = defaultdict(int)
        for ts in timestamps:
            buckets[(ts - min_ts) // bucket_seconds] += 1

        total_buckets = (max_ts - min_ts) // bucket_seconds + 1
        counts = [buckets.get(i, 0) for i in range(total_buckets)]

        mean = _mean(counts)
        std = _stddev(counts)
        p95 = _percentile(counts, 95)

        anomalies = []
        bucket_data = []
        for i, count in enumerate(counts):
            ts = min_ts + i * bucket_seconds
            z = _z_score(count, mean, std)
            is_anomaly = abs(z) > 2.5
            bucket_data.append({"ts": ts, "count": count, "z_score": round(z, 2), "anomaly": is_anomaly})
            if is_anomaly:
                anomalies.append({
                    "ts": ts, "count": count, "z_score": round(z, 2),
                    "type": "spike" if z > 0 else "drop",
                    "deviation": f"{abs(z):.1f}σ",
                })

        return {
            "anomalies": anomalies,
            "buckets": bucket_data[-100:],
            "stats": {
                "mean": round(mean, 2), "stddev": round(std, 2), "p95": round(p95, 2),
                "total_events": len(timestamps), "total_buckets": total_buckets,
                "bucket_seconds": bucket_seconds,
                "time_span_hours": round((max_ts - min_ts) / 3600, 1),
            },
        }

    # ── Trend analysis ─────────────────────────────────────────────────

    def _analyze_trends(logs: list, bucket_seconds: int = 600) -> dict:
        if len(logs) < 5:
            return {"trend": "insufficient_data", "slope": 0, "r_squared": 0}

        timestamps = [t for t in (_extract_ts(e) for e in logs) if t > 0]
        if len(timestamps) < 5:
            return {"trend": "insufficient_data", "slope": 0, "r_squared": 0}

        min_ts, max_ts = min(timestamps), max(timestamps)
        buckets = defaultdict(int)
        for ts in timestamps:
            buckets[(ts - min_ts) // bucket_seconds] += 1

        total_buckets = (max_ts - min_ts) // bucket_seconds + 1
        points = [(i, buckets.get(i, 0)) for i in range(total_buckets)]
        slope, intercept, r2 = _linear_regression(points)

        if r2 < 0.1:
            trend = "stable"
        elif slope > 0.5:
            trend = "increasing"
        elif slope > 0.1:
            trend = "slightly_increasing"
        elif slope < -0.5:
            trend = "decreasing"
        elif slope < -0.1:
            trend = "slightly_decreasing"
        else:
            trend = "stable"

        current_rate = slope * total_buckets + intercept
        forecast_1h = max(0, current_rate * (3600 / bucket_seconds))

        return {
            "trend": trend, "slope": round(slope, 4), "r_squared": round(r2, 4),
            "intercept": round(intercept, 2),
            "current_rate_per_bucket": round(current_rate, 2),
            "forecast_events_per_hour": round(forecast_1h, 1),
            "data_points": len(points),
        }

    # ── Event clustering ───────────────────────────────────────────────

    def _cluster_events(logs: list) -> list:
        if not logs:
            return []

        clusters: dict = defaultdict(lambda: {"count": 0, "events": [], "first_ts": 0, "last_ts": 0})
        for e in logs:
            key = f"{e.get('source', e.get('action', '?'))}:{e.get('event', e.get('type', '?'))}:{e.get('level', e.get('severity', e.get('outcome', 'info')))}"
            ts = _extract_ts(e)
            c = clusters[key]
            c["count"] += 1
            if c["first_ts"] == 0 or ts < c["first_ts"]:
                c["first_ts"] = ts
            if ts > c["last_ts"]:
                c["last_ts"] = ts
            if len(c["events"]) < 3:
                c["events"].append(e)

        result = []
        for key, data in sorted(clusters.items(), key=lambda x: x[1]["count"], reverse=True):
            parts = key.split(":", 2)
            span = data["last_ts"] - data["first_ts"]
            rate = data["count"] / max(span, 1) * 3600 if span > 0 else data["count"]
            result.append({
                "cluster_id": hashlib.md5(key.encode()).hexdigest()[:10],
                "source": parts[0] if parts else "?",
                "event": parts[1] if len(parts) > 1 else "?",
                "level": parts[2] if len(parts) > 2 else "?",
                "count": data["count"], "first_seen": data["first_ts"],
                "last_seen": data["last_ts"], "rate_per_hour": round(rate, 1),
                "samples": data["events"],
            })
        return result[:30]

    # ── Cross-source correlation ───────────────────────────────────────

    def _cross_source_analysis(all_logs: dict) -> dict:
        source_stats = {}
        total_events = 0

        for source, logs in all_logs.items():
            if not logs:
                source_stats[source] = {"count": 0, "severity_dist": {}, "trend": "empty"}
                continue

            levels = Counter()
            for e in logs:
                levels[e.get("level", e.get("severity", e.get("outcome", "info")))] += 1

            trend = _analyze_trends(logs)
            total = len(logs)
            total_events += total
            error_count = sum(v for k, v in levels.items() if k in ("error", "critical", "failed"))

            source_stats[source] = {
                "count": total,
                "severity_distribution": dict(levels),
                "error_rate": round(error_count / total, 3) if total else 0,
                "trend": trend["trend"], "trend_slope": trend["slope"],
            }

        # Pearson correlation across sources
        correlations = []
        sources = list(all_logs.keys())
        for i in range(len(sources)):
            for j in range(i + 1, len(sources)):
                s1, s2 = sources[i], sources[j]
                logs1, logs2 = all_logs[s1], all_logs[s2]
                if len(logs1) < 5 or len(logs2) < 5:
                    continue
                ts1 = sorted([_extract_ts(e) for e in logs1 if _extract_ts(e) > 0])
                ts2 = sorted([_extract_ts(e) for e in logs2 if _extract_ts(e) > 0])
                if not ts1 or not ts2:
                    continue
                min_ts = min(ts1[0], ts2[0])
                max_ts = max(ts1[-1], ts2[-1])
                bucket_s = 300
                total_b = max(1, (max_ts - min_ts) // bucket_s + 1)
                b1 = [0] * total_b
                b2 = [0] * total_b
                for t in ts1:
                    b1[min((t - min_ts) // bucket_s, total_b - 1)] += 1
                for t in ts2:
                    b2[min((t - min_ts) // bucket_s, total_b - 1)] += 1
                corr = _pearson(b1, b2)
                if abs(corr) > 0.3:
                    correlations.append({
                        "sources": [s1, s2], "correlation": round(corr, 3),
                        "strength": "strong" if abs(corr) > 0.7 else "moderate",
                        "direction": "positive" if corr > 0 else "negative",
                    })

        return {"source_stats": source_stats, "total_events": total_events, "cross_correlations": correlations}

    # ── Multi-factor severity scoring ──────────────────────────────────

    def _compute_severity_score(all_logs: dict) -> dict:
        score = 0
        factors = []

        # Factor 1: Error rate (max 30)
        total = errors = 0
        for logs in all_logs.values():
            total += len(logs)
            for e in logs:
                if e.get("level", e.get("severity", e.get("outcome", "info"))) in ("error", "critical", "failed"):
                    errors += 1
        if total > 0:
            er = errors / total
            fs = min(30, int(er * 100))
            score += fs
            factors.append({"name": "error_rate", "value": round(er, 3), "contribution": fs, "max": 30})

        # Factor 2: Anomaly count (max 25)
        all_events = [e for logs in all_logs.values() for e in logs]
        anom = _time_series_anomalies(all_events, 300)
        ac = len(anom["anomalies"])
        fs = min(25, ac * 5)
        score += fs
        factors.append({"name": "anomalies", "value": ac, "contribution": fs, "max": 25})

        # Factor 3: Security density (max 25)
        sec_count = len(all_logs.get("security", []))
        fs = min(25, int(sec_count / max(total, 1) * 200)) if total else 0
        score += fs
        factors.append({"name": "security_density", "value": sec_count, "contribution": fs, "max": 25})

        # Factor 4: Trend acceleration (max 20)
        trend = _analyze_trends(all_events, 600)
        if trend["trend"] == "increasing" and trend["r_squared"] > 0.3:
            fs = min(20, int(trend["slope"] * 10))
        elif trend["trend"] == "slightly_increasing":
            fs = 5
        else:
            fs = 0
        score += fs
        factors.append({"name": "trend_acceleration", "value": trend["slope"], "contribution": fs, "max": 20})

        score = min(100, score)
        level = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
        return {"score": score, "level": level, "factors": factors}

    # ── Natural language summary ───────────────────────────────────────

    def _generate_summary(severity: dict, trends: dict, cross: dict, anomalies: dict) -> str:
        parts = []
        level, sc = severity["level"], severity["score"]
        labels = {"critical": f"⚠ ATTENZIONE: Severità critica ({sc}/100).",
                  "high": f"⚡ Severità alta ({sc}/100) — azione raccomandata.",
                  "medium": f"📊 Severità media ({sc}/100) — monitorare.",
                  "low": f"✅ Sistema stabile ({sc}/100)."}
        parts.append(labels.get(level, labels["low"]))

        ac = len(anomalies.get("anomalies", []))
        if ac:
            spikes = sum(1 for a in anomalies["anomalies"] if a["type"] == "spike")
            if spikes:
                parts.append(f"Rilevati {spikes} picchi anomali.")
            if ac - spikes > 0:
                parts.append(f"Rilevate {ac - spikes} cadute anomale.")

        t = trends.get("trend", "stable")
        if t == "increasing":
            parts.append(f"Trend in forte crescita (pendenza: {trends['slope']:.2f}).")
        elif t == "decreasing":
            parts.append("Trend in diminuzione.")

        strong = [c for c in cross.get("cross_correlations", []) if c["strength"] == "strong"]
        if strong:
            pairs = ", ".join(f"{c['sources'][0]}↔{c['sources'][1]}" for c in strong[:3])
            parts.append(f"Correlazione forte: {pairs}.")

        for src, st in cross.get("source_stats", {}).items():
            if st.get("error_rate", 0) > 0.2:
                parts.append(f"'{src}' ha tasso errori elevato ({st['error_rate']:.0%}).")

        return " ".join(parts)

    # ── Forecasting ────────────────────────────────────────────────────

    def _forecast(logs: list, horizon_hours: int = 24) -> dict:
        if len(logs) < 10:
            return {"forecast": "insufficient_data", "predicted_events": 0}
        timestamps = sorted([t for t in (_extract_ts(e) for e in logs) if t > 0])
        if len(timestamps) < 10:
            return {"forecast": "insufficient_data", "predicted_events": 0}

        min_ts = timestamps[0]
        buckets = defaultdict(int)
        for ts in timestamps:
            buckets[(ts - min_ts) // 3600] += 1
        max_h = max(buckets.keys()) if buckets else 0
        points = [(h, buckets.get(h, 0)) for h in range(max_h + 1)]
        slope, intercept, r2 = _linear_regression(points)

        predictions = []
        for h in range(1, horizon_hours + 1):
            pred = max(0, slope * (max_h + h) + intercept)
            predictions.append({"hour_offset": h, "predicted_events": round(pred, 1)})

        total_pred = sum(p["predicted_events"] for p in predictions)
        confidence = "high" if r2 > 0.7 else "medium" if r2 > 0.3 else "low"

        return {
            "forecast": "computed", "horizon_hours": horizon_hours,
            "predicted_total": round(total_pred, 1), "confidence": confidence,
            "r_squared": round(r2, 4), "hourly_predictions": predictions[:24],
            "historical_hours": max_h + 1, "historical_total": len(timestamps),
        }

    # ── Periodicity detection ──────────────────────────────────────────

    def _detect_periodicity(logs: list) -> dict:
        if len(logs) < 20:
            return {"periodic": False, "patterns": []}
        timestamps = sorted([t for t in (_extract_ts(e) for e in logs) if t > 0])
        if len(timestamps) < 20:
            return {"periodic": False, "patterns": []}

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        intervals = [iv for iv in intervals if iv > 0]
        if not intervals:
            return {"periodic": False, "patterns": []}

        period_buckets = defaultdict(int)
        for iv in intervals:
            if iv < 5:
                continue
            if iv < 60:
                bucket = round(iv / 10) * 10
            elif iv < 3600:
                bucket = round(iv / 60) * 60
            else:
                bucket = round(iv / 300) * 300
            period_buckets[bucket] += 1

        total = len(intervals)
        patterns = []
        for period, count in sorted(period_buckets.items(), key=lambda x: x[1], reverse=True)[:5]:
            freq = count / total
            if freq > 0.1:
                label = f"{period}s" if period < 60 else f"{period // 60}min" if period < 3600 else f"{period // 3600}h"
                patterns.append({"period_seconds": period, "label": label, "occurrences": count, "frequency": round(freq, 3)})

        return {
            "periodic": len(patterns) > 0, "patterns": patterns,
            "total_intervals": total, "mean_interval": round(_mean(intervals), 1),
            "stddev_interval": round(_stddev(intervals), 1),
        }

    # ── Top events ─────────────────────────────────────────────────────

    def _top_events(logs: list, top_n: int = 15) -> list:
        if not logs:
            return []
        events = Counter()
        first_seen = {}
        last_seen = {}
        for e in logs:
            key = e.get("event", e.get("action", e.get("type", "unknown")))
            ts = _extract_ts(e)
            events[key] += 1
            if key not in first_seen or ts < first_seen[key]:
                first_seen[key] = ts
            if key not in last_seen or ts > last_seen[key]:
                last_seen[key] = ts

        total = sum(events.values())
        result = []
        for event, count in events.most_common(top_n):
            span = last_seen.get(event, 0) - first_seen.get(event, 0)
            rate_h = count / max(span, 1) * 3600 if span > 0 else count
            result.append({
                "event": event, "count": count,
                "percentage": round(count / total * 100, 1),
                "rate_per_hour": round(rate_h, 1),
                "first_seen": first_seen.get(event, 0),
                "last_seen": last_seen.get(event, 0),
            })
        return result

    # ── Endpoints ──────────────────────────────────────────────────────

    @app.get("/ai/log-analysis")
    async def analyze_logs(
        limit: int = Query(1000, ge=10, le=5000),
        bucket: int = Query(300, ge=60, le=3600),
        _u=Depends(require_admin),
    ):
        """Full AI log analysis: anomalies, trends, clusters, severity, forecast."""
        all_logs = _read_all_logs(limit)
        all_events = [e for logs in all_logs.values() for e in logs]
        anomalies = _time_series_anomalies(all_events, bucket)
        trends = _analyze_trends(all_events, bucket)
        cross = _cross_source_analysis(all_logs)
        severity = _compute_severity_score(all_logs)
        forecast = _forecast(all_events, 24)
        summary = _generate_summary(severity, trends, cross, anomalies)
        return {
            "severity": severity, "anomalies": anomalies, "trends": trends,
            "cross_source": cross, "forecast": forecast, "summary": summary,
            "analyzed_at": int(time.time()),
        }

    @app.get("/ai/anomalies")
    async def detect_anomalies(
        source: str = Query("all"),
        bucket: int = Query(300, ge=60, le=3600),
        limit: int = Query(1000, ge=10, le=5000),
        _u=Depends(require_admin),
    ):
        """Statistical anomaly detection with Z-score analysis."""
        if source == "all":
            events = [e for logs in _read_all_logs(limit).values() for e in logs]
        else:
            events = _read_log(LOG_FILES.get(source, ""), limit)
        result = _time_series_anomalies(events, bucket)
        result["source"] = source
        return result

    @app.get("/ai/trends")
    async def analyze_trends_ep(
        source: str = Query("all"),
        bucket: int = Query(600, ge=60, le=7200),
        limit: int = Query(2000, ge=10, le=5000),
        _u=Depends(require_admin),
    ):
        """Trend analysis with linear regression."""
        if source == "all":
            events = [e for logs in _read_all_logs(limit).values() for e in logs]
        else:
            events = _read_log(LOG_FILES.get(source, ""), limit)
        result = _analyze_trends(events, bucket)
        result["source"] = source
        return result

    @app.get("/ai/clusters")
    async def cluster_analysis(limit: int = Query(1000, ge=10, le=5000), _u=Depends(require_admin)):
        """Event clustering by similarity."""
        events = [e for logs in _read_all_logs(limit).values() for e in logs]
        clusters = _cluster_events(events)
        return {"clusters": clusters, "total_clusters": len(clusters), "total_events": len(events)}

    @app.get("/ai/forecast")
    async def forecast_events(
        horizon: int = Query(24, ge=1, le=168),
        limit: int = Query(2000, ge=100, le=5000),
        _u=Depends(require_admin),
    ):
        """Event volume forecasting."""
        events = [e for logs in _read_all_logs(limit).values() for e in logs]
        return _forecast(events, horizon)

    @app.get("/ai/severity")
    async def severity_score(limit: int = Query(1000, ge=10, le=5000), _u=Depends(require_admin)):
        """Multi-factor severity scoring."""
        return _compute_severity_score(_read_all_logs(limit))

    @app.get("/ai/periodicity")
    async def periodicity_analysis(
        source: str = Query("all"),
        limit: int = Query(2000, ge=50, le=5000),
        _u=Depends(require_admin),
    ):
        """Detect periodic patterns in events."""
        if source == "all":
            events = [e for logs in _read_all_logs(limit).values() for e in logs]
        else:
            events = _read_log(LOG_FILES.get(source, ""), limit)
        result = _detect_periodicity(events)
        result["source"] = source
        return result

    @app.get("/ai/top-events")
    async def top_events(
        source: str = Query("all"),
        top: int = Query(15, ge=5, le=50),
        limit: int = Query(2000, ge=10, le=5000),
        _u=Depends(require_admin),
    ):
        """Most frequent events with statistical context."""
        if source == "all":
            events = [e for logs in _read_all_logs(limit).values() for e in logs]
        else:
            events = _read_log(LOG_FILES.get(source, ""), limit)
        return {"top_events": _top_events(events, top), "total_events": len(events), "source": source}

    @app.get("/ai/cross-source")
    async def cross_source(limit: int = Query(1000, ge=10, le=5000), _u=Depends(require_admin)):
        """Cross-source correlation analysis."""
        return _cross_source_analysis(_read_all_logs(limit))

    @app.get("/ai/summary")
    async def ai_summary(limit: int = Query(1000, ge=10, le=3000), _u=Depends(require_admin)):
        """Quick AI summary in natural language."""
        all_logs = _read_all_logs(limit)
        all_events = [e for logs in all_logs.values() for e in logs]
        anomalies = _time_series_anomalies(all_events, 300)
        trends = _analyze_trends(all_events, 600)
        cross = _cross_source_analysis(all_logs)
        severity = _compute_severity_score(all_logs)
        return {
            "summary": _generate_summary(severity, trends, cross, anomalies),
            "severity_score": severity["score"], "severity_level": severity["level"],
            "anomaly_count": len(anomalies.get("anomalies", [])), "trend": trends["trend"],
        }
