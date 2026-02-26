"""
TPL Advanced AI Engine — v1.0.0
Funzionalità AI avanzatissime: Markov chain prediction, isolation-score
anomaly detection, time-series decomposition, cross-correlation matrix,
entropy analysis, EWMA monitoring, Bayesian risk estimation, KNN pattern
matching.  Tutto in pure Python, zero dipendenze ML esterne.
"""

import json, os, math, time, hashlib, threading
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
    LEARN_FILE = os.path.join(root, ".tpl_ai_learn.json")
    _lock = threading.Lock()

    # ═══════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════

    def _read_log(fpath: str, limit: int = 2000) -> list:
        if not os.path.isfile(fpath):
            return []
        out = []
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        try:
                            out.append(json.loads(ln))
                        except Exception:
                            pass
        except Exception:
            pass
        return out[-limit:]

    def _read_all(limit: int = 1500) -> dict:
        return {n: _read_log(p, limit) for n, p in LOG_FILES.items()}

    def _ts(e: dict) -> int:
        v = e.get("ts", e.get("timestamp", 0))
        if isinstance(v, str):
            try:
                return int(datetime.fromisoformat(v).timestamp())
            except Exception:
                return 0
        return int(v) if v else 0

    def _mean(v): return sum(v) / len(v) if v else 0.0
    def _var(v):
        if len(v) < 2: return 0.0
        m = _mean(v)
        return sum((x - m) ** 2 for x in v) / (len(v) - 1)
    def _std(v): return math.sqrt(_var(v))
    def _median(v):
        s = sorted(v)
        n = len(s)
        if n == 0: return 0
        return (s[n // 2 - 1] + s[n // 2]) / 2 if n % 2 == 0 else s[n // 2]
    def _percentile(v, p):
        s = sorted(v)
        if not s: return 0
        k = (len(s) - 1) * p / 100
        f, c = int(k), min(int(k) + 1, len(s) - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    def _linreg(pts):
        n = len(pts)
        if n < 2: return (0, 0, 0)
        sx = sum(p[0] for p in pts)
        sy = sum(p[1] for p in pts)
        sxy = sum(p[0] * p[1] for p in pts)
        sx2 = sum(p[0] ** 2 for p in pts)
        d = n * sx2 - sx * sx
        if d == 0: return (0, _mean([p[1] for p in pts]), 0)
        slope = (n * sxy - sx * sy) / d
        intercept = (sy - slope * sx) / n
        ym = sy / n
        ss_tot = sum((p[1] - ym) ** 2 for p in pts)
        ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in pts)
        r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
        return (slope, intercept, max(0, r2))

    def _entropy(counts: list) -> float:
        """Shannon entropy in bits."""
        total = sum(counts)
        if total == 0: return 0
        return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)

    def _cosine_sim(a: list, b: list) -> float:
        if len(a) != len(b) or not a: return 0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        return dot / (na * nb) if na > 0 and nb > 0 else 0

    def _pearson(a: list, b: list) -> float:
        n = min(len(a), len(b))
        if n < 3: return 0
        a, b = a[:n], b[:n]
        ma, mb = _mean(a), _mean(b)
        num = sum((a[i] - ma) * (b[i] - mb) for i in range(n))
        da = math.sqrt(sum((x - ma) ** 2 for x in a))
        db = math.sqrt(sum((x - mb) ** 2 for x in b))
        return num / (da * db) if da > 0 and db > 0 else 0

    def _load_learn() -> dict:
        if not os.path.isfile(LEARN_FILE): return {}
        try:
            with open(LEARN_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_learn(d: dict):
        with _lock:
            try:
                with open(LEARN_FILE, "w") as f:
                    json.dump(d, f, separators=(",", ":"))
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════
    # 1. MARKOV CHAIN ATTACK PREDICTION
    # ═══════════════════════════════════════════════════════════════════

    def _markov_prediction(security_logs: list, audit_logs: list) -> dict:
        """
        Model attack sequences as Markov chain state transitions.
        States = event types, transitions = observed sequences.
        Predict most likely next attack vectors and attack chain paths.
        """
        # Build transition matrix from sequential events
        events = []
        for e in security_logs:
            events.append({"ts": _ts(e), "type": e.get("type", e.get("category", "unknown")), "src": "security"})
        for e in audit_logs:
            if e.get("outcome") == "failed":
                events.append({"ts": _ts(e), "type": "failed_" + e.get("action", "unknown"), "src": "audit"})
        events.sort(key=lambda x: x["ts"])

        # Count transitions
        transitions: dict = defaultdict(lambda: Counter())
        states = Counter()
        for i in range(len(events) - 1):
            cur = events[i]["type"]
            nxt = events[i + 1]["type"]
            # Only count if events are within 5 minutes
            if events[i + 1]["ts"] - events[i]["ts"] < 300:
                transitions[cur][nxt] += 1
                states[cur] += 1

        # Build transition probability matrix
        trans_probs = {}
        for state, nexts in transitions.items():
            total = sum(nexts.values())
            trans_probs[state] = {
                nxt: round(cnt / total, 3)
                for nxt, cnt in nexts.most_common(5)
            }

        # Identify most likely current state (last observed event type)
        current_state = events[-1]["type"] if events else None

        # Predict next likely events
        predictions = []
        if current_state and current_state in trans_probs:
            for next_state, prob in sorted(trans_probs[current_state].items(), key=lambda x: -x[1]):
                severity = "high" if prob > 0.5 else "medium" if prob > 0.2 else "low"
                predictions.append({
                    "predicted_event": next_state,
                    "probability": prob,
                    "severity": severity,
                    "description": f"Dopo '{current_state}', probabilità {prob:.0%} di '{next_state}'",
                })

        # Find most dangerous attack chains (paths of length 3)
        chains = []
        for start in list(transitions.keys())[:20]:
            for mid, p1 in list(trans_probs.get(start, {}).items())[:5]:
                for end, p2 in list(trans_probs.get(mid, {}).items())[:5]:
                    chain_prob = p1 * p2
                    if chain_prob > 0.05:
                        chains.append({
                            "chain": [start, mid, end],
                            "probability": round(chain_prob, 4),
                            "risk": "critical" if chain_prob > 0.3 else "high" if chain_prob > 0.15 else "medium",
                        })
        chains.sort(key=lambda c: -c["probability"])

        # Stationary distribution (dominant threat states)
        stationary = {}
        total_trans = sum(states.values())
        if total_trans > 0:
            stationary = {s: round(c / total_trans, 3) for s, c in states.most_common(10)}

        return {
            "current_state": current_state,
            "transition_matrix_size": len(trans_probs),
            "predictions": predictions[:10],
            "attack_chains": chains[:10],
            "stationary_distribution": stationary,
            "total_transitions": total_trans,
            "description": f"Modello Markov con {len(trans_probs)} stati e {total_trans} transizioni osservate",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 2. ISOLATION-SCORE ANOMALY DETECTION
    # ═══════════════════════════════════════════════════════════════════

    def _isolation_scores(all_logs: dict) -> dict:
        """
        Approximate Isolation Forest anomaly detection.
        Per-entity anomaly score based on statistical density: entities
        with rare feature combinations get higher isolation scores (0-1).
        """
        # Build feature vectors per entity (user/IP)
        entities: dict = defaultdict(lambda: {
            "action_count": 0, "unique_actions": set(), "failure_count": 0,
            "unique_ips": set(), "hours": Counter(), "sources": set(),
            "intervals": [], "last_ts": 0,
        })

        for source, logs in all_logs.items():
            for e in logs:
                key = e.get("user", e.get("sub", e.get("ip", "unknown")))
                ent = entities[key]
                ent["action_count"] += 1
                ent["unique_actions"].add(e.get("action", e.get("type", "?")))
                ent["sources"].add(source)
                if e.get("outcome") == "failed":
                    ent["failure_count"] += 1
                ip = e.get("ip", "")
                if ip:
                    ent["unique_ips"].add(ip)
                ts = _ts(e)
                if ts > 0:
                    ent["hours"][datetime.fromtimestamp(ts).hour] += 1
                    if ent["last_ts"] > 0:
                        ent["intervals"].append(ts - ent["last_ts"])
                    ent["last_ts"] = ts

        if not entities:
            return {"entities": [], "description": "Nessun dato disponibile"}

        # Compute feature vectors
        feature_names = [
            "action_count", "unique_actions", "failure_rate",
            "unique_ips", "hour_entropy", "avg_interval", "source_count",
        ]
        vectors = {}
        for key, ent in entities.items():
            total = max(ent["action_count"], 1)
            hr_counts = list(ent["hours"].values()) if ent["hours"] else [0]
            intervals = ent["intervals"] if ent["intervals"] else [0]
            vectors[key] = [
                ent["action_count"],
                len(ent["unique_actions"]),
                ent["failure_count"] / total,
                len(ent["unique_ips"]),
                _entropy(hr_counts),
                _mean(intervals),
                len(ent["sources"]),
            ]

        # Compute z-scores per feature
        n_features = len(feature_names)
        feature_stats = []
        for f in range(n_features):
            vals = [v[f] for v in vectors.values()]
            feature_stats.append((_mean(vals), max(_std(vals), 1e-9)))

        # Isolation score: average absolute z-score normalized to 0-1
        scored = []
        for key, vec in vectors.items():
            z_scores = []
            for f in range(n_features):
                z = abs((vec[f] - feature_stats[f][0]) / feature_stats[f][1])
                z_scores.append(z)
            raw_score = _mean(z_scores)
            # Sigmoid normalization to 0-1
            isolation_score = round(1 / (1 + math.exp(-raw_score + 2)), 3)
            is_anomaly = isolation_score > 0.65

            scored.append({
                "entity": key,
                "isolation_score": isolation_score,
                "is_anomaly": is_anomaly,
                "anomaly_level": "critical" if isolation_score > 0.85 else "high" if isolation_score > 0.75 else "medium" if isolation_score > 0.65 else "normal",
                "features": {feature_names[i]: round(vec[i], 3) for i in range(n_features)},
                "top_deviation": feature_names[max(range(n_features), key=lambda i: abs((vec[i] - feature_stats[i][0]) / feature_stats[i][1]))],
            })

        scored.sort(key=lambda x: -x["isolation_score"])
        anomaly_count = sum(1 for s in scored if s["is_anomaly"])

        return {
            "entities": scored[:30],
            "total_entities": len(scored),
            "anomaly_count": anomaly_count,
            "anomaly_rate": round(anomaly_count / max(len(scored), 1), 3),
            "feature_names": feature_names,
            "description": f"Isolation scoring su {len(scored)} entità: {anomaly_count} anomalie rilevate",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 3. TIME-SERIES DECOMPOSITION
    # ═══════════════════════════════════════════════════════════════════

    def _time_decomposition(all_logs: dict, bucket_minutes: int = 10) -> dict:
        """
        Decompose log time series into Trend + Seasonal + Residual
        using moving-average-based classical decomposition.
        """
        # Build time series
        all_ts = []
        for logs in all_logs.values():
            for e in logs:
                t = _ts(e)
                if t > 0:
                    all_ts.append(t)

        if not all_ts:
            return {"series": [], "trend": [], "seasonal": [], "residual": [], "description": "Nessun dato"}

        all_ts.sort()
        min_t = all_ts[0]
        bucket_sec = bucket_minutes * 60

        # Bucket into time intervals
        buckets: dict = defaultdict(int)
        for t in all_ts:
            buckets[(t - min_t) // bucket_sec] += 1

        max_bucket = max(buckets.keys()) if buckets else 0
        series = [buckets.get(i, 0) for i in range(max_bucket + 1)]

        if len(series) < 6:
            return {"series": series, "trend": series, "seasonal": [0] * len(series), "residual": [0] * len(series), "description": "Serie troppo corta"}

        # 1. Trend: centered moving average (window = period_guess or 6)
        period = min(max(6, len(series) // 6), 24)  # adapt window
        half = period // 2
        trend = [None] * len(series)
        for i in range(half, len(series) - half):
            window = series[i - half : i + half + 1]
            trend[i] = _mean(window)

        # Fill edges with nearest value
        first_valid = next((i for i in range(len(trend)) if trend[i] is not None), 0)
        last_valid = next((i for i in range(len(trend) - 1, -1, -1) if trend[i] is not None), len(trend) - 1)
        for i in range(first_valid):
            trend[i] = trend[first_valid]
        for i in range(last_valid + 1, len(trend)):
            trend[i] = trend[last_valid]

        # 2. Detrended = series - trend
        detrended = [series[i] - (trend[i] or 0) for i in range(len(series))]

        # 3. Seasonal component: average detrended values by position mod period
        seasonal_avg = defaultdict(list)
        for i, v in enumerate(detrended):
            seasonal_avg[i % period].append(v)
        seasonal_factors = {k: _mean(v) for k, v in seasonal_avg.items()}
        seasonal = [round(seasonal_factors.get(i % period, 0), 3) for i in range(len(series))]

        # 4. Residual = series - trend - seasonal
        residual = [round(series[i] - (trend[i] or 0) - seasonal[i], 3) for i in range(len(series))]

        # Format trend
        trend = [round(t, 3) if t is not None else 0 for t in trend]

        # Detect unusual residuals (anomalies)
        res_std = _std(residual) if residual else 1
        res_mean = _mean(residual)
        anomaly_buckets = [
            {"bucket": i, "value": series[i], "residual": residual[i], "z_score": round((residual[i] - res_mean) / max(res_std, 0.01), 2)}
            for i in range(len(residual))
            if abs(residual[i] - res_mean) > 2.5 * max(res_std, 0.01)
        ]

        # Compute seasonality strength
        var_seasonal = _var(seasonal) if seasonal else 0
        var_residual = _var(residual) if residual else 1
        seasonality_strength = round(1 - var_residual / max(var_seasonal + var_residual, 0.01), 3)

        # Trend direction
        pts = [(i, trend[i]) for i in range(len(trend))]
        slope, _, r2 = _linreg(pts)
        trend_direction = "crescente" if slope > 0.05 else "decrescente" if slope < -0.05 else "stabile"

        return {
            "series_length": len(series),
            "bucket_minutes": bucket_minutes,
            "period_detected": period,
            "trend_direction": trend_direction,
            "trend_slope": round(slope, 4),
            "trend_r2": round(r2, 3),
            "seasonality_strength": max(0, seasonality_strength),
            "anomaly_buckets": anomaly_buckets[:15],
            "total_anomaly_buckets": len(anomaly_buckets),
            "stats": {
                "mean": round(_mean(series), 2),
                "median": round(_median(series), 2),
                "std": round(_std(series), 2),
                "min": min(series),
                "max": max(series),
                "p95": round(_percentile(series, 95), 2),
            },
            # Return last 50 points for visualization
            "series_tail": series[-50:],
            "trend_tail": trend[-50:],
            "seasonal_tail": seasonal[-50:],
            "residual_tail": residual[-50:],
            "description": f"Decomposizione: trend {trend_direction} (slope={slope:.4f}, R²={r2:.2f}), "
                           f"stagionalità={max(0, seasonality_strength):.2f}, "
                           f"{len(anomaly_buckets)} bucket anomali",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 4. CROSS-SOURCE CORRELATION MATRIX
    # ═══════════════════════════════════════════════════════════════════

    def _correlation_matrix(all_logs: dict, bucket_minutes: int = 5) -> dict:
        """
        Compute Pearson cross-correlation matrix between all log sources.
        Identify causally related event streams.
        """
        bucket_sec = bucket_minutes * 60
        sources = list(all_logs.keys())

        # Build time series per source
        all_min_t = float('inf')
        all_max_t = 0
        for logs in all_logs.values():
            for e in logs:
                t = _ts(e)
                if t > 0:
                    all_min_t = min(all_min_t, t)
                    all_max_t = max(all_max_t, t)

        if all_min_t >= all_max_t:
            return {"matrix": {}, "insights": [], "description": "Dati insufficienti"}

        n_buckets = max(1, (all_max_t - int(all_min_t)) // bucket_sec + 1)
        series_map = {}
        for name, logs in all_logs.items():
            buckets = [0] * n_buckets
            for e in logs:
                t = _ts(e)
                if t > 0:
                    idx = min((t - int(all_min_t)) // bucket_sec, n_buckets - 1)
                    buckets[idx] += 1
            series_map[name] = buckets

        # Compute correlation matrix
        matrix = {}
        for s1 in sources:
            matrix[s1] = {}
            for s2 in sources:
                matrix[s1][s2] = round(_pearson(series_map[s1], series_map[s2]), 3)

        # Lagged correlations (1-bucket lag)
        lagged = {}
        for s1 in sources:
            for s2 in sources:
                if s1 == s2:
                    continue
                # s1 leads s2 by 1 bucket
                a = series_map[s1][:-1]
                b = series_map[s2][1:]
                corr = _pearson(a, b)
                if abs(corr) > 0.3:
                    lagged[f"{s1}→{s2}"] = round(corr, 3)

        # Insights
        insights = []
        for s1 in sources:
            for s2 in sources:
                if s1 >= s2:
                    continue
                r = matrix[s1][s2]
                if abs(r) > 0.7:
                    insights.append({
                        "sources": [s1, s2], "correlation": r,
                        "type": "strong_positive" if r > 0 else "strong_negative",
                        "description": f"Forte correlazione {'positiva' if r > 0 else 'negativa'} tra {s1} e {s2} (r={r:.2f})",
                    })
                elif abs(r) > 0.4:
                    insights.append({
                        "sources": [s1, s2], "correlation": r,
                        "type": "moderate",
                        "description": f"Correlazione moderata tra {s1} e {s2} (r={r:.2f})",
                    })

        for key, corr in lagged.items():
            if abs(corr) > 0.5:
                s1, s2 = key.split("→")
                insights.append({
                    "sources": [s1, s2], "correlation": corr,
                    "type": "causal_lead",
                    "description": f"{s1} precede {s2} con correlazione laggata r={corr:.2f} (possibile nesso causale)",
                })

        insights.sort(key=lambda x: -abs(x["correlation"]))

        return {
            "matrix": matrix,
            "lagged_correlations": lagged,
            "insights": insights[:15],
            "bucket_minutes": bucket_minutes,
            "n_buckets": n_buckets,
            "sources": sources,
            "description": f"Matrice {len(sources)}×{len(sources)}, {len(insights)} correlazioni significative",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 5. ENTROPY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════

    def _entropy_analysis(all_logs: dict, bucket_minutes: int = 15) -> dict:
        """
        Monitor Shannon entropy of event distributions over time.
        Sudden entropy drops = attack convergence (single pattern dominates).
        Sudden entropy spikes = exploration/scanning activity.
        """
        bucket_sec = bucket_minutes * 60
        all_events = []
        for source, logs in all_logs.items():
            for e in logs:
                t = _ts(e)
                if t > 0:
                    all_events.append({
                        "ts": t,
                        "type": e.get("type", e.get("action", e.get("event", e.get("category", "unknown")))),
                        "source": source,
                    })

        if not all_events:
            return {"windows": [], "alerts": [], "description": "Nessun dato"}

        all_events.sort(key=lambda x: x["ts"])
        min_t = all_events[0]["ts"]

        # Bucket events
        windows: dict = defaultdict(lambda: Counter())
        for ev in all_events:
            bucket = (ev["ts"] - min_t) // bucket_sec
            windows[bucket][ev["type"]] += 1

        # Compute entropy per window
        entropy_series = []
        for b in sorted(windows.keys()):
            counts = list(windows[b].values())
            h = _entropy(counts)
            n_types = len(windows[b])
            max_h = math.log2(n_types) if n_types > 1 else 1
            normalized_h = h / max_h if max_h > 0 else 0
            entropy_series.append({
                "bucket": b,
                "entropy": round(h, 3),
                "normalized_entropy": round(normalized_h, 3),
                "event_count": sum(counts),
                "unique_types": n_types,
                "dominant_type": windows[b].most_common(1)[0][0] if windows[b] else "?",
                "dominance_ratio": round(windows[b].most_common(1)[0][1] / sum(counts), 3) if counts else 0,
            })

        # Detect entropy anomalies
        entropies = [w["entropy"] for w in entropy_series]
        h_mean = _mean(entropies)
        h_std = _std(entropies) if len(entropies) > 2 else 0.01
        alerts = []
        for w in entropy_series:
            z = (w["entropy"] - h_mean) / max(h_std, 0.001)
            if z < -2:
                alerts.append({
                    "bucket": w["bucket"], "type": "entropy_drop",
                    "z_score": round(z, 2), "entropy": w["entropy"],
                    "severity": "high" if z < -3 else "medium",
                    "description": f"Crollo entropia (H={w['entropy']:.2f}, z={z:.1f}): possibile attacco convergente su '{w['dominant_type']}'",
                })
            elif z > 2.5:
                alerts.append({
                    "bucket": w["bucket"], "type": "entropy_spike",
                    "z_score": round(z, 2), "entropy": w["entropy"],
                    "severity": "medium",
                    "description": f"Picco entropia (H={w['entropy']:.2f}, z={z:.1f}): possibile attività di scanning/esplorazione",
                })

        # Overall entropy stats
        return {
            "windows": entropy_series[-40:],
            "alerts": alerts[:15],
            "total_alerts": len(alerts),
            "stats": {
                "mean_entropy": round(h_mean, 3),
                "std_entropy": round(h_std, 3),
                "min_entropy": round(min(entropies), 3) if entropies else 0,
                "max_entropy": round(max(entropies), 3) if entropies else 0,
                "current_entropy": entropy_series[-1]["entropy"] if entropy_series else 0,
            },
            "bucket_minutes": bucket_minutes,
            "total_windows": len(entropy_series),
            "description": f"Analisi entropia su {len(entropy_series)} finestre: "
                           f"H medio={h_mean:.2f}, {len(alerts)} anomalie entropiche",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 6. EWMA — EXPONENTIALLY WEIGHTED MOVING AVERAGE MONITORING
    # ═══════════════════════════════════════════════════════════════════

    def _ewma_monitor(all_logs: dict, alpha: float = 0.3, threshold_sigma: float = 2.5) -> dict:
        """
        EWMA control chart for event rate anomaly detection.
        More sensitive to recent changes than static z-score.
        UCL/LCL = EWMA ± L·σ_EWMA
        """
        # Build event rate time series (per minute)
        all_ts = []
        for logs in all_logs.values():
            for e in logs:
                t = _ts(e)
                if t > 0:
                    all_ts.append(t)

        if len(all_ts) < 10:
            return {"series": [], "violations": [], "description": "Dati insufficienti per EWMA"}

        all_ts.sort()
        min_t = all_ts[0]
        bucket_sec = 60  # 1-minute buckets

        buckets: dict = defaultdict(int)
        for t in all_ts:
            buckets[(t - min_t) // bucket_sec] += 1

        max_b = max(buckets.keys()) if buckets else 0
        raw_series = [buckets.get(i, 0) for i in range(max_b + 1)]

        if len(raw_series) < 5:
            return {"series": [], "violations": [], "description": "Serie troppo corta"}

        # Compute EWMA
        mu0 = _mean(raw_series)  # target mean
        sigma0 = _std(raw_series)  # process std
        sigma_ewma_base = sigma0 * math.sqrt(alpha / (2 - alpha)) if sigma0 > 0 else 1

        ewma = [mu0]  # initialize at target
        ucl = []
        lcl = []
        for i, x in enumerate(raw_series):
            e = alpha * x + (1 - alpha) * ewma[-1]
            ewma.append(e)
            # Control limits widen slightly then stabilize
            lam_factor = math.sqrt(1 - (1 - alpha) ** (2 * (i + 1)))
            s = sigma_ewma_base * lam_factor * threshold_sigma
            ucl.append(round(mu0 + s, 2))
            lcl.append(round(max(0, mu0 - s), 2))

        ewma = ewma[1:]  # remove initial value

        # Detect violations
        violations = []
        for i in range(len(raw_series)):
            if ewma[i] > ucl[i]:
                violations.append({
                    "minute": i, "value": raw_series[i],
                    "ewma": round(ewma[i], 2), "ucl": ucl[i],
                    "type": "upper_violation",
                    "severity": "high" if ewma[i] > ucl[i] * 1.5 else "medium",
                    "description": f"EWMA={ewma[i]:.1f} supera UCL={ucl[i]:.1f} (picco attività)",
                })
            elif ewma[i] < lcl[i] and lcl[i] > 0:
                violations.append({
                    "minute": i, "value": raw_series[i],
                    "ewma": round(ewma[i], 2), "lcl": lcl[i],
                    "type": "lower_violation",
                    "severity": "medium",
                    "description": f"EWMA={ewma[i]:.1f} sotto LCL={lcl[i]:.1f} (calo anomalo)",
                })

        return {
            "alpha": alpha,
            "threshold_sigma": threshold_sigma,
            "target_mean": round(mu0, 2),
            "process_sigma": round(sigma0, 2),
            "current_ewma": round(ewma[-1], 2) if ewma else 0,
            "current_ucl": ucl[-1] if ucl else 0,
            "current_lcl": lcl[-1] if lcl else 0,
            "in_control": len(violations) == 0,
            "violations": violations[-20:],
            "total_violations": len(violations),
            "series_tail": [{"raw": raw_series[i], "ewma": round(ewma[i], 2), "ucl": ucl[i], "lcl": lcl[i]} for i in range(max(0, len(raw_series) - 40), len(raw_series))],
            "description": f"EWMA (α={alpha}): {'in controllo' if not violations else f'{len(violations)} violazioni'}, "
                           f"media target={mu0:.1f}, σ={sigma0:.1f}",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 7. BAYESIAN RISK ESTIMATION
    # ═══════════════════════════════════════════════════════════════════

    def _bayesian_risk(all_logs: dict) -> dict:
        """
        Bayesian risk estimation using conjugate Beta-Binomial priors.
        For each risk category, compute posterior probability of threat
        given observed evidence, with credible intervals.
        """
        categories = {
            "brute_force": {"prior_a": 1, "prior_b": 10},  # initially unlikely
            "data_breach": {"prior_a": 1, "prior_b": 20},  # very rare
            "privilege_escalation": {"prior_a": 1, "prior_b": 15},
            "service_disruption": {"prior_a": 2, "prior_b": 8},  # somewhat common
            "insider_threat": {"prior_a": 1, "prior_b": 12},
        }

        # Count evidence for each category
        audit = all_logs.get("audit", [])
        security = all_logs.get("security", [])
        events = all_logs.get("events", [])

        evidence = {
            "brute_force": {
                "successes": len([e for e in audit if e.get("outcome") == "failed" and "auth" in e.get("action", "")]),
                "trials": max(len([e for e in audit if "auth" in e.get("action", "")]), 1),
            },
            "data_breach": {
                "successes": len([e for e in security if e.get("category") in ("sqli", "traversal", "ssrf")]),
                "trials": max(len(security), 1),
            },
            "privilege_escalation": {
                "successes": len([e for e in audit if e.get("outcome") == "failed" and any(k in e.get("action", "") for k in ("admin", "role", "user."))]),
                "trials": max(len(audit), 1),
            },
            "service_disruption": {
                "successes": len([e for e in events if e.get("level") in ("error", "critical")]),
                "trials": max(len(events), 1),
            },
            "insider_threat": {
                "successes": len([e for e in audit if e.get("outcome") == "failed"]),
                "trials": max(len(audit), 1),
            },
        }

        results = {}
        for cat, priors in categories.items():
            a0, b0 = priors["prior_a"], priors["prior_b"]
            ev = evidence.get(cat, {"successes": 0, "trials": 1})
            x = ev["successes"]
            n = ev["trials"]

            # Posterior: Beta(a0 + x, b0 + n - x)
            a_post = a0 + x
            b_post = b0 + n - x

            # Posterior mean
            post_mean = a_post / (a_post + b_post)

            # Credible interval (approximate percentiles using normal approximation for Beta)
            post_var = (a_post * b_post) / ((a_post + b_post) ** 2 * (a_post + b_post + 1))
            post_sd = math.sqrt(post_var) if post_var > 0 else 0.01

            ci_lower = max(0, post_mean - 1.96 * post_sd)
            ci_upper = min(1, post_mean + 1.96 * post_sd)

            # Risk level based on posterior
            risk_level = "critical" if post_mean > 0.4 else "high" if post_mean > 0.2 else "medium" if post_mean > 0.08 else "low"

            # Bayes Factor (vs prior)
            prior_mean = a0 / (a0 + b0)
            bf = post_mean / max(prior_mean, 0.001)

            results[cat] = {
                "posterior_probability": round(post_mean, 4),
                "credible_interval": [round(ci_lower, 4), round(ci_upper, 4)],
                "prior_probability": round(prior_mean, 4),
                "bayes_factor": round(bf, 2),
                "evidence_count": x,
                "total_observations": n,
                "risk_level": risk_level,
                "posterior_params": {"alpha": a_post, "beta": b_post},
                "description": f"P({cat})={post_mean:.1%} (CI 95%: {ci_lower:.1%}–{ci_upper:.1%}), BF={bf:.1f}x",
            }

        # Overall Bayesian risk
        overall = _mean([r["posterior_probability"] for r in results.values()])
        max_risk = max(results.values(), key=lambda r: r["posterior_probability"])

        return {
            "categories": results,
            "overall_bayesian_risk": round(overall, 4),
            "highest_risk_category": next(k for k, v in results.items() if v == max_risk),
            "description": f"Rischio Bayesiano complessivo: {overall:.1%}. "
                           f"Categoria più a rischio: {next(k for k, v in results.items() if v == max_risk)} "
                           f"(P={max_risk['posterior_probability']:.1%})",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 8. KNN PATTERN MATCHING
    # ═══════════════════════════════════════════════════════════════════

    def _knn_pattern_match(all_logs: dict, k: int = 5) -> dict:
        """
        K-Nearest Neighbors pattern matching: compare current activity
        window against historical windows to find similar patterns.
        Useful for detecting recurring attack patterns.
        """
        # Build historical windows (1-hour segments)
        window_sec = 3600
        all_events = []
        for source, logs in all_logs.items():
            for e in logs:
                t = _ts(e)
                if t > 0:
                    all_events.append({
                        "ts": t, "source": source,
                        "type": e.get("type", e.get("action", e.get("event", "?"))),
                        "outcome": e.get("outcome", e.get("level", "info")),
                    })

        if not all_events:
            return {"current_window": {}, "neighbors": [], "description": "Nessun dato"}

        all_events.sort(key=lambda x: x["ts"])
        min_t = all_events[0]["ts"]
        max_t = all_events[-1]["ts"]

        # Create windows
        windows = []
        t = min_t
        while t < max_t:
            w_events = [e for e in all_events if t <= e["ts"] < t + window_sec]
            if w_events:
                feature = _window_features(w_events)
                feature["start_ts"] = t
                feature["end_ts"] = t + window_sec
                windows.append(feature)
            t += window_sec

        if len(windows) < 2:
            return {"current_window": windows[0] if windows else {}, "neighbors": [], "description": "Finestre storiche insufficienti"}

        # Current window is the last one
        current = windows[-1]
        historical = windows[:-1]

        # Compute distances
        feature_keys = ["event_count", "failure_rate", "entropy", "source_diversity", "event_diversity"]
        cur_vec = [current.get(f, 0) for f in feature_keys]

        distances = []
        for i, hw in enumerate(historical):
            hw_vec = [hw.get(f, 0) for f in feature_keys]
            # Euclidean distance (normalized)
            dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(cur_vec, hw_vec)))
            sim = round(1 / (1 + dist), 3)
            distances.append({
                "window_index": i,
                "start_ts": hw.get("start_ts", 0),
                "similarity": sim,
                "distance": round(dist, 3),
                "features": {f: round(hw.get(f, 0), 3) for f in feature_keys},
            })

        distances.sort(key=lambda d: d["distance"])

        # K nearest neighbors
        neighbors = distances[:k]

        # Majority vote on "is_anomalous" (high failure rate or unusual patterns)
        anomalous_neighbors = sum(1 for n in neighbors if historical[n["window_index"]].get("failure_rate", 0) > 0.3)
        pattern_type = "anomalous" if anomalous_neighbors > k // 2 else "normal"

        # Find the most similar historical pattern
        most_similar = neighbors[0] if neighbors else None

        return {
            "current_window": {f: round(current.get(f, 0), 3) for f in feature_keys},
            "current_ts": current.get("start_ts", 0),
            "k": k,
            "neighbors": neighbors,
            "pattern_classification": pattern_type,
            "anomalous_neighbor_ratio": round(anomalous_neighbors / max(k, 1), 2),
            "most_similar": most_similar,
            "total_historical_windows": len(historical),
            "description": f"KNN (k={k}): pattern attuale classificato come '{pattern_type}', "
                           f"similarità max={neighbors[0]['similarity']:.2f}" if neighbors else "Nessun vicino trovato",
        }

    def _window_features(events: list) -> dict:
        """Extract statistical features from a time window of events."""
        n = len(events)
        if n == 0:
            return {"event_count": 0, "failure_rate": 0, "entropy": 0, "source_diversity": 0, "event_diversity": 0}

        failures = sum(1 for e in events if e.get("outcome") in ("failed", "error", "critical", "blocked"))
        types = Counter(e["type"] for e in events)
        sources = Counter(e["source"] for e in events)

        return {
            "event_count": n,
            "failure_rate": round(failures / n, 3),
            "entropy": round(_entropy(list(types.values())), 3),
            "source_diversity": len(sources),
            "event_diversity": len(types),
            "dominant_type": types.most_common(1)[0][0] if types else "?",
            "dominant_source": sources.most_common(1)[0][0] if sources else "?",
        }

    # ═══════════════════════════════════════════════════════════════════
    # 9. LEARNING & BASELINE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════

    def _update_baseline(all_logs: dict) -> dict:
        """
        Build and update learned baseline: event rate profiles, entropy
        baselines, behavioral fingerprints.  Used by other algorithms
        to detect deviation from normal.
        """
        learn = _load_learn()
        learn.setdefault("baselines", {})
        learn.setdefault("updated_at", 0)

        # Event rate per source
        for source, logs in all_logs.items():
            ts_list = sorted([_ts(e) for e in logs if _ts(e) > 0])
            if len(ts_list) >= 2:
                span = max(ts_list[-1] - ts_list[0], 1)
                rate = len(ts_list) / (span / 3600)  # events per hour
            else:
                rate = len(ts_list)
            baseline = learn["baselines"].setdefault(source, {"rates": [], "entropy_history": []})
            baseline["rates"].append(round(rate, 2))
            baseline["rates"] = baseline["rates"][-50:]  # keep last 50 samples

            # Entropy baseline
            types = Counter(e.get("type", e.get("action", "?")) for e in logs)
            h = _entropy(list(types.values())) if types else 0
            baseline["entropy_history"].append(round(h, 3))
            baseline["entropy_history"] = baseline["entropy_history"][-50:]

        learn["updated_at"] = int(time.time())
        _save_learn(learn)

        # Compute deviation from baseline
        deviations = {}
        for source, bl in learn["baselines"].items():
            rates = bl.get("rates", [])
            if len(rates) >= 3:
                current_rate = rates[-1]
                hist_mean = _mean(rates[:-1])
                hist_std = _std(rates[:-1])
                z_rate = (current_rate - hist_mean) / max(hist_std, 0.01)
            else:
                z_rate = 0
            ents = bl.get("entropy_history", [])
            if len(ents) >= 3:
                z_ent = (ents[-1] - _mean(ents[:-1])) / max(_std(ents[:-1]), 0.01)
            else:
                z_ent = 0
            status = "anomalous" if abs(z_rate) > 2.5 or abs(z_ent) > 2.5 else "warning" if abs(z_rate) > 1.5 or abs(z_ent) > 1.5 else "normal"
            deviations[source] = {
                "rate_z_score": round(z_rate, 2),
                "entropy_z_score": round(z_ent, 2),
                "current_rate": rates[-1] if rates else 0,
                "baseline_rate_mean": round(_mean(rates[:-1]), 2) if len(rates) > 1 else 0,
                "status": status,
            }

        return {
            "deviations": deviations,
            "baseline_samples": {s: len(bl.get("rates", [])) for s, bl in learn["baselines"].items()},
            "last_updated": learn["updated_at"],
            "description": f"Baseline aggiornata per {len(learn['baselines'])} sorgenti",
        }

    # ═══════════════════════════════════════════════════════════════════
    # ENDPOINTS
    # ═══════════════════════════════════════════════════════════════════

    @app.get("/ai/advanced/markov-prediction")
    async def ep_markov(limit: int = Query(1000, ge=50, le=5000), _u=Depends(require_admin)):
        """Markov chain attack sequence prediction."""
        sec = _read_log(LOG_FILES["security"], limit)
        aud = _read_log(LOG_FILES["audit"], limit)
        return _markov_prediction(sec, aud)

    @app.get("/ai/advanced/anomaly-scores")
    async def ep_isolation(limit: int = Query(1000, ge=50, le=5000), _u=Depends(require_admin)):
        """Isolation-score anomaly detection per entity."""
        return _isolation_scores(_read_all(limit))

    @app.get("/ai/advanced/time-decomposition")
    async def ep_decomp(
        limit: int = Query(1500, ge=100, le=5000),
        bucket: int = Query(10, ge=1, le=60),
        _u=Depends(require_admin),
    ):
        """Time-series decomposition: trend + seasonal + residual."""
        return _time_decomposition(_read_all(limit), bucket)

    @app.get("/ai/advanced/correlation-matrix")
    async def ep_corr(
        limit: int = Query(1500, ge=100, le=5000),
        bucket: int = Query(5, ge=1, le=60),
        _u=Depends(require_admin),
    ):
        """Cross-source Pearson correlation matrix with lagged analysis."""
        return _correlation_matrix(_read_all(limit), bucket)

    @app.get("/ai/advanced/entropy-analysis")
    async def ep_entropy(
        limit: int = Query(1500, ge=100, le=5000),
        bucket: int = Query(15, ge=1, le=120),
        _u=Depends(require_admin),
    ):
        """Shannon entropy monitoring with anomaly detection."""
        return _entropy_analysis(_read_all(limit), bucket)

    @app.get("/ai/advanced/ewma-monitor")
    async def ep_ewma(
        limit: int = Query(1500, ge=100, le=5000),
        alpha: float = Query(0.3, ge=0.05, le=0.95),
        threshold: float = Query(2.5, ge=1.0, le=5.0),
        _u=Depends(require_admin),
    ):
        """EWMA control chart monitoring."""
        return _ewma_monitor(_read_all(limit), alpha, threshold)

    @app.get("/ai/advanced/bayesian-risk")
    async def ep_bayesian(limit: int = Query(1000, ge=50, le=5000), _u=Depends(require_admin)):
        """Bayesian risk estimation with credible intervals."""
        return _bayesian_risk(_read_all(limit))

    @app.get("/ai/advanced/pattern-match")
    async def ep_knn(
        limit: int = Query(1500, ge=100, le=5000),
        k: int = Query(5, ge=1, le=20),
        _u=Depends(require_admin),
    ):
        """KNN-based historical pattern matching."""
        return _knn_pattern_match(_read_all(limit), k)

    @app.get("/ai/advanced/baseline")
    async def ep_baseline(limit: int = Query(1000, ge=50, le=5000), _u=Depends(require_admin)):
        """Update and query learned baseline with deviation analysis."""
        return _update_baseline(_read_all(limit))

    @app.get("/ai/advanced/full-report")
    async def ep_full_report(limit: int = Query(1000, ge=50, le=3000), _u=Depends(require_admin)):
        """Comprehensive advanced AI report combining all algorithms."""
        all_logs = _read_all(limit)
        sec = all_logs.get("security", [])
        aud = all_logs.get("audit", [])

        markov = _markov_prediction(sec, aud)
        isolation = _isolation_scores(all_logs)
        decomp = _time_decomposition(all_logs)
        corr = _correlation_matrix(all_logs)
        entropy = _entropy_analysis(all_logs)
        ewma = _ewma_monitor(all_logs)
        bayesian = _bayesian_risk(all_logs)
        knn = _knn_pattern_match(all_logs)
        baseline = _update_baseline(all_logs)

        # Composite threat intelligence score (0-100)
        threat_signals = [
            min(100, len(markov.get("predictions", [])) * 10),
            min(100, isolation.get("anomaly_count", 0) * 15),
            min(100, decomp.get("total_anomaly_buckets", 0) * 8),
            min(100, entropy.get("total_alerts", 0) * 12),
            min(100, ewma.get("total_violations", 0) * 8),
            min(100, bayesian.get("overall_bayesian_risk", 0) * 200),
            50 if knn.get("pattern_classification") == "anomalous" else 0,
        ]
        composite_score = round(_mean(threat_signals), 1)
        risk_level = (
            "critical" if composite_score > 60 else
            "high" if composite_score > 40 else
            "medium" if composite_score > 20 else "low"
        )

        # Generate Italian NL summary
        parts = []
        if composite_score >= 60:
            parts.append(f"🔴 RISCHIO CRITICO ({composite_score}/100).")
        elif composite_score >= 40:
            parts.append(f"⚠ Rischio elevato ({composite_score}/100).")
        elif composite_score >= 20:
            parts.append(f"📊 Rischio moderato ({composite_score}/100).")
        else:
            parts.append(f"✅ Situazione sotto controllo ({composite_score}/100).")

        if markov.get("predictions"):
            parts.append(f"Catena di Markov prevede {len(markov['predictions'])} prossimi eventi probabili.")
        if isolation.get("anomaly_count", 0) > 0:
            parts.append(f"Isolation scoring rileva {isolation['anomaly_count']} entità anomale.")
        if entropy.get("total_alerts", 0) > 0:
            parts.append(f"Analisi entropia: {entropy['total_alerts']} variazioni anomale.")
        if not ewma.get("in_control", True):
            parts.append(f"EWMA: processo fuori controllo ({ewma.get('total_violations', 0)} violazioni).")
        br = bayesian.get("highest_risk_category", "?")
        bp = bayesian.get("categories", {}).get(br, {}).get("posterior_probability", 0)
        if bp > 0.15:
            parts.append(f"Bayesiano: rischio '{br}' al {bp:.0%}.")

        return {
            "composite_threat_score": composite_score,
            "risk_level": risk_level,
            "summary": " ".join(parts),
            "algorithms": {
                "markov": {"predictions_count": len(markov.get("predictions", [])), "chains_count": len(markov.get("attack_chains", []))},
                "isolation": {"anomaly_count": isolation.get("anomaly_count", 0), "anomaly_rate": isolation.get("anomaly_rate", 0)},
                "decomposition": {"trend": decomp.get("trend_direction", "?"), "seasonality": decomp.get("seasonality_strength", 0), "anomaly_buckets": decomp.get("total_anomaly_buckets", 0)},
                "correlation": {"insights_count": len(corr.get("insights", []))},
                "entropy": {"mean": entropy.get("stats", {}).get("mean_entropy", 0), "alerts": entropy.get("total_alerts", 0)},
                "ewma": {"in_control": ewma.get("in_control", True), "violations": ewma.get("total_violations", 0)},
                "bayesian": {"overall_risk": bayesian.get("overall_bayesian_risk", 0), "top_category": br},
                "knn": {"pattern": knn.get("pattern_classification", "?"), "anomalous_ratio": knn.get("anomalous_neighbor_ratio", 0)},
                "baseline": {"status": {s: d.get("status", "?") for s, d in baseline.get("deviations", {}).items()}},
            },
            "analyzed_at": int(time.time()),
            "engines_versions": "advanced_ai_engine v1.0.0",
        }
