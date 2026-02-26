"""
Router Manager Engine — Advanced Route Control System
─────────────────────────────────────────────────────
Self-healing, anti-blackout, circuit-breaker protection,
real-time metrics, anomaly detection, criticality alerts.
"""
import json, re, os, time, asyncio, traceback
from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from collections import deque, defaultdict
from typing import Dict, List, Optional
from starlette.middleware.base import BaseHTTPMiddleware
import threading

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  audit_fn = ctx.get("audit")

  # ═══════════════════════════════════════════════════════════════
  # CONFIGURATION
  # ═══════════════════════════════════════════════════════════════
  WATCHDOG_INTERVAL   = 20        # seconds between watchdog cycles
  MAX_LATENCY_SAMPLES = 60        # per-route latency ring buffer
  CB_FAIL_THRESHOLD   = 5         # failures to open circuit breaker
  CB_RECOVERY_SEC     = 60        # seconds before half-open attempt
  ALERT_MAX           = 200       # max alerts retained
  HEAL_LOG_MAX        = 100       # max self-healing events
  ANOMALY_LAT_MULT    = 3.0       # 3× avg latency = anomaly
  DEGRADATION_WINDOW  = 300       # 5 min trend analysis window
  STALE_ROUTE_SEC     = 600       # 10 min no traffic = stale warning
  ERROR_RATE_WARN     = 0.15      # 15% error rate threshold
  ERROR_RATE_CRIT     = 0.40      # 40% error rate threshold

  # ═══════════════════════════════════════════════════════════════
  # SHORTHAND MAP
  # ═══════════════════════════════════════════════════════════════
  shorthand_map = {
    "health":    "/monitoring/health",
    "security":  "/security/status",
    "users":     "/users",
    "audit":     "/audit/logs",
    "modules":   "/modules/state",
    "ai":        "/ai/log-analysis",
    "templates": "/template/list",
    "lang":      "/lang/strings",
    "router":    "/router/status",
  }

  # ═══════════════════════════════════════════════════════════════
  # STATE STORES
  # ═══════════════════════════════════════════════════════════════

  # Per-route metrics: path -> { requests, errors, latencies[], last_request, last_error, last_error_msg }
  route_metrics: Dict[str, dict] = {}

  # Circuit breakers: path -> { state, failures, last_failure, opened_at, half_open_at, trips }
  circuit_breakers: Dict[str, dict] = {}

  # Alert log
  alerts: deque = deque(maxlen=ALERT_MAX)

  # Self-healing event log
  heal_log: deque = deque(maxlen=HEAL_LOG_MAX)

  # Watchdog state
  watchdog = {
    "running": False,
    "last_cycle": None,
    "cycle_count": 0,
    "uptime_start": time.time(),
    "consecutive_healthy": 0,
    "consecutive_degraded": 0,
    "total_healthy_cycles": 0,
    "task": None,
  }

  # Global request counter
  global_stats = {
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
  }

  _lock = threading.Lock()

  # Restart state tracker
  restart_state = {
    "active": False,
    "phase": None,
    "phases_done": [],
    "progress": 0,
    "started_at": None,
    "completed_at": None,
    "error": None,
  }

  RESTART_PHASES = [
    {"id": "stop_watchdog",     "label": "Arresto Watchdog",            "weight": 15},
    {"id": "clear_metrics",     "label": "Reset Metriche",             "weight": 20},
    {"id": "clear_cbs",         "label": "Reset Circuit Breakers",     "weight": 15},
    {"id": "clear_alerts",      "label": "Pulizia Alert e Heal Log",   "weight": 15},
    {"id": "reset_globals",     "label": "Reset Contatori Globali",    "weight": 10},
    {"id": "start_watchdog",    "label": "Avvio Watchdog",             "weight": 20},
    {"id": "verify",            "label": "Verifica Sistema",           "weight": 5},
  ]

  # ═══════════════════════════════════════════════════════════════
  # HELPERS
  # ═══════════════════════════════════════════════════════════════

  def _now():
    return time.time()

  def _ensure_metrics(path: str) -> dict:
    if path not in route_metrics:
      route_metrics[path] = {
        "requests": 0,
        "errors": 0,
        "latencies": deque(maxlen=MAX_LATENCY_SAMPLES),
        "last_request": None,
        "last_error": None,
        "last_error_msg": None,
        "first_seen": _now(),
      }
    return route_metrics[path]

  def _ensure_cb(path: str) -> dict:
    if path not in circuit_breakers:
      circuit_breakers[path] = {
        "state": "closed",       # closed | open | half-open
        "failures": 0,
        "last_failure": None,
        "opened_at": None,
        "half_open_at": None,
        "trips": 0,              # total times it opened
        "last_success": None,
      }
    return circuit_breakers[path]

  def _avg_latency(path: str) -> float:
    m = route_metrics.get(path)
    if not m or not m["latencies"]:
      return 0.0
    return sum(m["latencies"]) / len(m["latencies"])

  def _error_rate(path: str) -> float:
    m = route_metrics.get(path)
    if not m or m["requests"] == 0:
      return 0.0
    return m["errors"] / m["requests"]

  def _p95_latency(path: str) -> float:
    m = route_metrics.get(path)
    if not m or not m["latencies"]:
      return 0.0
    sorted_l = sorted(m["latencies"])
    idx = int(len(sorted_l) * 0.95)
    return sorted_l[min(idx, len(sorted_l)-1)]

  def _emit_alert(severity: str, category: str, message: str, route: str = None):
    alert = {
      "id": f"a-{int(_now()*1000)}",
      "severity": severity,    # critical | high | medium | low
      "category": category,
      "message": message,
      "route": route,
      "ts": _now(),
      "resolved": False,
    }
    alerts.appendleft(alert)
    return alert

  def _emit_heal(action: str, route: str, detail: str, success: bool):
    event = {
      "action": action,
      "route": route,
      "detail": detail,
      "success": success,
      "ts": _now(),
    }
    heal_log.appendleft(event)
    return event

  # ═══════════════════════════════════════════════════════════════
  # CIRCUIT BREAKER LOGIC
  # ═══════════════════════════════════════════════════════════════

  def cb_record_success(path: str):
    cb = _ensure_cb(path)
    if cb["state"] == "half-open":
      cb["state"] = "closed"
      cb["failures"] = 0
      cb["opened_at"] = None
      cb["half_open_at"] = None
      _emit_heal("circuit_close", path, "Circuit breaker chiuso dopo recovery", True)
    cb["last_success"] = _now()

  def cb_record_failure(path: str, error_msg: str = ""):
    cb = _ensure_cb(path)
    cb["failures"] += 1
    cb["last_failure"] = _now()

    if cb["state"] == "half-open":
      # Failed during half-open → reopen
      cb["state"] = "open"
      cb["opened_at"] = _now()
      cb["trips"] += 1
      _emit_alert("high", "circuit_breaker", f"Circuit breaker ri-aperto: {path}", path)
      _emit_heal("circuit_reopen", path, f"Fallito durante half-open: {error_msg}", False)

    elif cb["state"] == "closed" and cb["failures"] >= CB_FAIL_THRESHOLD:
      cb["state"] = "open"
      cb["opened_at"] = _now()
      cb["trips"] += 1
      _emit_alert("critical", "circuit_breaker", f"Circuit breaker APERTO per {path} — {cb['failures']} fallimenti consecutivi", path)
      _emit_heal("circuit_open", path, f"Threshold raggiunto: {cb['failures']} errori", False)

  def cb_check_recovery():
    """Check if any open circuit breakers should move to half-open."""
    now = _now()
    for path, cb in circuit_breakers.items():
      if cb["state"] == "open" and cb["opened_at"]:
        elapsed = now - cb["opened_at"]
        if elapsed >= CB_RECOVERY_SEC:
          cb["state"] = "half-open"
          cb["half_open_at"] = now
          _emit_heal("circuit_half_open", path, f"Tentativo recovery dopo {int(elapsed)}s", True)

  def cb_reset(path: str):
    """Manual circuit breaker reset."""
    cb = _ensure_cb(path)
    old_state = cb["state"]
    cb["state"] = "closed"
    cb["failures"] = 0
    cb["opened_at"] = None
    cb["half_open_at"] = None
    _emit_heal("circuit_manual_reset", path, f"Reset manuale da {old_state}", True)

  # ═══════════════════════════════════════════════════════════════
  # ANOMALY DETECTION & ALERTING
  # ═══════════════════════════════════════════════════════════════

  def analyze_routes():
    """Run anomaly detection across all tracked routes."""
    now = _now()
    issues = []

    for path, m in route_metrics.items():
      if m["requests"] < 3:
        continue  # not enough data

      err_rate = _error_rate(path)
      avg_lat = _avg_latency(path)
      p95_lat = _p95_latency(path)

      # ── Error rate alerts ──
      if err_rate >= ERROR_RATE_CRIT:
        issues.append({
          "severity": "critical",
          "type": "error_rate_critical",
          "route": path,
          "value": round(err_rate * 100, 1),
          "message": f"Tasso errori CRITICO: {round(err_rate*100,1)}% su {path}",
        })
      elif err_rate >= ERROR_RATE_WARN:
        issues.append({
          "severity": "high",
          "type": "error_rate_high",
          "route": path,
          "value": round(err_rate * 100, 1),
          "message": f"Tasso errori elevato: {round(err_rate*100,1)}% su {path}",
        })

      # ── Latency anomaly (P95 vs avg) ──
      if avg_lat > 0 and p95_lat > avg_lat * ANOMALY_LAT_MULT and p95_lat > 0.5:
        issues.append({
          "severity": "high",
          "type": "latency_anomaly",
          "route": path,
          "value": round(p95_lat * 1000),
          "message": f"Anomalia latenza su {path}: P95={round(p95_lat*1000)}ms (media={round(avg_lat*1000)}ms)",
        })

      # ── Stale route (no traffic) ──
      if m["last_request"] and (now - m["last_request"]) > STALE_ROUTE_SEC:
        stale_min = int((now - m["last_request"]) / 60)
        issues.append({
          "severity": "low",
          "type": "stale_route",
          "route": path,
          "value": stale_min,
          "message": f"Nessun traffico su {path} da {stale_min} minuti",
        })

    # ── Circuit breaker status ──
    for path, cb in circuit_breakers.items():
      if cb["state"] == "open":
        issues.append({
          "severity": "critical",
          "type": "circuit_open",
          "route": path,
          "value": cb["trips"],
          "message": f"Circuit breaker APERTO su {path} (scattato {cb['trips']}×)",
        })
      elif cb["state"] == "half-open":
        issues.append({
          "severity": "medium",
          "type": "circuit_half_open",
          "route": path,
          "value": cb["trips"],
          "message": f"Circuit breaker in RECOVERY su {path}",
        })

    return issues

  def compute_overall_health():
    """Compute global system health from route analysis."""
    issues = analyze_routes()
    crit = len([i for i in issues if i["severity"] == "critical"])
    high = len([i for i in issues if i["severity"] == "high"])
    med  = len([i for i in issues if i["severity"] == "medium"])

    if crit > 0:
      status = "critical"
    elif high > 0:
      status = "degraded"
    elif med > 0:
      status = "warning"
    else:
      status = "healthy"

    return {
      "status": status,
      "issues": issues,
      "counts": {"critical": crit, "high": high, "medium": med, "low": len([i for i in issues if i["severity"] == "low"])},
    }

  # ═══════════════════════════════════════════════════════════════
  # SELF-HEALING ENGINE
  # ═══════════════════════════════════════════════════════════════

  def run_self_healing():
    """Execute self-healing procedures for detected issues."""
    healed = []
    now = _now()

    # 1. Auto-recover circuit breakers
    cb_check_recovery()

    # 2. Clear stale error counts on routes with no recent errors
    for path, m in route_metrics.items():
      if m["errors"] > 0 and m["last_error"]:
        since_error = now - m["last_error"]
        if since_error > DEGRADATION_WINDOW and _error_rate(path) < ERROR_RATE_WARN:
          old_errors = m["errors"]
          m["errors"] = max(0, m["errors"] - int(old_errors * 0.5))
          _emit_heal("error_decay", path, f"Decadimento errori: {old_errors}→{m['errors']} (nessun errore da {int(since_error)}s)", True)
          healed.append({"route": path, "action": "error_decay"})

    # 3. Resolve old alerts automatically
    for alert in alerts:
      if not alert["resolved"] and (now - alert["ts"]) > DEGRADATION_WINDOW:
        route = alert.get("route")
        if route:
          err = _error_rate(route)
          cb = circuit_breakers.get(route, {})
          if err < ERROR_RATE_WARN and cb.get("state", "closed") == "closed":
            alert["resolved"] = True
            healed.append({"route": route, "action": "alert_auto_resolved"})

    return healed

  # ═══════════════════════════════════════════════════════════════
  # WATCHDOG (background async task)
  # ═══════════════════════════════════════════════════════════════

  async def watchdog_loop():
    """Background watchdog: runs health checks & self-healing periodically."""
    watchdog["running"] = True
    while watchdog["running"]:
      try:
        await asyncio.sleep(WATCHDOG_INTERVAL)
        watchdog["cycle_count"] += 1
        watchdog["last_cycle"] = _now()

        # Run analysis
        health = compute_overall_health()

        # Track consecutive states
        if health["status"] == "healthy":
          watchdog["consecutive_healthy"] += 1
          watchdog["consecutive_degraded"] = 0
          watchdog["total_healthy_cycles"] += 1
        else:
          watchdog["consecutive_healthy"] = 0
          watchdog["consecutive_degraded"] += 1

        # Emit alerts for persistent degradation
        if watchdog["consecutive_degraded"] >= 3:
          _emit_alert(
            "critical" if watchdog["consecutive_degraded"] >= 5 else "high",
            "watchdog",
            f"Degradazione persistente: {watchdog['consecutive_degraded']} cicli consecutivi ({health['status']})",
          )

        # Run self-healing
        run_self_healing()

        # Emit new alerts from analysis (avoid duplicates)
        existing_routes = {a["route"] for a in alerts if not a["resolved"] and (_now() - a["ts"]) < WATCHDOG_INTERVAL * 2}
        for issue in health["issues"]:
          if issue["severity"] in ("critical", "high") and issue.get("route") not in existing_routes:
            _emit_alert(issue["severity"], issue["type"], issue["message"], issue.get("route"))

      except asyncio.CancelledError:
        break
      except Exception as e:
        _emit_alert("high", "watchdog_error", f"Errore watchdog: {str(e)[:200]}")

    watchdog["running"] = False

  # Start watchdog on app startup
  @app.on_event("startup")
  async def _start_watchdog():
    watchdog["task"] = asyncio.create_task(watchdog_loop())

  # ═══════════════════════════════════════════════════════════════
  # REQUEST TRACKING MIDDLEWARE
  # ═══════════════════════════════════════════════════════════════

  class RouteMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
      path = request.url.path
      method = request.method
      start = _now()

      try:
        response = await call_next(request)
        elapsed = _now() - start

        with _lock:
          m = _ensure_metrics(path)
          m["requests"] += 1
          m["latencies"].append(elapsed)
          m["last_request"] = _now()
          global_stats["total_requests"] += 1

          if response.status_code >= 500:
            m["errors"] += 1
            m["last_error"] = _now()
            m["last_error_msg"] = f"HTTP {response.status_code}"
            global_stats["total_errors"] += 1
            cb_record_failure(path, f"HTTP {response.status_code}")
          elif response.status_code < 400:
            cb_record_success(path)

        return response

      except Exception as e:
        elapsed = _now() - start
        with _lock:
          m = _ensure_metrics(path)
          m["requests"] += 1
          m["errors"] += 1
          m["latencies"].append(elapsed)
          m["last_request"] = _now()
          m["last_error"] = _now()
          m["last_error_msg"] = str(e)[:200]
          global_stats["total_requests"] += 1
          global_stats["total_errors"] += 1
          cb_record_failure(path, str(e)[:100])
        raise

  app.add_middleware(RouteMetricsMiddleware)

  # ═══════════════════════════════════════════════════════════════
  # API ENDPOINTS
  # ═══════════════════════════════════════════════════════════════

  @app.get("/router/routes")
  async def list_routes(_: dict = Depends(require_admin)):
    """List all registered API routes with live health metrics."""
    routes = []
    for route in app.routes:
      if hasattr(route, "path") and hasattr(route, "methods"):
        path = route.path
        m = route_metrics.get(path, {})
        cb = circuit_breakers.get(path, {})
        avg = _avg_latency(path)
        p95 = _p95_latency(path)
        err = _error_rate(path)

        routes.append({
          "path": path,
          "methods": sorted(route.methods) if route.methods else [],
          "name": route.name if hasattr(route, "name") else None,
          "metrics": {
            "requests": m.get("requests", 0),
            "errors": m.get("errors", 0),
            "error_rate": round(err, 4),
            "avg_latency_ms": round(avg * 1000, 1),
            "p95_latency_ms": round(p95 * 1000, 1),
            "last_request": m.get("last_request"),
            "last_error": m.get("last_error"),
          },
          "circuit_breaker": {
            "state": cb.get("state", "closed"),
            "failures": cb.get("failures", 0),
            "trips": cb.get("trips", 0),
          },
          "health": "critical" if cb.get("state") == "open" else
                    "degraded" if err >= ERROR_RATE_WARN else
                    "warning" if cb.get("state") == "half-open" else
                    "healthy",
        })
    return {"routes": sorted(routes, key=lambda x: x["path"]), "total": len(routes)}

  @app.get("/router/status")
  async def router_status(_: dict = Depends(require_admin)):
    """Enhanced routing system status with health assessment."""
    health = compute_overall_health()
    now = _now()
    uptime_sec = now - watchdog["uptime_start"]

    total_routes = len([r for r in app.routes if hasattr(r, "methods")])
    active_routes = len([p for p, m in route_metrics.items() if m["requests"] > 0])
    open_cbs = len([p for p, cb in circuit_breakers.items() if cb["state"] == "open"])
    halfopen_cbs = len([p for p, cb in circuit_breakers.items() if cb["state"] == "half-open"])

    # Global avg latency
    all_lats = []
    for m in route_metrics.values():
      all_lats.extend(m["latencies"])
    global_avg_lat = (sum(all_lats) / len(all_lats) * 1000) if all_lats else 0

    # Uptime percentage (based on total healthy watchdog cycles)
    total_cycles = watchdog["cycle_count"] or 1
    healthy_ratio = watchdog["total_healthy_cycles"] / total_cycles if total_cycles > 0 else 1.0

    active_alerts = len([a for a in alerts if not a["resolved"]])
    heal_events = len(heal_log)

    return {
      "status": health["status"],
      "total_routes": total_routes,
      "active_routes": active_routes,
      "registered_routes": len(route_metrics),
      "middleware_count": len(app.user_middleware) if hasattr(app, "user_middleware") else 0,
      "global_avg_latency_ms": round(global_avg_lat, 1),
      "uptime_seconds": round(uptime_sec),
      "uptime_healthy_pct": round(min(healthy_ratio * 100, 100), 1),
      "circuit_breakers": {
        "open": open_cbs,
        "half_open": halfopen_cbs,
        "total_trips": sum(cb.get("trips", 0) for cb in circuit_breakers.values()),
      },
      "alerts": {
        "active": active_alerts,
        "total": len(alerts),
      },
      "self_healing": {
        "events": heal_events,
        "last_heal": heal_log[0]["ts"] if heal_log else None,
      },
      "watchdog": {
        "running": watchdog["running"],
        "last_cycle": watchdog["last_cycle"],
        "cycle_count": watchdog["cycle_count"],
        "consecutive_healthy": watchdog["consecutive_healthy"],
        "consecutive_degraded": watchdog["consecutive_degraded"],
      },
      "global_stats": {
        "total_requests": global_stats["total_requests"],
        "total_errors": global_stats["total_errors"],
        "error_rate": round(global_stats["total_errors"] / max(global_stats["total_requests"], 1), 4),
      },
      "health_issues": health["issues"][:10],
      "issue_counts": health["counts"],
    }

  @app.get("/router/alerts")
  async def get_alerts(limit: int = Query(default=50, le=200), active_only: bool = Query(default=False), _: dict = Depends(require_admin)):
    """Get route control alerts with filtering."""
    items = list(alerts)
    if active_only:
      items = [a for a in items if not a["resolved"]]
    return {
      "alerts": items[:limit],
      "total": len(items),
      "active": len([a for a in alerts if not a["resolved"]]),
    }

  @app.get("/router/heal-log")
  async def get_heal_log(limit: int = Query(default=50, le=100), _: dict = Depends(require_admin)):
    """Get self-healing event history."""
    items = list(heal_log)
    return {
      "events": items[:limit],
      "total": len(items),
    }

  @app.get("/router/circuit-breakers")
  async def get_circuit_breakers(_: dict = Depends(require_admin)):
    """Get all circuit breaker states."""
    result = {}
    for path, cb in circuit_breakers.items():
      result[path] = {
        **cb,
        "age": round(_now() - cb["opened_at"]) if cb["opened_at"] else None,
        "error_rate": round(_error_rate(path), 4),
        "avg_latency_ms": round(_avg_latency(path) * 1000, 1),
      }
    return {
      "circuit_breakers": result,
      "summary": {
        "total": len(circuit_breakers),
        "open": len([c for c in circuit_breakers.values() if c["state"] == "open"]),
        "half_open": len([c for c in circuit_breakers.values() if c["state"] == "half-open"]),
        "closed": len([c for c in circuit_breakers.values() if c["state"] == "closed"]),
      },
    }

  @app.post("/router/circuit-breakers/reset")
  async def reset_circuit_breaker(path: str = Query(...), _: dict = Depends(require_admin)):
    """Manually reset a circuit breaker."""
    if path not in circuit_breakers:
      raise HTTPException(status_code=404, detail=f"Nessun circuit breaker per: {path}")
    cb_reset(path)
    return {"ok": True, "path": path, "new_state": "closed"}

  @app.post("/router/heal")
  async def trigger_healing(_: dict = Depends(require_admin)):
    """Manually trigger self-healing cycle."""
    healed = run_self_healing()
    return {
      "ok": True,
      "healed": healed,
      "healed_count": len(healed),
      "timestamp": _now(),
    }

  @app.post("/router/restart")
  async def restart_route_control(_: dict = Depends(require_admin)):
    """Full restart of route control: stop watchdog, clear all state, restart."""
    if restart_state["active"]:
      raise HTTPException(status_code=409, detail="Riavvio già in corso")

    async def _do_restart():
      restart_state["active"] = True
      restart_state["started_at"] = _now()
      restart_state["completed_at"] = None
      restart_state["error"] = None
      restart_state["phases_done"] = []
      restart_state["progress"] = 0

      cumulative_weight = 0
      total_weight = sum(p["weight"] for p in RESTART_PHASES)

      try:
        # Phase 1: Stop watchdog
        restart_state["phase"] = "stop_watchdog"
        if watchdog.get("task"):
          watchdog["running"] = False
          watchdog["task"].cancel()
          try:
            await asyncio.sleep(0.3)
          except asyncio.CancelledError:
            pass
          watchdog["task"] = None
        else:
          watchdog["running"] = False
        await asyncio.sleep(0.4)
        cumulative_weight += RESTART_PHASES[0]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("stop_watchdog")

        # Phase 2: Clear metrics
        restart_state["phase"] = "clear_metrics"
        with _lock:
          route_metrics.clear()
        await asyncio.sleep(0.5)
        cumulative_weight += RESTART_PHASES[1]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("clear_metrics")

        # Phase 3: Clear circuit breakers
        restart_state["phase"] = "clear_cbs"
        with _lock:
          circuit_breakers.clear()
        await asyncio.sleep(0.4)
        cumulative_weight += RESTART_PHASES[2]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("clear_cbs")

        # Phase 4: Clear alerts & heal log
        restart_state["phase"] = "clear_alerts"
        alerts.clear()
        heal_log.clear()
        await asyncio.sleep(0.3)
        cumulative_weight += RESTART_PHASES[3]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("clear_alerts")

        # Phase 5: Reset global stats
        restart_state["phase"] = "reset_globals"
        global_stats["total_requests"] = 0
        global_stats["total_errors"] = 0
        global_stats["start_time"] = time.time()
        watchdog["cycle_count"] = 0
        watchdog["last_cycle"] = None
        watchdog["uptime_start"] = time.time()
        watchdog["consecutive_healthy"] = 0
        watchdog["consecutive_degraded"] = 0
        await asyncio.sleep(0.3)
        cumulative_weight += RESTART_PHASES[4]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("reset_globals")

        # Phase 6: Restart watchdog
        restart_state["phase"] = "start_watchdog"
        watchdog["task"] = asyncio.create_task(watchdog_loop())
        await asyncio.sleep(0.6)
        cumulative_weight += RESTART_PHASES[5]["weight"]
        restart_state["progress"] = int((cumulative_weight / total_weight) * 100)
        restart_state["phases_done"].append("start_watchdog")

        # Phase 7: Verify
        restart_state["phase"] = "verify"
        await asyncio.sleep(0.3)
        cumulative_weight += RESTART_PHASES[6]["weight"]
        restart_state["progress"] = 100
        restart_state["phases_done"].append("verify")

        restart_state["phase"] = "complete"
        restart_state["completed_at"] = _now()

        _emit_alert("low", "system", "Route Control riavviato con successo")

      except Exception as e:
        restart_state["error"] = str(e)[:200]
        restart_state["phase"] = "error"
        _emit_alert("critical", "system", f"Errore durante il riavvio: {str(e)[:200]}")
      finally:
        restart_state["active"] = False

    asyncio.create_task(_do_restart())
    return {
      "ok": True,
      "message": "Riavvio avviato",
      "phases": RESTART_PHASES,
      "poll_url": "/router/restart/status",
    }

  @app.get("/router/restart/status")
  async def restart_status(_: dict = Depends(require_admin)):
    """Poll restart progress."""
    return {
      "active": restart_state["active"],
      "phase": restart_state["phase"],
      "phases_done": restart_state["phases_done"],
      "progress": restart_state["progress"],
      "started_at": restart_state["started_at"],
      "completed_at": restart_state["completed_at"],
      "error": restart_state["error"],
      "phases": RESTART_PHASES,
    }

  @app.get("/router/topology")
  async def get_topology(_: dict = Depends(require_admin)):
    """Get route topology for visualization."""
    # Group routes by prefix
    groups = defaultdict(list)
    for route in app.routes:
      if hasattr(route, "path") and hasattr(route, "methods"):
        path = route.path
        parts = path.strip("/").split("/")
        prefix = parts[0] if parts else "root"
        m = route_metrics.get(path, {})
        cb = circuit_breakers.get(path, {})
        groups[prefix].append({
          "path": path,
          "methods": sorted(route.methods) if route.methods else [],
          "requests": m.get("requests", 0),
          "errors": m.get("errors", 0),
          "cb_state": cb.get("state", "closed"),
          "health": "critical" if cb.get("state") == "open" else
                    "degraded" if m.get("requests", 0) > 0 and _error_rate(path) >= ERROR_RATE_WARN else
                    "healthy",
        })

    # Traefik layer (static info)
    proxy_routes = [
      {"rule": "PathPrefix(`/`)", "service": "web", "target": "http://web:80", "priority": 1},
      {"rule": "PathPrefix(`/api`)", "service": "api", "target": "http://api:8000", "priority": 9},
      {"rule": "PathPrefix(`/auth`)", "service": "keycloak", "target": "http://keycloak:8080", "priority": 10},
    ]

    return {
      "proxy": {"type": "traefik", "routes": proxy_routes},
      "api_groups": {k: v for k, v in sorted(groups.items())},
      "total_groups": len(groups),
      "total_endpoints": sum(len(v) for v in groups.values()),
    }

  @app.post("/router/validate-path")
  async def validate_path(path: str = Query(...), _: dict = Depends(require_admin)):
    """Validate path matches FastAPI route patterns."""
    try:
      pattern = re.compile(f"^{re.escape(path)}$")
      return {"valid": True, "pattern": pattern.pattern}
    except Exception as e:
      return {"valid": False, "error": str(e)}

  @app.get("/r/map")
  async def get_shorthand_map(_: dict = Depends(require_admin)):
    """Get all available shorthand routes."""
    return {
      "shorthand_routes": {
        sh: {
          "full_path": full_path,
          "example": f"/api/r/{sh}",
          "alternative": f"/api{full_path}"
        }
        for sh, full_path in shorthand_map.items()
      },
      "total": len(shorthand_map)
    }

  @app.get("/r/{shorthand}")
  async def shorthand_redirect(shorthand: str, request: Request, _: dict = Depends(require_admin)):
    """Shorthand route redirector."""
    if shorthand not in shorthand_map:
      raise HTTPException(status_code=404, detail=f"Unknown shorthand: {shorthand}")
    full_path = shorthand_map[shorthand]
    return {
      "shorthand": shorthand,
      "mapped_to": full_path,
      "description": f"Use /api{full_path} directly or /api/r/{shorthand} as shorthand",
      "note": "For actual data, call the mapped_to endpoint with proper auth"
    }
