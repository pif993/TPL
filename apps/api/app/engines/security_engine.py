"""
TPL Security Engine — Sistema di sicurezza estremo anti-hacking, anti-corruzione,
anti brute-force con monitoraggio in tempo reale, firewall applicativo,
threat intelligence e integrity verification.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, constr

# ─── Costanti ────────────────────────────────────────────────────────────────
_LOCK = threading.Lock()
_BF_WINDOW = 300          # 5 min sliding window per brute-force
_BF_MAX = 15              # max tentativi per IP in finestra
_SCAN_WINDOW = 60         # 1 min per port-scan heuristic
_SCAN_THRESHOLD = 50      # richieste sospette per attivare scan-detect
_RATE_WINDOW = 60          # rate-limit window (s)
_RATE_MAX = 200            # max richieste per IP/min
_INTEGRITY_INTERVAL = 300  # ogni 5 min controlla integrità
_ALERT_RETENTION = 5000    # max alert in file


# ─── In-Memory State ─────────────────────────────────────────────────────────
class _State:
    """Thread-safe state container."""
    def __init__(self):
        self.brute_force: dict[str, list[float]] = defaultdict(list)
        self.rate_limit: dict[str, list[float]] = defaultdict(list)
        self.blocked_ips: dict[str, float] = {}          # ip -> block_until
        self.scan_detect: dict[str, list[float]] = defaultdict(list)
        self.threat_events: list[dict] = []
        self.failed_logins_total: int = 0
        self.blocked_requests_total: int = 0
        self.threats_detected_total: int = 0
        self.xss_blocked: int = 0
        self.sqli_blocked: int = 0
        self.traversal_blocked: int = 0
        self.anomaly_score: float = 0.0
        self.last_integrity_check: float = 0.0
        self.integrity_status: str = "pending"
        self.integrity_files: dict[str, str] = {}       # path -> sha256
        self.baseline_hashes: dict[str, str] = {}
        self.firewall_rules: list[dict] = []
        self.encryption_ops: int = 0
        self.uptime_start: float = time.time()
        self.requests_total: int = 0
        self.requests_by_method: dict[str, int] = defaultdict(int)
        self.geo_blocks: set = set()
        self.ip_whitelist: set = set()
        self.ip_blacklist: set = set()
        self.honeypot_hits: int = 0
        self.cors_violations: int = 0
        self.csrf_blocked: int = 0

_S = _State()

# ─── XSS / SQL Injection / Path Traversal Patterns ──────────────────────────
_XSS_PATTERNS = [
    re.compile(r'<\s*script', re.I),
    re.compile(r'javascript\s*:', re.I),
    re.compile(r'on(load|error|click|mouse|focus|blur|change|submit)\s*=', re.I),
    re.compile(r'<\s*iframe', re.I),
    re.compile(r'<\s*object', re.I),
    re.compile(r'<\s*embed', re.I),
    re.compile(r'<\s*svg[^>]*on', re.I),
    re.compile(r'expression\s*\(', re.I),
    re.compile(r'vbscript\s*:', re.I),
    re.compile(r'data\s*:.*base64', re.I),
]

_SQLI_PATTERNS = [
    # More targeted patterns to reduce false positives
    re.compile(r"(\bunion\b\s+\bselect\b)", re.I),
    re.compile(r"('\s*(or|and)\s*'?\s*\d+\s*=\s*\d+)", re.I),
    re.compile(r"(--\s*$|;\s*drop\s|;\s*delete\s|;\s*insert\s)", re.I),
    re.compile(r"(\bwaitfor\b\s+\bdelay\b)", re.I),
    re.compile(r"(\bbenchmark\s*\(\s*\d)", re.I),
    re.compile(r"(\bsleep\s*\(\s*\d)", re.I),
    re.compile(r"(\bload_file\s*\()", re.I),
    re.compile(r"(\binto\s+outfile\b)", re.I),
    re.compile(r"(\bexec\s*\(\s*xp_)", re.I),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\./'),
    re.compile(r'\.\.\\'),
    re.compile(r'%2e%2e[/\\]', re.I),
    re.compile(r'%252e%252e', re.I),
    re.compile(r'/etc/(passwd|shadow|hosts)', re.I),
    re.compile(r'/proc/self', re.I),
    re.compile(r'\\windows\\', re.I),
    re.compile(r'%00', re.I),  # null byte injection
]

_SUSPICIOUS_HEADERS = [
    'x-original-url',
    'x-rewrite-url',
]

_SUSPICIOUS_UA = [
    re.compile(r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|medusa|burp)', re.I),
    re.compile(r'^$'),                           # empty UA
    re.compile(r'^-$'),
    re.compile(r'^Mozilla/4\.0$'),               # ancient / fake
]

# ─── Command Injection Patterns ──────────────────────────────────────────────
_CMDI_PATTERNS = [
    re.compile(r'[;&|`]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b', re.I),
    re.compile(r'\$\(.*\)', re.I),               # $(command)
    re.compile(r'`[^`]+`'),                       # `command`
    re.compile(r'\|\|\s*\w+', re.I),              # || fallback
    re.compile(r';\s*(rm|chmod|chown|kill|shutdown|reboot|mkfs)\b', re.I),
]

# ─── SSRF Patterns ───────────────────────────────────────────────────────────
_SSRF_PATTERNS = [
    re.compile(r'https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])', re.I),
    re.compile(r'https?://169\.254\.', re.I),     # AWS metadata
    re.compile(r'https?://metadata\.google', re.I),
    re.compile(r'https?://10\.', re.I),
    re.compile(r'https?://172\.(1[6-9]|2\d|3[01])\.', re.I),
    re.compile(r'https?://192\.168\.', re.I),
    re.compile(r'file://', re.I),
    re.compile(r'gopher://', re.I),
    re.compile(r'dict://', re.I),
]

# ─── XXE Patterns ────────────────────────────────────────────────────────────
_XXE_PATTERNS = [
    re.compile(r'<!\s*ENTITY', re.I),
    re.compile(r'<!\s*DOCTYPE[^>]*ENTITY', re.I),
    re.compile(r'SYSTEM\s+["\']', re.I),
    re.compile(r'PUBLIC\s+["\']', re.I),
]

# ─── Internal / trusted IPs (exempt from scan detection) ────────────────────
def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/Docker/loopback — trusted traffic."""
    try:
        return _ip_is_trusted(ip)
    except Exception:
        return ip in ('localhost', 'unknown')

# ─── Informational categories (excluded from threat scoring) ────────────────
_INFORMATIONAL_CATEGORIES = frozenset({
    'ip_management', 'firewall_rule', 'integrity',
    'scan_detected',  # internal scan detection is noise
})


import ipaddress as _ipa

# ─── Trusted proxy CIDR list ─────────────────────────────────────────────────
_TRUSTED_PROXY_NETS: list = []
_trusted_raw = os.getenv("TRUSTED_PROXY_IPS", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8,::1/128")
for _cidr in _trusted_raw.split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            _TRUSTED_PROXY_NETS.append(_ipa.ip_network(_cidr, strict=False))
        except ValueError:
            pass

def _ip_is_trusted(ip_str: str) -> bool:
    try:
        addr = _ipa.ip_address(ip_str)
        return any(addr in net for net in _TRUSTED_PROXY_NETS)
    except ValueError:
        return False


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _now() -> float:
    return time.time()

def _ts() -> int:
    return int(time.time())

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _client_ip(request: Request) -> str:
    """Extract client IP safely. Only trust X-Forwarded-For when the direct
    peer is in TRUSTED_PROXY_IPS. Walk the XFF chain right-to-left, returning
    the first non-trusted IP."""
    peer = request.client.host if request.client else "unknown"
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd and _ip_is_trusted(peer):
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        for ip in reversed(parts):
            if not _ip_is_trusted(ip):
                return ip
        return parts[0] if parts else peer
    return peer


# ─── Alert Persistence ───────────────────────────────────────────────────────
def _alert_file(root: str) -> str:
    return os.path.join(root, ".tpl_security.jsonl")

def _append_alert(root: str, payload: dict):
    row = {
        "ts": _ts(),
        "id": secrets.token_hex(8),
        **payload,
    }
    try:
        with open(_alert_file(root), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
    except Exception:
        pass
    with _LOCK:
        _S.threat_events.append(row)
        if len(_S.threat_events) > 500:
            _S.threat_events = _S.threat_events[-500:]
        _S.threats_detected_total += 1

def _tail_alerts(root: str, limit: int = 100) -> list:
    limit = max(1, min(limit, _ALERT_RETENTION))
    path = _alert_file(root)
    if not os.path.isfile(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-limit:]


# ─── Brute Force Detection ───────────────────────────────────────────────────
def _bf_check(ip: str) -> bool:
    """Ritorna True se IP è rate-limited per brute-force."""
    now = _now()
    with _LOCK:
        if ip in _S.blocked_ips:
            if now < _S.blocked_ips[ip]:
                return True
            del _S.blocked_ips[ip]
        cutoff = now - _BF_WINDOW
        _S.brute_force[ip] = [t for t in _S.brute_force[ip] if t >= cutoff]
        return len(_S.brute_force[ip]) >= _BF_MAX

def _bf_register(ip: str):
    """Registra tentativo fallito."""
    now = _now()
    with _LOCK:
        _S.brute_force[ip].append(now)
        _S.failed_logins_total += 1
        cutoff = now - _BF_WINDOW
        _S.brute_force[ip] = [t for t in _S.brute_force[ip] if t >= cutoff]
        if len(_S.brute_force[ip]) >= _BF_MAX:
            # Escalation: count how many times this IP has been blocked
            block_count = sum(1 for t in _S.threat_events if t.get("ip") == ip and t.get("category") == "brute_force")
            duration = min(3600, 300 * (2 ** min(block_count, 3)))
            _S.blocked_ips[ip] = now + duration

def _bf_clear(ip: str):
    with _LOCK:
        _S.brute_force.pop(ip, None)


# ─── Rate Limiting ────────────────────────────────────────────────────────────
def _rate_check(ip: str) -> bool:
    """True se IP supera rate limit."""
    now = _now()
    with _LOCK:
        if ip in _S.ip_whitelist:
            return False
        if ip in _S.ip_blacklist or ip in _S.blocked_ips:
            return True
        cutoff = now - _RATE_WINDOW
        _S.rate_limit[ip] = [t for t in _S.rate_limit[ip] if t >= cutoff]
        _S.rate_limit[ip].append(now)
        return len(_S.rate_limit[ip]) > _RATE_MAX

# ─── WAF (Web Application Firewall) ──────────────────────────────────────────
def _waf_scan(request: Request, body_str: str = "") -> dict | None:
    """Scansiona richiesta per XSS, SQLi, path traversal, CMDi, SSRF, XXE.
    Ritorna threat dict o None."""
    url = str(request.url)
    path = request.url.path
    query = str(request.query_params)
    check_str = f"{path} {query} {url}"
    if body_str:
        check_str = f"{check_str} {body_str}"
    # Per SSRF/XXE usiamo solo path+query+body per evitare falsi positivi
    # sull'URL della richiesta stessa (es. http://localhost:8000/api/...)
    param_str = f"{path} {query}"
    if body_str:
        param_str = f"{param_str} {body_str}"

    for pat in _TRAVERSAL_PATTERNS:
        if pat.search(check_str):
            with _LOCK:
                _S.traversal_blocked += 1
            return {"category": "path_traversal", "severity": "high",
                    "message": f"Path traversal attempt blocked: {path[:120]}",
                    "source": "waf", "meta": {"pattern": "traversal", "path": path[:200]}}

    for pat in _XSS_PATTERNS:
        if pat.search(check_str):
            with _LOCK:
                _S.xss_blocked += 1
            return {"category": "xss_attempt", "severity": "high",
                    "message": f"XSS attempt blocked on {path[:120]}",
                    "source": "waf", "meta": {"pattern": "xss", "path": path[:200]}}

    for pat in _SQLI_PATTERNS:
        if pat.search(check_str):
            with _LOCK:
                _S.sqli_blocked += 1
            return {"category": "sql_injection", "severity": "critical",
                    "message": f"SQL injection attempt blocked on {path[:120]}",
                    "source": "waf", "meta": {"pattern": "sqli", "path": path[:200]}}

    for pat in _CMDI_PATTERNS:
        if pat.search(param_str):
            return {"category": "command_injection", "severity": "critical",
                    "message": f"Command injection attempt blocked on {path[:120]}",
                    "source": "waf", "meta": {"pattern": "cmdi", "path": path[:200]}}

    for pat in _SSRF_PATTERNS:
        if pat.search(param_str):
            return {"category": "ssrf_attempt", "severity": "high",
                    "message": f"SSRF attempt blocked on {path[:120]}",
                    "source": "waf", "meta": {"pattern": "ssrf", "path": path[:200]}}

    for pat in _XXE_PATTERNS:
        if pat.search(param_str):
            return {"category": "xxe_attempt", "severity": "critical",
                    "message": f"XXE attempt blocked on {path[:120]}",
                    "source": "waf", "meta": {"pattern": "xxe", "path": path[:200]}}

    for h in _SUSPICIOUS_HEADERS:
        if request.headers.get(h):
            return {"category": "header_injection", "severity": "medium",
                    "message": f"Suspicious header '{h}' detected",
                    "source": "waf", "meta": {"header": h}}

    ua = request.headers.get("user-agent", "")
    for pat in _SUSPICIOUS_UA:
        if pat.search(ua):
            return {"category": "suspicious_ua", "severity": "medium",
                    "message": f"Suspicious user-agent detected: {ua[:80]}",
                    "source": "waf", "meta": {"ua": ua[:120]}}

    return None


# ─── Scan Detection ──────────────────────────────────────────────────────────
def _scan_check(ip: str) -> bool:
    """Rileva port scanning / path enumeration. Skips internal IPs."""
    if _is_internal_ip(ip):
        return False
    now = _now()
    with _LOCK:
        cutoff = now - _SCAN_WINDOW
        _S.scan_detect[ip] = [t for t in _S.scan_detect[ip] if t >= cutoff]
        _S.scan_detect[ip].append(now)
        return len(_S.scan_detect[ip]) > _SCAN_THRESHOLD


# ─── File Integrity Monitoring ────────────────────────────────────────────────
def _compute_file_hashes(root: str) -> dict[str, str]:
    """Calcola SHA-256 dei file critici."""
    critical_paths = []
    app_dir = os.path.join(root, "apps", "api", "app")
    if os.path.isdir(app_dir):
        for dp, _, fns in os.walk(app_dir):
            for fn in fns:
                if fn.endswith(('.py', '.json', '.yml')):
                    critical_paths.append(os.path.join(dp, fn))
    mod_dir = os.path.join(root, "modules")
    if os.path.isdir(mod_dir):
        for fn in os.listdir(mod_dir):
            if fn.endswith('.sh'):
                critical_paths.append(os.path.join(mod_dir, fn))
    compose_dir = os.path.join(root, "compose.d")
    if os.path.isdir(compose_dir):
        for fn in os.listdir(compose_dir):
            critical_paths.append(os.path.join(compose_dir, fn))
    hashes = {}
    for p in critical_paths:
        try:
            with open(p, "rb") as f:
                hashes[p] = _sha256(f.read())
        except Exception:
            continue
    return hashes


def _integrity_check(root: str) -> dict:
    """Esegue controllo integrità file. Ritorna report."""
    now = _now()
    current = _compute_file_hashes(root)
    report = {
        "timestamp": _ts(),
        "files_checked": len(current),
        "status": "ok",
        "modified": [],
        "added": [],
        "removed": [],
    }
    with _LOCK:
        if not _S.baseline_hashes:
            _S.baseline_hashes = dict(current)
            _S.integrity_files = dict(current)
            _S.integrity_status = "ok"
            _S.last_integrity_check = now
            report["status"] = "baseline_set"
            return report

        baseline = _S.baseline_hashes
        for path, h in current.items():
            if path not in baseline:
                report["added"].append(path)
            elif baseline[path] != h:
                report["modified"].append(path)
        for path in baseline:
            if path not in current:
                report["removed"].append(path)

        if report["modified"] or report["removed"]:
            report["status"] = "tampered"
            _S.integrity_status = "tampered"
        elif report["added"]:
            report["status"] = "changed"
            _S.integrity_status = "changed"
        else:
            report["status"] = "ok"
            _S.integrity_status = "ok"

        _S.integrity_files = dict(current)
        _S.last_integrity_check = now
    return report


# ─── Anomaly Score ────────────────────────────────────────────────────────────
def _compute_anomaly_score() -> float:
    """Calcola score di anomalia 0-100 con decay temporale.

    Solo gli eventi di sicurezza reali (non informational) contribuiscono.
    Eventi più recenti pesano di più grazie a un fattore di decay.
    """
    with _LOCK:
        now = _now()
        recent_window = 900  # 15 minuti
        # Solo eventi REALI (escludi categorie informational)
        recent = [
            e for e in _S.threat_events
            if e.get("ts", 0) > now - recent_window
            and e.get("category") not in _INFORMATIONAL_CATEGORIES
        ]
        bf_active = len([ip for ip, exp in _S.blocked_ips.items() if exp > now])

        # Decay-weighted scoring: eventi più recenti pesano di più
        score = 0.0
        sev_weights = {"critical": 15, "high": 6, "medium": 1.5, "low": 0.2}
        for e in recent:
            age = max(1, now - e.get("ts", now))
            decay = max(0.15, 1.0 - (age / recent_window))  # 1.0 → 0.15
            w = sev_weights.get(e.get("severity", "low"), 0.2)
            score += w * decay

        # Cap per categoria di evento
        score = min(score, 65)

        # Brute-force attivi
        score += min(bf_active * 6, 20)

        # Integrità
        if _S.integrity_status == "tampered":
            score += 20
        elif _S.integrity_status == "changed":
            score += 3

        score = min(score, 100.0)
        _S.anomaly_score = round(score, 2)
        return _S.anomaly_score


# ─── Pydantic Models ─────────────────────────────────────────────────────────
class SecurityAlert(BaseModel):
    severity: constr(pattern="^(low|medium|high|critical)$") = "medium"
    category: constr(min_length=1, max_length=64) = "manual"
    message: constr(min_length=1, max_length=500) = "Manual alert"
    source: str = "admin"
    meta: dict = Field(default_factory=dict)

class FirewallRule(BaseModel):
    action: constr(pattern="^(block|allow|monitor)$") = "block"
    target: constr(min_length=1, max_length=128) = ""
    rule_type: constr(pattern="^(ip|cidr|path|ua|header)$") = "ip"
    description: str = ""

class IPAction(BaseModel):
    ip: constr(min_length=1, max_length=64)
    action: constr(pattern="^(block|unblock|whitelist|unwhitelist)$") = "block"
    duration: int = 3600


# ═══════════════════════════════════════════════════════════════════════════════
#  REGISTER — entry point per engine loader
# ═══════════════════════════════════════════════════════════════════════════════
def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    root = ctx["root"]
    audit_fn = ctx.get("audit")

    # Honeypot paths — expanded coverage for common attack vectors
    _honeypot_paths = ('/admin/config', '/wp-admin', '/wp-login.php',
                       '/.env', '/phpinfo.php', '/phpmyadmin',
                       '/actuator', '/debug', '/console',
                       '/.git/config', '/.svn/entries', '/.DS_Store',
                       '/server-status', '/server-info',
                       '/cgi-bin/', '/shell', '/cmd',
                       '/wp-content/uploads/', '/xmlrpc.php',
                       '/.well-known/security.txt',
                       '/administrator/', '/manager/html',
                       '/solr/', '/jenkins/', '/api/v1/pods',
                       '/.aws/credentials', '/.ssh/id_rsa')

    # Inizializza baseline integrità
    threading.Thread(target=lambda: _integrity_check(root), daemon=True).start()

    # ── Expose per altri engine ──────────────────────────────────────────
    app.state.security_engine_alert = lambda payload: _append_alert(root, payload)
    app.state.security_engine_bf_register = _bf_register
    app.state.security_engine_bf_check = _bf_check
    app.state.security_engine_bf_clear = _bf_clear
    app.state.security_engine_waf = _waf_scan

    def _security_engine_status():
        """Return current security engine status summary for inter-engine use."""
        with _LOCK:
            return {
                "status": "active",
                "uptime": time.time() - _S.uptime_start,
                "requests_total": _S.requests_total,
                "threats_detected": _S.threats_detected_total,
                "blocked_requests": _S.blocked_requests_total,
                "failed_logins": _S.failed_logins_total,
                "blocked_ips": len(_S.blocked_ips),
                "firewall_rules": len(_S.firewall_rules),
                "integrity_status": _S.integrity_status,
                "xss_blocked": _S.xss_blocked,
                "sqli_blocked": _S.sqli_blocked,
                "traversal_blocked": _S.traversal_blocked,
                "honeypot_hits": _S.honeypot_hits,
                "cors_violations": _S.cors_violations,
                "csrf_blocked": _S.csrf_blocked,
            }

    app.state.security_engine_status = _security_engine_status

    # ── WAF Middleware ───────────────────────────────────────────────────
    @app.middleware("http")
    async def security_waf_middleware(request: Request, call_next):
        ip = _client_ip(request)

        with _LOCK:
            _S.requests_total += 1
            _S.requests_by_method[request.method] += 1

        # 1) Check IP blacklist & blocked
        if _rate_check(ip):
            with _LOCK:
                _S.blocked_requests_total += 1
            _append_alert(root, {
                "severity": "high", "category": "rate_limit",
                "message": f"Rate limit exceeded by {ip}",
                "source": "firewall", "meta": {"ip": ip}
            })
            raise HTTPException(429, "rate_limited")

        # 2) Scan detection
        if _scan_check(ip):
            _append_alert(root, {
                "severity": "medium", "category": "scan_detected",
                "message": f"Possible scan from {ip}",
                "source": "ids", "meta": {"ip": ip}
            })

        # 3) WAF scan (including POST/PUT/PATCH body for mutating requests)
        body_str = ""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                raw = await request.body()
                # Limit body scan to first 16KB to avoid memory issues
                body_str = raw[:16384].decode("utf-8", errors="ignore")
            except Exception:
                pass
        threat = _waf_scan(request, body_str)
        if threat:
            _append_alert(root, {**threat, "meta": {**threat.get("meta", {}), "ip": ip}})
            with _LOCK:
                _S.blocked_requests_total += 1
            if threat["severity"] in ("critical", "high"):
                raise HTTPException(403, "blocked_by_waf")

        # 4) Honeypot paths
        if request.url.path.lower() in _honeypot_paths:
            with _LOCK:
                _S.honeypot_hits += 1
            _append_alert(root, {
                "severity": "medium", "category": "honeypot",
                "message": f"Honeypot triggered: {request.url.path} from {ip}",
                "source": "honeypot", "meta": {"ip": ip, "path": request.url.path}
            })

        response = await call_next(request)

        # Security headers — only set if not already present (avoid conflicts with main middleware)
        # HSTS: set when FORCE_HTTPS=true or actual HTTPS traffic detected
        _force_https = os.getenv("FORCE_HTTPS", "false").lower() in ("true", "1", "yes")
        proto = request.headers.get("X-Forwarded-Proto", "http")
        if _force_https or proto == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        # COEP/COOP/CORP: disabled by default as they break many legitimate use cases.
        # Enable only if you're sure your app doesn't need cross-origin resources.
        # response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        # response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, private")
        response.headers.setdefault("Pragma", "no-cache")
        response.headers.setdefault("X-DNS-Prefetch-Control", "off")

        return response

    # ═══ API ENDPOINTS ════════════════════════════════════════════════════

    # ── Dashboard Status (comprehensive) ──────────────────────────────────
    @app.get("/security/status")
    async def security_status(_: dict = Depends(require_admin)):
        all_alerts = _tail_alerts(root, 500)
        now = _ts()
        day_ago = now - 86400
        hour_ago = now - 3600

        alerts_today = [a for a in all_alerts if a.get("ts", 0) > day_ago]
        alerts_hour = [a for a in all_alerts if a.get("ts", 0) > hour_ago]

        # Conta SOLO minacce reali (escludi rumore informational)
        real_today = [a for a in alerts_today if a.get("category") not in _INFORMATIONAL_CATEGORIES]
        real_hour  = [a for a in alerts_hour  if a.get("category") not in _INFORMATIONAL_CATEGORIES]

        crit   = len([a for a in real_today if a.get("severity") == "critical"])
        high   = len([a for a in real_today if a.get("severity") == "high"])
        medium = len([a for a in real_today if a.get("severity") == "medium"])
        low    = len([a for a in real_today if a.get("severity") == "low"])

        # Velocità di arrivo minacce (ultimi 10 min)
        ten_min_ago = now - 600
        velocity = len([a for a in real_hour if a.get("ts", 0) > ten_min_ago])

        categories = defaultdict(int)
        for a in alerts_today:
            categories[a.get("category", "unknown")] += 1

        anomaly = _compute_anomaly_score()

        # ── Threat level realistico ──
        #  - critical: attacco attivo confermato (multipli critici O anomaly altissimo)
        #  - high: minacce significative in corso
        #  - elevated: attività sospetta recente
        #  - guarded: rumore di fondo basso
        #  - low: sistema pulito
        if crit >= 3 or (crit >= 1 and anomaly > 70):
            threat_level = "critical"
        elif crit >= 1 or high >= 5 or anomaly > 55:
            threat_level = "high"
        elif high >= 2 or (high >= 1 and velocity >= 3) or anomaly > 35:
            threat_level = "elevated"
        elif high >= 1 or medium >= 10 or anomaly > 15:
            threat_level = "guarded"
        else:
            threat_level = "low"

        with _LOCK:
            uptime = _now() - _S.uptime_start
            result = {
                "threat_level": threat_level,
                "anomaly_score": round(anomaly, 1),
                "critical": crit,
                "high": high,
                "medium": medium,
                "low": low,
                "total_today": len(alerts_today),
                "total_hour": len(alerts_hour),
                "total_all": len(all_alerts),
                "categories": dict(categories),
                "blocked_ips": len(_S.blocked_ips),
                "blocked_ips_list": list(_S.blocked_ips.keys())[:50],
                "blacklist_count": len(_S.ip_blacklist),
                "whitelist_count": len(_S.ip_whitelist),
                "firewall_rules": len(_S.firewall_rules),
                "real_threats_today": len(real_today),
                "real_threats_hour": len(real_hour),
                "threat_velocity": velocity,
                "waf_stats": {
                    "xss_blocked": _S.xss_blocked,
                    "sqli_blocked": _S.sqli_blocked,
                    "traversal_blocked": _S.traversal_blocked,
                    "total_blocked": _S.blocked_requests_total,
                },
                "brute_force": {
                    "failed_logins": _S.failed_logins_total,
                    "active_blocks": len(_S.blocked_ips),
                },
                "integrity": {
                    "status": _S.integrity_status,
                    "last_check": int(_S.last_integrity_check),
                    "files_monitored": len(_S.integrity_files),
                },
                "honeypot_hits": _S.honeypot_hits,
                "requests_total": _S.requests_total,
                "requests_by_method": dict(_S.requests_by_method),
                "uptime_seconds": int(uptime),
            }
        return result

    # ── Alerts CRUD ───────────────────────────────────────────────────────
    @app.post("/security/alert")
    async def create_alert(x: SecurityAlert, _: dict = Depends(require_admin)):
        _append_alert(root, x.model_dump())
        return {"ok": True}

    @app.get("/security/alerts")
    async def list_alerts(
        limit: int = 200,
        severity: str = "",
        category: str = "",
        since: int = 0,
        offset: int = 0,
        search: str = "",
        exclude_info: bool = True,
        _: dict = Depends(require_admin),
    ):
        items = _tail_alerts(root, 2000)
        # Escludi alert informativi/futili di default
        if exclude_info:
            items = [a for a in items if a.get("category") not in _INFORMATIONAL_CATEGORIES]
        if severity:
            items = [a for a in items if a.get("severity") == severity]
        if category:
            items = [a for a in items if a.get("category") == category]
        if since > 0:
            items = [a for a in items if a.get("ts", 0) >= since]
        if search:
            s = search.lower()
            items = [a for a in items if s in (a.get("message","") + a.get("category","") + a.get("source","")).lower()]
        total = len(items)
        items = items[offset:offset + limit] if offset > 0 else items[:limit]
        return {"items": items, "count": len(items), "total": total, "offset": offset}

    @app.delete("/security/alerts")
    async def clear_alerts(_: dict = Depends(require_admin)):
        try:
            with open(_alert_file(root), "w", encoding="utf-8") as f:
                f.write("")
            with _LOCK:
                _S.threat_events.clear()
        except Exception:
            pass
        return {"ok": True, "cleared": True}

    # ── WAF Stats ─────────────────────────────────────────────────────────
    @app.get("/security/waf")
    async def waf_status(_: dict = Depends(require_admin)):
        with _LOCK:
            return {
                "enabled": True,
                "xss_blocked": _S.xss_blocked,
                "sqli_blocked": _S.sqli_blocked,
                "traversal_blocked": _S.traversal_blocked,
                "total_blocked": _S.blocked_requests_total,
                "honeypot_hits": _S.honeypot_hits,
                "cors_violations": _S.cors_violations,
                "active_patterns": {
                    "xss": len(_XSS_PATTERNS),
                    "sqli": len(_SQLI_PATTERNS),
                    "traversal": len(_TRAVERSAL_PATTERNS),
                    "cmdi": len(_CMDI_PATTERNS),
                    "ssrf": len(_SSRF_PATTERNS),
                    "xxe": len(_XXE_PATTERNS),
                    "ua": len(_SUSPICIOUS_UA),
                },
                "rules": [
                    {"type": "xss", "count": len(_XSS_PATTERNS), "status": "active"},
                    {"type": "sqli", "count": len(_SQLI_PATTERNS), "status": "active"},
                    {"type": "traversal", "count": len(_TRAVERSAL_PATTERNS), "status": "active"},
                    {"type": "cmdi", "count": len(_CMDI_PATTERNS), "status": "active"},
                    {"type": "ssrf", "count": len(_SSRF_PATTERNS), "status": "active"},
                    {"type": "xxe", "count": len(_XXE_PATTERNS), "status": "active"},
                    {"type": "suspicious_ua", "count": len(_SUSPICIOUS_UA), "status": "active"},
                    {"type": "honeypot", "count": len(_honeypot_paths), "status": "active"},
                ],
            }

    # ── IP Management ─────────────────────────────────────────────────────
    @app.post("/security/ip")
    async def manage_ip(x: IPAction, request: Request, _: dict = Depends(require_admin)):
        with _LOCK:
            if x.action == "block":
                _S.blocked_ips[x.ip] = _now() + x.duration
                _S.ip_blacklist.add(x.ip)
                action_msg = f"IP {x.ip} blocked for {x.duration}s"
            elif x.action == "unblock":
                _S.blocked_ips.pop(x.ip, None)
                _S.ip_blacklist.discard(x.ip)
                action_msg = f"IP {x.ip} unblocked"
            elif x.action == "whitelist":
                _S.ip_whitelist.add(x.ip)
                _S.blocked_ips.pop(x.ip, None)
                _S.ip_blacklist.discard(x.ip)
                action_msg = f"IP {x.ip} whitelisted"
            elif x.action == "unwhitelist":
                _S.ip_whitelist.discard(x.ip)
                action_msg = f"IP {x.ip} removed from whitelist"
            else:
                raise HTTPException(400, "invalid action")

        _append_alert(root, {
            "severity": "low", "category": "ip_management",
            "message": action_msg, "source": "admin",
            "meta": {"ip": x.ip, "action": x.action}
        })
        return {"ok": True, "message": action_msg}

    @app.get("/security/ip/lists")
    async def ip_lists(_: dict = Depends(require_admin)):
        with _LOCK:
            return {
                "blocked": {ip: int(exp - _now()) for ip, exp in _S.blocked_ips.items()},
                "blacklist": sorted(_S.ip_blacklist),
                "whitelist": sorted(_S.ip_whitelist),
            }

    # ── Firewall Rules ────────────────────────────────────────────────────
    @app.get("/security/firewall")
    async def firewall_rules(_: dict = Depends(require_admin)):
        with _LOCK:
            return {
                "rules": list(_S.firewall_rules),
                "count": len(_S.firewall_rules),
                "waf_enabled": True,
                "rate_limit": {"window": _RATE_WINDOW, "max": _RATE_MAX},
                "brute_force": {"window": _BF_WINDOW, "max": _BF_MAX},
            }

    @app.post("/security/firewall/rule")
    async def add_firewall_rule(x: FirewallRule, _: dict = Depends(require_admin)):
        rule = {
            "id": secrets.token_hex(6),
            "created": _ts(),
            **x.model_dump(),
        }
        with _LOCK:
            _S.firewall_rules.append(rule)
        _append_alert(root, {
            "severity": "low", "category": "firewall_rule",
            "message": f"Firewall rule added: {x.action} {x.rule_type} {x.target}",
            "source": "admin",
        })
        return {"ok": True, "rule": rule}

    @app.delete("/security/firewall/rule/{rule_id}")
    async def delete_firewall_rule(rule_id: str, _: dict = Depends(require_admin)):
        with _LOCK:
            before = len(_S.firewall_rules)
            _S.firewall_rules = [r for r in _S.firewall_rules if r.get("id") != rule_id]
            removed = before - len(_S.firewall_rules)
        return {"ok": True, "removed": removed}

    # ── Integrity Check ───────────────────────────────────────────────────
    @app.get("/security/integrity")
    async def integrity_status(_: dict = Depends(require_admin)):
        report = _integrity_check(root)
        return report

    @app.post("/security/integrity/baseline")
    async def reset_baseline(_: dict = Depends(require_admin)):
        with _LOCK:
            _S.baseline_hashes.clear()
        report = _integrity_check(root)
        _append_alert(root, {
            "severity": "low", "category": "integrity",
            "message": "Integrity baseline reset by admin",
            "source": "admin",
        })
        return {"ok": True, "report": report}

    # ── Brute Force Info ──────────────────────────────────────────────────
    @app.get("/security/bruteforce")
    async def bruteforce_status(_: dict = Depends(require_admin)):
        now = _now()
        with _LOCK:
            active_blocks = {
                ip: {"expires_in": int(exp - now), "expires_at": int(exp)}
                for ip, exp in _S.blocked_ips.items()
                if exp > now
            }
            tracked_ips = len(_S.brute_force)
        return {
            "active_blocks": active_blocks,
            "tracked_ips": tracked_ips,
            "total_failed": _S.failed_logins_total,
            "config": {
                "window_seconds": _BF_WINDOW,
                "max_attempts": _BF_MAX,
            },
        }

    # ── Threat Timeline (per chart) ───────────────────────────────────────
    @app.get("/security/threats/timeline")
    async def threats_timeline(hours: int = 24, _: dict = Depends(require_admin)):
        now = _ts()
        since = now - (hours * 3600)
        alerts = _tail_alerts(root, 2000)
        # Solo eventi reali nella timeline, escludi rumore informational
        alerts = [a for a in alerts if a.get("ts", 0) >= since and a.get("category") not in _INFORMATIONAL_CATEGORIES]

        buckets = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        for a in alerts:
            hour_key = (a["ts"] // 3600) * 3600
            sev = a.get("severity", "low")
            buckets[hour_key][sev] += 1
            buckets[hour_key]["total"] += 1

        timeline = []
        for h in range(hours):
            ts_key = ((now // 3600) - (hours - 1 - h)) * 3600
            b = buckets.get(ts_key, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
            timeline.append({"ts": ts_key, **b})

        return {"timeline": timeline, "hours": hours, "total_events": len(alerts)}

    # ── Security Score ────────────────────────────────────────────────────
    @app.get("/security/score")
    async def security_score(_: dict = Depends(require_admin)):
        anomaly = _compute_anomaly_score()
        base_score = max(0, 100 - anomaly)

        bonuses = 0
        with _LOCK:
            if _S.integrity_status == "ok":
                bonuses += 5
            if len(_S.firewall_rules) > 0:
                bonuses += 2
            if _S.sqli_blocked == 0 and _S.xss_blocked == 0:
                bonuses += 3       # nessun attacco riuscito
            if len(_S.ip_whitelist) > 0:
                bonuses += 1
            # Bonus per protezioni attive
            bonuses += 3  # WAF multi-layer (XSS+SQLi+CMDi+SSRF+XXE+traversal)
            bonuses += 2  # honeypot attivo
            bonuses += 1  # rate limiting + anti-BF attivi

        score = min(100, base_score + bonuses)

        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": round(score, 1),
            "grade": grade,
            "anomaly_score": round(anomaly, 1),
            "breakdown": {
                "base": round(base_score, 1),
                "bonuses": bonuses,
                "integrity": _S.integrity_status,
                "waf_active": True,
                "waf_layers": ["xss", "sqli", "cmdi", "ssrf", "xxe", "traversal"],
                "rate_limiting": True,
                "brute_force_protection": True,
                "honeypot_active": True,
                "scan_detection": True,
                "security_headers": True,
            },
        }
