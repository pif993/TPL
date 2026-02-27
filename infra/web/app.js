/**
 * TPL Fortress — Core client library v3.0
 *
 * Ed25519 JWT · Refresh-token rotation · Cross-tab sync · Auto-refresh
 * ──────────────────────────────────────────────────────────────────────
 */
(() => {
  'use strict';

  // ── Storage keys ──────────────────────────────────────────────
  const TOKEN_KEY   = 'tpl_token';
  const REFRESH_KEY = 'tpl_refresh';
  const SESSION_KEY = 'tpl_session';
  const EXPIRY_KEY  = 'tpl_token_exp';
  const LANG_KEY    = 'tpl_lang';

  // ── Cross-tab synchronisation via BroadcastChannel ────────────
  let _bc = null;
  try { _bc = new BroadcastChannel('tpl_auth'); } catch (_) { /* unsupported */ }

  // ── Refresh scheduler ─────────────────────────────────────────
  let _refreshTimer = null;
  let _refreshing   = false;          // guard against concurrent refreshes

  // ────────────────────────────────────────────────────────────────
  //  Token helpers
  // ────────────────────────────────────────────────────────────────
  const getToken        = () => sessionStorage.getItem(TOKEN_KEY)   || '';
  const getRefreshToken = () => sessionStorage.getItem(REFRESH_KEY) || '';
  const getSessionId    = () => sessionStorage.getItem(SESSION_KEY) || '';

  /** Store access-token and schedule next refresh. */
  const setToken = (token) => {
    if (!token) {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(EXPIRY_KEY);
      _cancelRefresh();
      return;
    }
    sessionStorage.setItem(TOKEN_KEY, token);
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload.exp) {
        sessionStorage.setItem(EXPIRY_KEY, String(payload.exp));
        _scheduleRefresh(payload.exp);
      }
    } catch (_) { /* non-JWT or parse error */ }
  };

  const setRefreshToken = (rt) => {
    rt ? sessionStorage.setItem(REFRESH_KEY, rt)
       : sessionStorage.removeItem(REFRESH_KEY);
  };

  const setSessionId = (sid) => {
    sid ? sessionStorage.setItem(SESSION_KEY, sid)
        : sessionStorage.removeItem(SESSION_KEY);
  };

  const authHeader = () => {
    const t = getToken();
    return t ? { Authorization: `Bearer ${t}` } : {};
  };

  // ────────────────────────────────────────────────────────────────
  //  Auto-refresh  (triggers at 80 % of token lifetime)
  // ────────────────────────────────────────────────────────────────
  const _cancelRefresh = () => {
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  };

  const _scheduleRefresh = (expUnix) => {
    _cancelRefresh();
    const ttl = expUnix - Math.floor(Date.now() / 1000);
    if (ttl <= 0) return;
    const delay = Math.max(ttl * 0.8, 10) * 1000;     // at least 10 s
    _refreshTimer = setTimeout(_doRefresh, delay);
  };

  const _doRefresh = async () => {
    if (_refreshing) return;          // deduplicate
    _refreshing = true;
    const rt = getRefreshToken();
    if (!rt) { _refreshing = false; return; }
    try {
      const data = await _rawFetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (data.access_token) {
        setToken(data.access_token);
        setRefreshToken(data.refresh_token || '');
        if (data.session_id) setSessionId(data.session_id);
      }
    } catch (err) {
      console.warn('[TPL] refresh failed — forcing logout:', err.message);
      _forceLocalLogout();
    } finally {
      _refreshing = false;
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Raw fetch (no auto-retry)
  // ────────────────────────────────────────────────────────────────
  const _rawFetch = async (url, opts = {}) => {
    const resp = await fetch(url, {
      ...opts,
      headers: { ...(opts.headers || {}), ...authHeader() },
    });
    const text = await resp.text();
    let data = text;
    try { data = JSON.parse(text); } catch (_) { /* plain text */ }
    if (!resp.ok) {
      let errMsg;
      if (typeof data === 'string') {
        errMsg = data;
      } else if (Array.isArray(data.detail)) {
        // FastAPI / Pydantic validation errors → extract human-readable messages
        errMsg = data.detail.map(d => d.msg || JSON.stringify(d)).join('; ');
      } else if (typeof data.detail === 'string') {
        errMsg = data.detail;
      } else {
        errMsg = JSON.stringify(data);
      }
      const err = new Error(errMsg);
      err.status = resp.status;
      throw err;
    }
    return data;
  };

  // ────────────────────────────────────────────────────────────────
  //  jsonFetch — transparent 401 retry via refresh
  // ────────────────────────────────────────────────────────────────
  const jsonFetch = async (url, opts = {}) => {
    try {
      return await _rawFetch(url, opts);
    } catch (err) {
      if (err.status === 401 && getRefreshToken()) {
        try {
          await _doRefresh();
          return await _rawFetch(url, opts);   // retry once
        } catch (_) {
          _forceLocalLogout();
          throw err;
        }
      }
      throw err;
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Logout  (server revoke → local wipe → redirect)
  // ────────────────────────────────────────────────────────────────
  const _forceLocalLogout = () => {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(EXPIRY_KEY);
    _cancelRefresh();
    location.href = '/';
  };

  const logout = async () => {
    const rt = getRefreshToken();
    if (rt) {
      try {
        await _rawFetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: rt }),
        });
      } catch (_) { /* best-effort */ }
    }
    // Notify all sibling tabs
    if (_bc) _bc.postMessage({ type: 'logout' });
    _forceLocalLogout();
  };

  // ── Cross-tab listener ────────────────────────────────────────
  if (_bc) {
    _bc.onmessage = (ev) => {
      if (ev.data?.type === 'logout') _forceLocalLogout();
    };
  }

  // ────────────────────────────────────────────────────────────────
  //  Role-based routing
  // ────────────────────────────────────────────────────────────────
  const roleRoute = (roles) => {
    if (Array.isArray(roles) && roles.includes('admin')) return '/dashboard';
    if (roles === 'admin') return '/dashboard';
    return '/dashboard';
  };

  // ────────────────────────────────────────────────────────────────
  //  i18n
  // ────────────────────────────────────────────────────────────────
  const setLang = (lang) => localStorage.setItem(LANG_KEY, lang || 'it');
  const getLang = ()     => localStorage.getItem(LANG_KEY) || 'it';

  let _strings = {};
  const t = (key, fb) => _strings[key] || fb || key;

  const applyI18n = async (force = false) => {
    const lang = getLang();
    try {
      const catalog = await jsonFetch(`/api/lang/strings?lang=${encodeURIComponent(lang)}`);
      _strings = catalog.strings || {};
      if (force) console.log('i18n loaded:', Object.keys(_strings).length, 'keys');

      document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.getAttribute('data-i18n');
        if (_strings[k]) { el.textContent = _strings[k]; el.setAttribute('data-translated', 'true'); }
      });
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const k = el.getAttribute('data-i18n-placeholder');
        if (_strings[k]) el.placeholder = _strings[k];
      });
      document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const k = el.getAttribute('data-i18n-title');
        if (_strings[k]) el.title = _strings[k];
      });
      document.documentElement.lang = lang;
      return _strings;
    } catch (e) {
      console.error('i18n load error:', e);
      return {};
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Template loader
  // ────────────────────────────────────────────────────────────────
  const getTemplate = async (tpl, section = '') => {
    try {
      if (!tpl) return null;
      const r = await jsonFetch(`/api/template/${tpl}`);
      if (r.error) return null;
      const tmpl = r.template || {};
      return section ? tmpl.sections?.[section] || null : { template: tmpl, section };
    } catch (e) {
      console.error('template load error:', e);
      return null;
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Communication signature  (HMAC-SHA-256 canonical form)
  // ────────────────────────────────────────────────────────────────
  const makeCommSignature = async (msg, secret) => {
    const payload   = JSON.stringify(msg.payload || {}, Object.keys(msg.payload || {}).sort());
    const canonical = `${msg.sender}|${msg.recipient}|${msg.msg_type}|${payload}|${msg.nonce}|${msg.ts}`;
    const enc       = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(canonical));
    return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // ────────────────────────────────────────────────────────────────
  //  Platform version badge  (auto-populated from /api/status)
  // ────────────────────────────────────────────────────────────────
  let _versionCache = null;

  /**
   * Fetch platform version from /api/status and populate every
   * element with id="tplVersionBadge" or class="tpl-version-badge".
   * Caches the response for the session to avoid redundant fetches.
   */
  const populateVersionBadge = async () => {
    try {
      if (!_versionCache) {
        const res = await fetch('/api/status', { cache: 'no-store' });
        if (!res.ok) return;
        const data = await res.json();
        _versionCache = data.platform || null;
      }
      if (!_versionCache) return;

      const v = _versionCache;
      const label  = v.full_version ? `v${v.full_version}` : (v.version ? `v${v.version}` : null);
      if (!label) return;

      const badges = document.querySelectorAll('#tplVersionBadge, .tpl-version-badge');
      badges.forEach(el => {
        el.textContent = label;
        if (v.codename) el.title = `${v.codename} — build ${v.build || '?'}`;
      });
    } catch (_) { /* API unavailable — keep static badge text */ }
  };

  /** Return cached version info or null. */
  const getVersion = () => _versionCache;

  // ────────────────────────────────────────────────────────────────
  //  Public API
  // ────────────────────────────────────────────────────────────────
  window.TPL = {
    // Token management
    token:          getToken,
    setToken,
    setRefreshToken,
    getRefreshToken,
    setSessionId,
    getSessionId,
    authHeader,

    // Network
    jsonFetch,

    // Auth lifecycle
    logout,
    refreshNow: _doRefresh,

    // Navigation
    roleRoute,

    // i18n
    setLang, getLang, t, applyI18n,

    // Version
    getVersion,
    populateVersionBadge,

    // Utilities
    getTemplate,
    makeCommSignature,
    log: (m) => console.log('[TPL]', m),
  };

  // ── Boot ──────────────────────────────────────────────────────
  window.addEventListener('load', () => {
    TPL.applyI18n(false);
    // Restore refresh schedule from surviving session
    const exp = sessionStorage.getItem(EXPIRY_KEY);
    if (exp) _scheduleRefresh(parseInt(exp, 10));
    // Populate version badges from API
    TPL.populateVersionBadge();
  });
})();
