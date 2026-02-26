/**
 * TPL — Advanced & Security page controller
 * Extracted from inline script in advanced.html
 */
(() => {
  'use strict';

  const esc = (s) =>
    String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  /* ── Engine Status ──────────────────────────────────────────── */
  async function loadEngineStatus() {
    const c = document.getElementById('engineStatusContainer');
    if (!c) return;
    try {
      const data = await TPL.jsonFetch('/api/status');
      const engines = data.engines || {};
      const names = Object.keys(engines);
      if (!names.length) {
        c.innerHTML = '<p class="text-muted">Nessun engine registrato.</p>';
        return;
      }
      let html =
        '<div class="table-responsive"><table class="ov-table"><thead><tr>' +
        '<th>Engine</th><th>Stato</th><th>Info</th></tr></thead><tbody>';
      for (const name of names.sort()) {
        const e = engines[name];
        const ok = e.status === 'ok' || e.healthy === true;
        const badge = ok
          ? '<span class="badge bg-success">OK</span>'
          : '<span class="badge bg-danger">ERR</span>';
        const info = e.version || e.uptime || e.detail || '—';
        html +=
          '<tr><td>' + esc(name) + '</td><td>' + badge +
          '</td><td class="text-muted adv-info-cell">' +
          esc(String(info)) + '</td></tr>';
      }
      html += '</tbody></table></div>';
      c.innerHTML = html;
    } catch (e) {
      c.innerHTML =
        '<p class="text-danger">Errore caricamento: ' + esc(e.message) + '</p>';
    }
  }

  /* ── Security Status ────────────────────────────────────────── */
  async function loadSecurityStatus() {
    const c = document.getElementById('securityStatusContainer');
    if (!c) return;
    try {
      const data = await TPL.jsonFetch('/api/security/status');
      let html = '<div class="row g-2">';
      html +=
        '<div class="col-6 col-md-3"><div class="text-center p-2">' +
        '<div class="fw-bold fs-5">' + (data.requests_total ?? 0) +
        '</div><div class="adv-stat-label">Richieste Totali</div></div></div>';
      html +=
        '<div class="col-6 col-md-3"><div class="text-center p-2">' +
        '<div class="fw-bold fs-5 text-danger">' + (data.blocked_requests_total ?? 0) +
        '</div><div class="adv-stat-label">Bloccate</div></div></div>';
      html +=
        '<div class="col-6 col-md-3"><div class="text-center p-2">' +
        '<div class="fw-bold fs-5 text-warning">' + (data.xss_blocked ?? 0) +
        '</div><div class="adv-stat-label">XSS Bloccati</div></div></div>';
      html +=
        '<div class="col-6 col-md-3"><div class="text-center p-2">' +
        '<div class="fw-bold fs-5 text-warning">' + (data.sqli_blocked ?? 0) +
        '</div><div class="adv-stat-label">SQLi Bloccati</div></div></div>';
      html += '</div>';
      if (data.waf_enabled === false) {
        html +=
          '<div class="alert alert-warning mt-2 mb-0 py-1 px-2 adv-waf-alert">' +
          '<i class="bi bi-exclamation-triangle me-1"></i>WAF disabilitato</div>';
      }
      c.innerHTML = html;
    } catch (e) {
      c.innerHTML =
        '<p class="text-muted adv-info-text">Dati sicurezza non disponibili (' +
        esc(e.message) + ')</p>';
    }
  }

  /* ── System Info ────────────────────────────────────────────── */
  async function loadSystemInfo() {
    const c = document.getElementById('systemInfoContainer');
    if (!c) return;
    try {
      const [health, version] = await Promise.all([
        TPL.jsonFetch('/api/health'),
        TPL.jsonFetch('/api/version/info').catch(() => null),
      ]);
      let html = '<div class="row g-2">';
      html +=
        '<div class="col-6"><strong class="adv-field-label">Health:</strong> ' +
        '<span class="badge ' +
        (health.status === 'ok' ? 'bg-success' : 'bg-warning') + '">' +
        esc(health.status || '?') + '</span></div>';
      if (version) {
        html +=
          '<div class="col-6"><strong class="adv-field-label">Versione:</strong> ' +
          esc(version.version || version.current_version || '?') + '</div>';
        if (version.codename) {
          html +=
            '<div class="col-6"><strong class="adv-field-label">Codename:</strong> ' +
            esc(version.codename) + '</div>';
        }
        if (version.build) {
          html +=
            '<div class="col-6"><strong class="adv-field-label">Build:</strong> ' +
            esc(version.build) + '</div>';
        }
      }
      html +=
        '<div class="col-6"><strong class="adv-field-label">Auth:</strong> ' +
        esc(health.auth_mode || '?') + '</div>';
      html +=
        '<div class="col-6"><strong class="adv-field-label">Secret:</strong> ' +
        (health.secret_source ? esc(health.secret_source) : '—') + '</div>';
      html += '</div>';
      c.innerHTML = html;
    } catch (e) {
      c.innerHTML =
        '<p class="text-danger">Errore: ' + esc(e.message) + '</p>';
    }
  }

  /* ── Audit Log ──────────────────────────────────────────────── */
  async function loadAuditLog() {
    const c = document.getElementById('auditLogContainer');
    if (!c) return;
    try {
      const data = await TPL.jsonFetch('/api/audit/tail?limit=10');
      const entries = data.entries || data || [];
      if (!entries.length) {
        c.innerHTML = '<p class="text-muted">Nessuna voce di audit.</p>';
        return;
      }
      let html =
        '<div class="table-responsive"><table class="ov-table"><thead><tr>' +
        '<th>Ora</th><th>Azione</th><th>Utente</th><th>Risultato</th>' +
        '</tr></thead><tbody>';
      for (const e of entries.slice(-10).reverse()) {
        const ts = e.ts
          ? new Date(e.ts * 1000).toLocaleTimeString('it-IT')
          : '—';
        html +=
          '<tr><td class="adv-ts-cell">' + esc(ts) + '</td>' +
          '<td class="adv-action-cell">' + esc(e.action || '—') + '</td>' +
          '<td class="adv-action-cell">' + esc(e.user || e.sub || '—') + '</td>' +
          '<td>' +
          (e.result === 'success'
            ? '<i class="bi bi-check-circle text-success"></i>'
            : '<i class="bi bi-x-circle text-danger"></i>') +
          '</td></tr>';
      }
      html += '</tbody></table></div>';
      c.innerHTML = html;
    } catch (_e) {
      c.innerHTML =
        '<p class="text-muted adv-info-text">Log audit non disponibili.</p>';
    }
  }

  /* ── Expose for onclick handlers ────────────────────────────── */
  window.loadEngineStatus = loadEngineStatus;
  window.loadSecurityStatus = loadSecurityStatus;
  window.loadSystemInfo = loadSystemInfo;
  window.loadAuditLog = loadAuditLog;

  /* ── Init: load all panels + sidebar auth ───────────────────── */
  document.addEventListener('DOMContentLoaded', () => {
    loadEngineStatus();
    loadSecurityStatus();
    loadSystemInfo();
    loadAuditLog();
  });

  (async () => {
    try {
      const me = await TPL.jsonFetch('/api/me');
      if (me.roles && me.roles.includes('admin')) {
        TPLSidebar.setAdmin(true);
      }
      TPLSidebar.setUser(me.sub || '—');
      if (typeof TPL.applyI18n === 'function') TPL.applyI18n();
    } catch (_e) {
      location.href = '/';
    }
  })();
})();
