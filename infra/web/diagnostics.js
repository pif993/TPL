/**
 * TPL Platform — Diagnostica Sistema  (v3.5.0)
 *
 * Live health checks, OTA integrity verification,
 * module listing and security summary.
 *
 * Requires: app.js, sidebar.js, tpl-nav.js
 */
(() => {
  'use strict';

  const API = '/api';

  const log = [];
  const addLog = (msg) => {
    const ts = new Date().toLocaleTimeString('it-IT');
    log.push(`[${ts}] ${msg}`);
    const el = document.getElementById('diagLog');
    if (el) el.textContent = log.join('\n');
    el?.scrollTo(0, el.scrollHeight);
  };

  /* ── Version Info ───────────────────────────────────────── */
  async function loadVersion() {
    try {
      const d = await TPL.jsonFetch(`${API}/ota/status`);
      document.getElementById('diagVersion').textContent = d.current_version || '—';
      document.getElementById('diagVersionBadge').textContent = `v${d.current_version}`;

      // Full version details from /health (public endpoint)
      try {
        const resp = await fetch(`${API}/health`);
        const dh = resp.ok ? await resp.json() : {};
        document.getElementById('diagCodename').textContent = dh.codename || d.current_version;
        document.getElementById('diagBuild').textContent = dh.build || '—';
        document.getElementById('diagChannel').textContent = dh.channel || 'stable';
      } catch {
        document.getElementById('diagCodename').textContent = '—';
        document.getElementById('diagBuild').textContent = '—';
        document.getElementById('diagChannel').textContent = '—';
      }
    } catch (e) {
      addLog(`ERRORE caricamento versione: ${e.message}`);
    }
  }

  /* ── Health Checks ──────────────────────────────────────── */
  function setCheck(id, passed, detail, latency) {
    const icon = document.getElementById(`icon${id}`);
    const badge = document.getElementById(`badge${id}`);
    const lat = document.getElementById(`lat${id}`);
    if (icon) {
      icon.classList.remove('text-secondary', 'text-success', 'text-danger');
      icon.classList.add(passed ? 'text-success' : 'text-danger');
    }
    if (badge) {
      badge.className = `badge ${passed ? 'bg-success' : 'bg-danger'}`;
      badge.textContent = passed ? 'OK' : 'ERRORE';
    }
    if (lat) lat.textContent = detail || (latency >= 0 ? `${latency}ms` : '');
  }

  window.runDiagnostics = async function () {
    const btn = document.getElementById('btnRunDiag');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Analisi in corso…';
    log.length = 0;
    addLog('═══ Diagnostica Sistema avviata ═══');

    try {
      /* 1. OTA Health — GET (was incorrectly POST) */
      addLog('▸ Esecuzione health check OTA…');
      try {
        const d = await TPL.jsonFetch(`${API}/ota/health`);
        addLog(`  Health check completato: ${d.passed}/${d.total_checks} controlli superati`);

        const checkMap = { api_health: 'Api', ota_engine: 'Ota', filesystem_writable: 'Fs', keys_accessible: 'Keys' };
        (d.checks || []).forEach((c) => {
          const uiId = checkMap[c.check];
          if (uiId) {
            setCheck(uiId, c.passed, c.detail, c.latency_ms);
            addLog(`  [${c.check}] ${c.passed ? '✓' : '✗'} ${c.detail}`);
          }
        });

        if (d.healthy) {
          addLog('  ★ Sistema in salute');
        } else {
          addLog('  ⚠ Problemi rilevati!');
        }
      } catch (e) {
        addLog(`  ✗ Health check fallito: ${e.message}`);
        setCheck('Api', false, e.message);
      }

      /* 2. OTA Status / Security */
      addLog('▸ Raccolta stato sicurezza OTA…');
      try {
        const ds = await TPL.jsonFetch(`${API}/ota/status`);
        const sec = ds.security || {};

        document.getElementById('securitySummary').innerHTML = `
          <div class="row g-3">
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi ${sec.require_signature ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'} fs-5"></i>
                <span>Firma Ed25519 ${sec.require_signature ? 'richiesta' : 'non richiesta'}</span>
              </div>
            </div>
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi ${sec.require_checksum ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'} fs-5"></i>
                <span>Checksum SHA-256 ${sec.require_checksum ? 'attivo' : 'disattivo'}</span>
              </div>
            </div>
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi ${sec.publisher_key_loaded ? 'bi-key-fill text-success' : 'bi-key text-danger'} fs-5"></i>
                <span>Chiave publisher ${sec.publisher_key_loaded ? 'caricata' : 'mancante'}</span>
              </div>
            </div>
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi bi-fingerprint text-info fs-5"></i>
                <span>Fingerprint: <code>${(sec.publisher_fingerprint || '—').slice(0, 16)}</code></span>
              </div>
            </div>
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi bi-journal-text text-warning fs-5"></i>
                <span>Audit entries: <strong>${sec.audit_entries || 0}</strong></span>
              </div>
            </div>
            <div class="col-md-4">
              <div class="d-flex align-items-center gap-2">
                <i class="bi ${sec.quarantine_files > 0 ? 'bi-exclamation-triangle text-warning' : 'bi-shield-check text-success'} fs-5"></i>
                <span>File in quarantena: <strong>${sec.quarantine_files || 0}</strong></span>
              </div>
            </div>
          </div>
        `;
        addLog(`  Firma: ${sec.require_signature ? 'ON' : 'OFF'}, Checksum: ${sec.require_checksum ? 'ON' : 'OFF'}`);
        addLog(`  Publisher key: ${sec.publisher_key_loaded ? 'OK' : 'MANCANTE'}`);
        addLog(`  Audit entries: ${sec.audit_entries || 0}, Quarantena: ${sec.quarantine_files || 0}`);

        // Enable verify button if an install was done
        try {
          const di = await TPL.jsonFetch(`${API}/ota/install/status`);
          if (di.status === 'applied' || di.status === 'finalized') {
            document.getElementById('btnVerifyOta').disabled = false;
            addLog(`  Install status: ${di.status} (tag: ${di.tag}) — verifica disponibile`);
          }
        } catch { /* no install active */ }
      } catch (e) {
        addLog(`  Stato OTA non disponibile: ${e.message}`);
      }

      /* 3. Modules — /engines/registry (not /engines) */
      addLog('▸ Elencazione moduli caricati…');
      try {
        const dm = await TPL.jsonFetch(`${API}/engines/registry`);
        const engines = dm.engines || dm || [];
        if (Array.isArray(engines) && engines.length > 0) {
          document.getElementById('modulesList').innerHTML = engines
            .map((e) => {
              const name = typeof e === 'string' ? e : e.name || e.id || '?';
              const status = typeof e === 'object' && e.status ? e.status : 'loaded';
              const cls = status === 'loaded' ? 'bg-success' : status === 'error' ? 'bg-danger' : 'bg-primary';
              return `<span class="badge ${cls} me-1 mb-1">${name}</span>`;
            })
            .join('');
          addLog(`  ${engines.length} moduli trovati`);
        } else {
          document.getElementById('modulesList').innerHTML = '<span class="text-body-secondary">Nessun modulo rilevato</span>';
          addLog('  Nessun modulo rilevato');
        }
      } catch (e) {
        addLog(`  Endpoint moduli non disponibile: ${e.message}`);
        document.getElementById('modulesList').innerHTML = `<span class="text-danger">Errore: ${e.message}</span>`;
      }

      addLog('═══ Diagnostica completata ═══');
    } catch (e) {
      addLog(`ERRORE CRITICO: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-play-circle me-1"></i> Esegui Diagnostica';
      document.getElementById('diagTimestamp').textContent = new Date().toLocaleString('it-IT');
    }
  };

  /* ── OTA Install Verify ─────────────────────────────────── */
  window.runOtaVerify = async function () {
    const btn = document.getElementById('btnVerifyOta');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Verifica…';
    addLog('');
    addLog('═══ Verifica Integrità OTA ═══');

    try {
      const d = await TPL.jsonFetch(`${API}/ota/install/verify`, { method: 'POST' });

      {
        const s = d.summary || {};
        addLog(`  Stato: ${d.status}`);
        addLog(`  File verificati: ${s.verified_ok}/${s.total_files}`);
        addLog(`  Tampered: ${s.tampered}, Missing: ${s.missing}, Errori: ${s.errors}`);
        addLog(`  Protetti (skip): ${s.skipped_protected}`);
        addLog(`  Bytes controllati: ${s.bytes_checked_human}`);

        const vc = d.version_check || {};
        addLog(`  Versione — runtime: ${vc.details?.runtime}, disco: ${vc.details?.on_disk}, manifest: ${vc.details?.manifest}`);
        addLog(`  Versione consistente: ${vc.consistent ? 'SÌ ✓' : 'NO ✗'}`);

        if (d.integrity_passed) {
          addLog('  ★ INTEGRITÀ VERIFICATA — tutti i file corrispondono ai checksum attesi');
        } else {
          addLog('  ⚠ PROBLEMI DI INTEGRITÀ RILEVATI');
          (d.tampered_files || []).forEach((t) => {
            addLog(`    ✗ ${t.file}: atteso ${t.expected_sha256}, trovato ${t.actual_sha256}`);
          });
        }
      addLog('═══ Verifica completata ═══');
    } catch (e) {
      addLog(`ERRORE: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-patch-check me-1"></i> Verifica Integrità OTA';
    }
  };

  /* ── Init ───────────────────────────────────────────────── */
  // Auth + sidebar handled by tpl-nav.js; load version when ready
  if (window.TPLNav) {
    TPLNav.onReady(() => loadVersion());
  } else {
    document.addEventListener('DOMContentLoaded', loadVersion);
  }
})();
