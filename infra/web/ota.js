/**
 * TPL Platform — OTA Update Center v5.0
 *
 * Smart Pipeline: fully automated GUI-only update system.
 * Single-button orchestration: Check → Prepare → Verify → Apply → Finalize.
 * No terminal intervention required.
 */
(() => {
  'use strict';

  const q = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

  let _state = {};
  let _releases = [];
  let _selectedTag = null;
  let _pipelineRunning = false;
  let _pipelineAborted = false;

  /* ── Pipeline Step Names ───────────────────────────────────── */
  const STEPS = ['check', 'prepare', 'verify', 'apply', 'finalize'];

  /* ── Helpers ───────────────────────────────────────────────── */
  const fmtDate = (iso) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('it-IT', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    catch { return iso; }
  };

  const fmtDateShort = (iso) => {
    if (!iso) return 'mai';
    try { return new Date(iso).toLocaleString('it-IT', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' }); }
    catch { return iso; }
  };

  const showToast = (msg, type = 'info') => {
    const el = q('otaToast');
    if (!el) return;
    el.className = `alert alert-${type} alert-dismissible fade show`;
    el.style.position = 'fixed'; el.style.bottom = '1rem'; el.style.right = '1rem';
    el.style.zIndex = '9999'; el.style.maxWidth = '420px';
    el.innerHTML = `${msg}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
    setTimeout(() => { el.className = 'd-none'; }, 6000);
  };

  const renderMarkdown = (text) => {
    return esc(text)
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/^### (.*)/gm, '<h6 class="mt-2 mb-1">$1</h6>')
      .replace(/^## (.*)/gm, '<h5 class="mt-2 mb-1">$1</h5>')
      .replace(/^# (.*)/gm, '<h4 class="mt-2 mb-1">$1</h4>')
      .replace(/^- (.*)/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
      .replace(/\n/g, '<br>');
  };

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  /* ═══════════════════════════════════════════════════════════════
   *  PIPELINE STEPPER UI
   * ═══════════════════════════════════════════════════════════════ */

  const setStepState = (stepName, state) => {
    // state: 'pending' | 'active' | 'done' | 'error' | 'skipped'
    const stepEl = document.querySelector(`.ota-pipe-step[data-step="${stepName}"]`);
    if (!stepEl) return;
    stepEl.className = `ota-pipe-step ota-pipe-step--${state}`;
  };

  const resetStepper = () => {
    STEPS.forEach(s => setStepState(s, 'pending'));
    // Reset lines
    document.querySelectorAll('.ota-pipe-step-line').forEach(l => {
      l.className = 'ota-pipe-step-line';
    });
  };

  const fillLineBefore = (stepName) => {
    const idx = STEPS.indexOf(stepName);
    if (idx <= 0) return;
    const lines = document.querySelectorAll('.ota-pipe-step-line');
    if (lines[idx - 1]) lines[idx - 1].classList.add('ota-pipe-step-line--done');
  };

  const pipeLog = (msg, type = 'info') => {
    const wrap = q('otaPipeLogWrap');
    const log = q('otaPipeLog');
    if (!wrap || !log) return;
    wrap.style.display = '';
    const ts = new Date().toLocaleTimeString('it-IT');
    const cls = { info: '', ok: 'text-success', error: 'text-danger', warn: 'text-warning' }[type] || '';
    const icon = { info: 'bi-info-circle', ok: 'bi-check-circle-fill', error: 'bi-x-circle-fill', warn: 'bi-exclamation-triangle-fill' }[type] || 'bi-info-circle';
    log.innerHTML += `<div class="ota-pipe-log-line ${cls}"><span class="ota-pipe-log-ts">${ts}</span><i class="bi ${icon}"></i> ${esc(msg)}</div>`;
    log.scrollTop = log.scrollHeight;
  };

  const setPipelineStatus = (html) => {
    const el = q('otaPipeStatus');
    if (el) el.innerHTML = html;
  };

  const setPipelinePill = (text, cls = '') => {
    const pill = q('otaPipePill');
    if (pill) { pill.textContent = text; pill.className = `ota-pipe-pill ${cls}`; }
  };

  const updateCta = (icon, text, disabled = false, variant = '') => {
    const btn = q('otaPipeCta');
    const ico = q('otaPipeCtaIcon');
    const txt = q('otaPipeCtaText');
    if (btn) { btn.disabled = disabled; btn.className = `ota-pipe-cta ${variant}`; }
    if (ico) ico.className = `bi bi-${icon}`;
    if (txt) txt.textContent = text;
  };

  /* ═══════════════════════════════════════════════════════════════
   *  CORE: Load Status
   * ═══════════════════════════════════════════════════════════════ */

  const loadStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/status');
      _state = data;

      // Hero: Current version
      const curEl = q('otaHeroCurrentVer');
      if (curEl) curEl.textContent = `v${data.current_version || '?'}`;

      // Hero: Latest version + arrow
      if (data.update_available && data.latest_version) {
        q('otaHeroArrow')?.style.setProperty('display', '');
        const newEl = q('otaHeroNewVer');
        if (newEl) newEl.style.display = '';
        const latEl = q('otaHeroLatestVer');
        if (latEl) latEl.textContent = `v${data.latest_version}`;
      } else {
        q('otaHeroArrow')?.style.setProperty('display', 'none');
        q('otaHeroNewVer')?.style.setProperty('display', 'none');
      }

      // Repo status warning
      const repoWarn = q('otaRepoStatus');
      if (repoWarn) {
        if (data.repo_status === 'not_found') {
          repoWarn.style.display = '';
          repoWarn.innerHTML = `<div class="alert alert-warning py-1 px-2 small mb-2">
            <i class="bi bi-exclamation-triangle-fill"></i>
            Repository non trovato o non ancora pubblico. Le release GitHub non sono disponibili.
            Puoi usare i <strong>Test Update</strong> per verificare il sistema OTA.
          </div>`;
        } else {
          repoWarn.style.display = 'none';
        }
      }

      // Config fields
      const cfgAuto = q('otaCfgAuto');
      const cfgInterval = q('otaCfgInterval');
      const cfgBranch = q('otaCfgBranch');
      const cfgPre = q('otaCfgPre');
      if (cfgAuto) cfgAuto.checked = data.auto_check !== false;
      if (cfgInterval) cfgInterval.value = data.check_interval_minutes || 60;
      if (cfgBranch) cfgBranch.value = data.branch || 'main';
      if (cfgPre) cfgPre.checked = !!data.pre_release;

      // Update CTA based on state
      if (!_pipelineRunning) {
        if (data.update_available) {
          updateCta('rocket-takeoff-fill', 'Aggiorna ora', false, 'ota-pipe-cta--go');
        } else {
          updateCta('arrow-repeat', 'Verifica aggiornamenti', false, '');
        }
      }

      return data;
    } catch (error) {
      console.warn('OTA status load failed:', error);
      return null;
    }
  };

  /* ══ Check for updates ═════════════════════════════════════════ */
  const checkUpdates = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/check', { method: 'POST' });
      await loadStatus();
      loadReleases();
      if (data.repo_status === 'not_found' && !data.update_available) {
        showToast('Repository GitHub non trovato — nessuna release disponibile. Usa Test Update per provare il sistema.', 'warning');
      } else if (data.update_available) {
        showToast(`Aggiornamento disponibile: v${data.latest_version}`, 'success');
      } else {
        showToast('Piattaforma aggiornata, nessun update disponibile.', 'info');
      }
      return data;
    } catch (error) {
      showToast(`Controllo OTA fallito: ${error}`, 'danger');
      throw error;
    }
  };

  /* ══ Load releases ═════════════════════════════════════════════ */
  const loadReleases = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/releases');
      _releases = data.releases || [];

      const pill = q('otaRelPill');
      if (pill) pill.textContent = `${_releases.length}`;

      const container = q('otaReleaseList');
      if (!container) return;

      if (!_releases.length) {
        const repoNotFound = _state.repo_status === 'not_found';
        container.innerHTML = `<div class="text-center p-3 text-muted small">
          <i class="bi bi-inbox" style="font-size:1.4rem;opacity:.3;display:block;margin-bottom:.3rem"></i>
          ${repoNotFound
            ? 'Repository GitHub non disponibile. Usa <strong>Test Update</strong> per provare il sistema OTA.'
            : 'Nessuna release trovata. Premi "Verifica aggiornamenti".'}
        </div>`;
        return;
      }

      // Compact table-style list
      container.innerHTML = `<div class="ota-pipe-releases">
        ${_releases.map((r, idx) => `
          <div class="ota-pipe-rel ${r.is_current ? 'ota-pipe-rel--current' : ''} ${r.is_newer ? 'ota-pipe-rel--newer' : ''} ${r.is_prepared ? 'ota-pipe-rel--prepared' : ''}"
               data-tag="${esc(r.tag)}" style="animation:otaPipeFadeIn .25s ease-out ${idx * 40}ms both">
            <div class="ota-pipe-rel-tag">${esc(r.tag)}</div>
            <div class="ota-pipe-rel-badges">
              ${r.is_current ? '<span class="badge bg-primary">Corrente</span>' : ''}
              ${r.is_newer ? '<span class="badge bg-success">Nuovo</span>' : ''}
              ${r.prerelease ? '<span class="badge bg-warning text-dark">Pre</span>' : ''}
              ${r.is_prepared ? '<span class="badge bg-info text-dark">Pronto</span>' : ''}
            </div>
            <div class="ota-pipe-rel-date">${fmtDateShort(r.published_at)}</div>
            <div class="ota-pipe-rel-actions">
              <button class="ota-pipe-btn ota-pipe-btn--xs" data-detail="${esc(r.tag)}" type="button"><i class="bi bi-info-circle"></i></button>
              ${r.is_newer && r.is_prepared ? `<button class="ota-pipe-btn ota-pipe-btn--xs ota-pipe-btn--primary" data-auto-update="${esc(r.tag)}" type="button" title="Aggiorna automaticamente"><i class="bi bi-rocket-takeoff-fill"></i></button>` : ''}
              ${r.is_newer && !r.is_prepared ? `<button class="ota-pipe-btn ota-pipe-btn--xs" data-prepare="${esc(r.tag)}" type="button" title="Prepara"><i class="bi bi-download"></i></button>` : ''}
            </div>
          </div>
        `).join('')}
      </div>`;

      // Attach listeners
      container.querySelectorAll('[data-detail]').forEach(btn =>
        btn.addEventListener('click', () => showDetail(btn.dataset.detail))
      );
      container.querySelectorAll('[data-prepare]').forEach(btn =>
        btn.addEventListener('click', () => prepare(btn.dataset.prepare))
      );
      container.querySelectorAll('[data-auto-update]').forEach(btn =>
        btn.addEventListener('click', () => runPipeline(btn.dataset.autoUpdate))
      );
    } catch (error) {
      console.warn('loadReleases failed:', error);
    }
  };

  /* ══ Show detail ═══════════════════════════════════════════════ */
  const showDetail = async (tag) => {
    _selectedTag = tag;
    const panel = q('otaDetailPanel');
    const container = q('otaDetailContent');
    if (!panel || !container) return;

    panel.classList.remove('d-none');
    container.innerHTML = '<div class="text-center p-3"><i class="bi bi-hourglass-split ota-pipe-spin"></i> Caricamento…</div>';

    try {
      const [detail, diff] = await Promise.all([
        TPL.jsonFetch(`/api/ota/release/${encodeURIComponent(tag)}`),
        TPL.jsonFetch(`/api/ota/diff/${encodeURIComponent(tag)}`).catch(() => null),
      ]);

      let html = `
        <div class="mb-2">
          <h5 class="mb-1"><i class="bi bi-tag"></i> ${esc(detail.name || tag)}</h5>
          <div class="d-flex flex-wrap gap-1 mb-2">
            <span class="badge bg-secondary">${esc(tag)}</span>
            ${detail.is_current ? '<span class="badge bg-primary">Corrente</span>' : ''}
            ${detail.is_newer ? '<span class="badge bg-success">Aggiornamento</span>' : ''}
            ${detail.prerelease ? '<span class="badge bg-warning text-dark">Pre-release</span>' : ''}
            ${detail.is_prepared ? '<span class="badge bg-info text-dark">Preparato</span>' : ''}
          </div>
          <div class="small text-muted mb-2">
            <i class="bi bi-calendar3"></i> ${fmtDate(detail.published_at)}
            ${detail.author ? ` · <i class="bi bi-person"></i> ${esc(detail.author)}` : ''}
            ${detail.html_url ? ` · <a href="${esc(detail.html_url)}" target="_blank" rel="noopener"><i class="bi bi-github"></i> GitHub</a>` : ''}
          </div>
        </div>

        ${detail.body ? `<div class="ota-pipe-release-notes mb-2">${renderMarkdown(detail.body)}</div>` : ''}`;

      // Changed files
      if (detail.changed_files?.length) {
        const categories = {};
        detail.changed_files.forEach(f => {
          const cat = f.category || 'Altro';
          if (!categories[cat]) categories[cat] = [];
          categories[cat].push(f);
        });
        html += `<details class="mb-2"><summary class="small fw-semibold"><i class="bi bi-files"></i> File nell'aggiornamento (${detail.changed_files.length})</summary>
          <div class="mt-1">${Object.entries(categories).map(([cat, files]) => `
            <div class="mb-1"><span class="small text-muted">${esc(cat)} (${files.length})</span>
              ${files.map(f => `<div class="small"><code>${esc(f.file)}</code></div>`).join('')}
            </div>
          `).join('')}</div>
        </details>`;
      }

      // Diff
      if (diff && diff.commits?.length) {
        html += `<details class="mb-2"><summary class="small fw-semibold"><i class="bi bi-git"></i> ${diff.total_commits || 0} commit, ${diff.files_changed?.length || 0} file</summary>
          <div class="mt-1">${diff.commits.slice(0, 10).map(c => `
            <div class="small"><code class="me-1">${esc(c.sha)}</code>${esc(c.message)}</div>
          `).join('')}
          ${diff.commits.length > 10 ? `<div class="text-muted small">… e altri ${diff.commits.length - 10}</div>` : ''}
          </div>
        </details>`;
      }

      // Actions
      html += `<div class="d-flex gap-2 mt-2">
        ${detail.is_newer && detail.is_prepared ?
          `<button class="ota-pipe-btn ota-pipe-btn--primary" id="otaDetailUpdateBtn" type="button"><i class="bi bi-rocket-takeoff-fill"></i> Aggiorna automaticamente</button>` :
          detail.is_newer && !detail.is_prepared ?
          `<button class="ota-pipe-btn ota-pipe-btn--primary" id="otaDetailPrepareBtn" type="button"><i class="bi bi-download"></i> Prepara aggiornamento</button>` : ''}
        ${detail.is_prepared ? `<button class="ota-pipe-btn ota-pipe-btn--sm" id="otaDetailCleanupBtn" type="button"><i class="bi bi-trash"></i> Rimuovi</button>` : ''}
      </div>`;

      container.innerHTML = html;

      q('otaDetailUpdateBtn')?.addEventListener('click', () => {
        panel.classList.add('d-none');
        runPipeline(tag);
      });
      q('otaDetailPrepareBtn')?.addEventListener('click', () => prepare(tag));
      q('otaDetailCleanupBtn')?.addEventListener('click', () => cleanupStaging(tag));

      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      container.innerHTML = `<div class="text-danger p-3"><i class="bi bi-exclamation-triangle"></i> ${esc(String(error))}</div>`;
    }
  };

  /* ══ Prepare ═══════════════════════════════════════════════════ */
  const prepare = async (tag) => {
    setPipelineStatus(`<span class="text-primary small"><i class="bi bi-download ota-pipe-spin"></i> Preparazione ${esc(tag)}…</span>`);
    try {
      const data = await TPL.jsonFetch(`/api/ota/prepare/${encodeURIComponent(tag)}`, { method: 'POST' });
      showToast(`${tag} preparato: ${data.file_count || 0} file (${data.size_human || '?'})`, 'success');
      await loadStatus();
      loadReleases();
      return data;
    } catch (error) {
      showToast(`Preparazione ${tag} fallita: ${error}`, 'danger');
      throw error;
    }
  };

  /* ══ Cleanup staging ═══════════════════════════════════════════ */
  const cleanupStaging = async (tag) => {
    if (!confirm(`Rimuovere staging per ${tag}?`)) return;
    try {
      await TPL.jsonFetch(`/api/ota/staging/${encodeURIComponent(tag)}`, { method: 'DELETE' });
      showToast(`Staging ${tag} rimosso`, 'success');
      q('otaDetailPanel')?.classList.add('d-none');
      await loadStatus();
      loadReleases();
    } catch (e) { showToast(`Errore: ${e}`, 'danger'); }
  };

  /* ══ Save config ═══════════════════════════════════════════════ */
  const saveConfig = async () => {
    try {
      const cfg = {
        auto_check: q('otaCfgAuto')?.checked ?? true,
        check_interval_minutes: parseInt(q('otaCfgInterval')?.value || '60', 10),
        branch: q('otaCfgBranch')?.value || 'main',
        pre_release: q('otaCfgPre')?.checked ?? false,
      };
      await TPL.jsonFetch('/api/ota/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      const res = q('otaCfgResult');
      if (res) { res.innerHTML = '<span class="text-success"><i class="bi bi-check-lg"></i></span>'; setTimeout(() => { res.textContent = ''; }, 2000); }
    } catch (e) {
      const res = q('otaCfgResult');
      if (res) res.innerHTML = `<span class="text-danger">${esc(String(e))}</span>`;
    }
  };

  /* ══ Changelog ═════════════════════════════════════════════════ */
  const loadChangelog = async () => {
    try {
      const data = await TPL.jsonFetch('/api/version/changelog');
      const el = q('otaChangelog');
      if (!el) return;
      if (!data.entries?.length) { el.innerHTML = '<div class="text-muted small p-2">Nessuna voce</div>'; return; }
      el.innerHTML = data.entries.map(e => `
        <div class="mc-cl-item"><span class="mc-cl-ver">${esc(e.version)}</span><span class="mc-cl-date">${esc(e.date || '')}</span>
        <ul class="mc-cl-list">${(e.changes || []).map(c => `<li class="mc-cl-change">${esc(c)}</li>`).join('')}</ul></div>
      `).join('');
    } catch (e) { const el = q('otaChangelog'); if (el) el.innerHTML = `<span class="text-danger small">${esc(String(e))}</span>`; }
  };

  /* ══ Rollback points ═══════════════════════════════════════════ */
  const loadRollback = async () => {
    try {
      const data = await TPL.jsonFetch('/api/version/rollback-points');
      const el = q('otaRollbackList');
      const pill = q('otaRbPill');
      const pts = data.points || [];
      if (pill) pill.textContent = `${pts.length}`;
      if (!el) return;
      if (!pts.length) { el.innerHTML = '<div class="text-muted small p-2">Nessun punto di rollback</div>'; return; }
      el.innerHTML = pts.map(p => `
        <div class="mc-rb-item"><div class="mc-rb-head"><span class="mc-rb-label">${esc(p.label || p.id)}</span><span class="mc-rb-date">${fmtDate(p.created)}</span></div></div>
      `).join('');
    } catch (e) { const el = q('otaRollbackList'); if (el) el.innerHTML = `<span class="text-danger small">${esc(String(e))}</span>`; }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  SECURITY MODULE
   * ═══════════════════════════════════════════════════════════════ */

  const loadTrustInfo = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/trust-info');

      const badge = q('otaSecBadge');
      if (badge) {
        if (data.publisher_key_loaded) {
          badge.className = 'ota-pipe-sec-badge ota-pipe-sec-badge--ok';
          badge.innerHTML = '<i class="bi bi-shield-fill-check"></i> Protetto';
        } else {
          badge.className = 'ota-pipe-sec-badge ota-pipe-sec-badge--err';
          badge.innerHTML = '<i class="bi bi-shield-fill-exclamation"></i> Chiave mancante';
        }
      }

      const heroBadge = q('otaHeroSecBadge');
      if (heroBadge) {
        heroBadge.innerHTML = data.publisher_key_loaded
          ? `<i class="bi bi-shield-lock-fill"></i> Ed25519 · ${data.audit_entries || 0} audit`
          : '<i class="bi bi-shield-exclamation"></i> Chiave mancante';
      }

      const pubKey = q('otaSecPubKey');
      if (pubKey) pubKey.innerHTML = data.publisher_key_loaded
        ? `<span class="text-success"><i class="bi bi-check-circle-fill"></i></span> <code>${esc((data.publisher_key_fingerprint || '—').substring(0, 12))}…</code>`
        : '<span class="text-danger"><i class="bi bi-x-circle-fill"></i></span>';

      const platKey = q('otaSecPlatKey');
      if (platKey) platKey.innerHTML = data.platform_key_fingerprint
        ? `<span class="text-success"><i class="bi bi-check-circle-fill"></i></span> <code>${esc(data.platform_key_fingerprint.substring(0, 12))}…</code>`
        : '<span class="text-muted">—</span>';

      const algos = q('otaSecAlgo');
      if (algos && data.algorithms) algos.textContent = `${data.algorithms.signing} · ${data.algorithms.hashing}`;

      const chain = q('otaSecChain');
      if (chain) chain.innerHTML = `${data.audit_entries || 0} voci`;

      const status = await TPL.jsonFetch('/api/ota/status');
      if (status) {
        const cfgSig = q('otaSecCfgSig');
        const cfgCheck = q('otaSecCfgCheck');
        const cfgQuar = q('otaSecCfgQuar');
        const cfgRisk = q('otaSecCfgRisk');
        // Fields are now also at top level for convenience
        if (cfgSig) cfgSig.checked = (status.require_signature ?? status.security?.require_signature) !== false;
        if (cfgCheck) cfgCheck.checked = (status.require_checksum ?? status.security?.require_checksum) !== false;
        if (cfgQuar) cfgQuar.checked = (status.quarantine_suspicious ?? status.security?.quarantine_suspicious) !== false;
        if (cfgRisk) cfgRisk.value = status.max_risk_score ?? status.security?.max_risk_score ?? 30;
      }
    } catch (e) { console.warn('Trust info failed:', e); }
  };

  const runSimulation = async () => {
    const btn = q('otaSecSimBtn');
    const results = q('otaSecResults');
    if (!results) return;

    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota-pipe-spin"></i>'; }
    results.className = '';
    results.innerHTML = '<div class="text-center p-3"><i class="bi bi-hourglass-split ota-pipe-spin"></i> Simulazione…</div>';

    try {
      const data = await TPL.jsonFetch('/api/ota/simulate', { method: 'POST' });
      const cert = data.certification || {};
      const scan = data.security_scan || {};
      const pf = data.preflight || [];
      const passedPf = pf.filter(c => c.passed).length;

      let html = `<div class="ota-pipe-sec-results p-3">
        <div class="d-flex align-items-center gap-2 mb-2">
          <span class="badge ${cert.certified ? 'bg-success' : 'bg-danger'}">${cert.certified ? 'CERTIFICATO' : 'NON CERTIFICATO'}</span>
          <span class="small text-muted">${esc(data.tag || '—')}</span>
        </div>
        <div class="ota-pipe-sec-grid">
          <div><i class="bi bi-${cert.signature_verified ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i> Firma Ed25519</div>
          <div><i class="bi bi-${cert.integrity_verified ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i> Integrità SHA-256</div>
          <div><i class="bi bi-${cert.preflight_passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i> Pre-flight (${passedPf}/${pf.length})</div>
          <div><i class="bi bi-${scan.verdict === 'clean' ? 'check-circle-fill text-success' : 'exclamation-triangle-fill text-warning'}"></i> Scan: ${esc(scan.verdict || '—')}</div>
        </div>
        ${data.integrity?.results?.length ? `<details class="mt-2"><summary class="small">Integrità file (${data.integrity.files_checked})</summary>${data.integrity.results.map(f => `<div class="small"><i class="bi bi-${f.passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i> <code>${esc(f.file)}</code></div>`).join('')}</details>` : ''}
      </div>`;
      results.innerHTML = html;
      showToast(cert.certified ? 'Simulazione: CERTIFICATO' : 'Simulazione: NON CERTIFICATO', cert.certified ? 'success' : 'warning');
    } catch (e) {
      results.innerHTML = `<div class="text-danger p-3"><i class="bi bi-exclamation-triangle"></i> ${esc(String(e))}</div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-play-circle"></i> Simula'; }
    }
  };

  const verifyChain = async () => {
    const btn = q('otaSecChainBtn');
    const repairBtn = q('otaSecRepairBtn');
    const results = q('otaSecResults');
    if (!results) return;
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota-pipe-spin"></i>'; }
    results.className = '';
    try {
      const data = await TPL.jsonFetch('/api/ota/security/verify-chain', { method: 'POST' });
      results.innerHTML = `<div class="ota-pipe-sec-results p-3">
        <div class="d-flex align-items-center gap-2 mb-2">
          <span class="badge ${data.valid ? 'bg-success' : 'bg-danger'}">${data.valid ? 'CATENA VALIDA' : 'CATENA COMPROMESSA'}</span>
          <span class="small text-muted">${data.entries || 0} voci</span>
        </div>
        ${data.valid ? '<div class="small text-success"><i class="bi bi-shield-fill-check"></i> Nessuna manomissione rilevata.</div>' :
          data.repairable ? '<div class="small text-warning"><i class="bi bi-wrench"></i> Riparabile automaticamente.</div>' :
          '<div class="small text-danger"><i class="bi bi-shield-fill-exclamation"></i> Possibile manomissione.</div>'}
      </div>`;
      if (repairBtn) repairBtn.style.display = (!data.valid && data.repairable) ? '' : 'none';
      showToast(data.valid ? 'Chain: VALIDA' : 'Chain: COMPROMESSA', data.valid ? 'success' : 'danger');
    } catch (e) {
      results.innerHTML = `<div class="text-danger p-3">${esc(String(e))}</div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-link-45deg"></i> Chain'; }
    }
  };

  const repairChain = async () => {
    const btn = q('otaSecRepairBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota-pipe-spin"></i>'; }
    try {
      const data = await TPL.jsonFetch('/api/ota/security/repair-chain', { method: 'POST' });
      showToast(data.repaired ? `Chain riparata: ${data.repaired_count} voci` : 'Riparazione fallita', data.repaired ? 'success' : 'warning');
      if (data.repaired) { if (btn) btn.style.display = 'none'; await verifyChain(); }
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
    finally { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-wrench"></i> Ripara'; } }
  };

  const saveSecurityConfig = async () => {
    try {
      const cfg = {
        require_signature: q('otaSecCfgSig')?.checked ?? true,
        require_checksum: q('otaSecCfgCheck')?.checked ?? true,
        quarantine_suspicious: q('otaSecCfgQuar')?.checked ?? true,
        max_risk_score: parseInt(q('otaSecCfgRisk')?.value || '30', 10),
      };
      await TPL.jsonFetch('/api/ota/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg) });
      const res = q('otaSecCfgResult');
      if (res) { res.innerHTML = '<span class="text-success"><i class="bi bi-check-lg"></i></span>'; setTimeout(() => { res.textContent = ''; }, 2000); }
    } catch (e) { const res = q('otaSecCfgResult'); if (res) res.innerHTML = `<span class="text-danger">${esc(String(e))}</span>`; }
  };

  const loadLockdownStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/lockdown');
      const el = q('otaLockdownStatus');
      const btn = q('otaLockdownBtn');
      if (data.active) {
        if (el) el.innerHTML = '<i class="bi bi-lock-fill text-danger"></i> <strong class="text-danger">ATTIVO</strong>';
        if (btn) { btn.innerHTML = '<i class="bi bi-unlock-fill"></i> Disattiva'; btn.classList.remove('ota-pipe-btn--danger'); btn.classList.add('ota-pipe-btn--primary'); }
      } else {
        if (el) el.innerHTML = '<i class="bi bi-unlock-fill text-success"></i> Inattivo';
        if (btn) { btn.innerHTML = '<i class="bi bi-lock-fill"></i> Lockdown'; btn.classList.add('ota-pipe-btn--danger'); btn.classList.remove('ota-pipe-btn--primary'); }
      }
    } catch { }
  };

  const toggleLockdown = async () => {
    try {
      const current = await TPL.jsonFetch('/api/ota/security/lockdown');
      const newState = !current.active;
      if (newState && !confirm('Attivare LOCKDOWN? Tutte le operazioni OTA verranno bloccate.')) return;
      await TPL.jsonFetch('/api/ota/security/lockdown', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: newState, reason: newState ? 'manual_lockdown' : 'manual_unlock' }) });
      showToast(newState ? 'Lockdown attivato' : 'Lockdown disattivato', newState ? 'warning' : 'success');
      loadLockdownStatus();
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
  };

  const loadTofuStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/tofu-status');
      const el = q('otaSecTofu');
      if (el) { el.textContent = data.tofu_enabled ? 'Attivo' : 'Disattivato'; el.style.color = data.tofu_enabled ? 'var(--bs-success)' : ''; }
    } catch { }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  SNAPSHOTS
   * ═══════════════════════════════════════════════════════════════ */

  const loadSnapshots = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/rollback/snapshots');
      const el = q('otaSnapshotList');
      const pill = q('otaSnapPill');
      if (pill) pill.textContent = data.total || 0;
      if (!el) return;
      if (!data.snapshots?.length) { el.innerHTML = '<div class="text-muted small p-2">Nessun snapshot</div>'; return; }
      el.innerHTML = data.snapshots.map(s => `
        <div class="d-flex justify-content-between align-items-center p-1">
          <span class="small"><i class="bi bi-camera-fill me-1"></i>${esc(s.snap_id || s.tag || '?')}</span>
          <span class="badge bg-secondary">${s.files_saved || 0} files</span>
        </div>
      `).join('');
    } catch { const el = q('otaSnapshotList'); if (el) el.innerHTML = '<div class="text-muted small p-2">Non disponibile</div>'; }
  };

  const createSnapshot = async () => {
    const btn = q('otaSnapCreateBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota-pipe-spin"></i>'; }
    try {
      await TPL.jsonFetch('/api/ota/rollback/create-snapshot', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tag: `manual-${Date.now()}` }) });
      showToast('Snapshot creato', 'success');
      loadSnapshots();
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
    finally { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-camera"></i> Snapshot'; } }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  TEST UPDATE DELIVERY
   * ═══════════════════════════════════════════════════════════════ */

  const loadTestUpdateInfo = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/info');
      const info = q('otaTestInfo');
      const pill = q('otaTestPill');
      const deliverBtn = q('otaTestDeliverBtn');
      const verifyBtn = q('otaTestVerifyBtn');
      const cleanBtn = q('otaTestCleanBtn');

      if (!data.exists) {
        if (info) info.innerHTML = '<span class="text-muted small">Nessun test update</span>';
        if (pill) pill.textContent = '—';
        if (deliverBtn) deliverBtn.disabled = true;
        if (verifyBtn) verifyBtn.disabled = true;
        if (cleanBtn) cleanBtn.disabled = true;
        return;
      }

      if (pill) pill.textContent = data.delivered ? 'Consegnato' : (data.certified ? 'Pronto' : 'Non cert.');
      if (info) {
        info.innerHTML = `<div class="d-flex flex-wrap gap-2 small">
          <span>v${esc(data.version)}</span>
          <span>${data.file_count || data.staged_files || '—'} file</span>
          <span>${data.certified ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>'}</span>
          <span>Rischio: ${data.risk_score ?? '—'}/100</span>
        </div>`;
      }
      if (deliverBtn) deliverBtn.disabled = !data.certified || data.delivered;
      if (verifyBtn) verifyBtn.disabled = false;
      if (cleanBtn) cleanBtn.disabled = false;
    } catch { }
  };

  const createTestUpdate = async () => {
    const btn = q('otaTestCreateBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota-pipe-spin"></i>'; }
    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/create', { method: 'POST' });
      showToast(`Test v${data.version} ${data.certification?.certified ? 'certificato' : 'non certificato'}`, data.certification?.certified ? 'success' : 'warning');
      loadTestUpdateInfo();
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
    finally { if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-plus-circle"></i> Crea'; } }
  };

  const deliverTestUpdate = async () => {
    if (!confirm('Consegnare il test update come aggiornamento OTA?')) return;
    const btn = q('otaTestDeliverBtn');
    if (btn) { btn.disabled = true; }
    try {
      await TPL.jsonFetch('/api/ota/test-update/deliver', { method: 'POST' });
      showToast('Test update consegnato via OTA!', 'success');
      await loadAll();
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
    finally { if (btn) btn.disabled = false; loadTestUpdateInfo(); }
  };

  const verifyTestUpdate = async () => {
    const btn = q('otaTestVerifyBtn');
    const result = q('otaTestResult');
    if (btn) { btn.disabled = true; }
    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/verify');
      if (result) result.innerHTML = `<div class="alert alert-${data.certified ? 'success' : 'danger'} py-1 px-2 small mb-0">
        ${data.certified ? 'Verificato' : 'Verifica fallita'} — Firma: ${data.signature_valid ? 'OK' : 'NO'} · Integrità: ${data.all_integrity_ok ? 'OK' : 'NO'}
      </div>`;
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
    finally { if (btn) btn.disabled = false; }
  };

  const cleanupTestUpdate = async () => {
    if (!confirm('Rimuovere il test update?')) return;
    try {
      await TPL.jsonFetch('/api/ota/test-update', { method: 'DELETE' });
      showToast('Test update rimosso', 'success');
      q('otaTestResult').innerHTML = '';
      await loadAll();
    } catch (e) { showToast('Errore: ' + e, 'danger'); }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  SMART PIPELINE: Fully Automated Update
   * ═══════════════════════════════════════════════════════════════ */

  const runPipeline = async (targetTag = null) => {
    if (_pipelineRunning) return;
    _pipelineRunning = true;
    _pipelineAborted = false;

    const controls = q('otaPipeControls');
    const rollbackBtn = q('otaPipeRollbackBtn');
    const cancelBtn = q('otaPipeCancelBtn');
    if (controls) controls.classList.remove('d-none');
    if (cancelBtn) { cancelBtn.disabled = false; }

    resetStepper();
    q('otaPipeLog')&& (q('otaPipeLog').innerHTML = '');
    setPipelinePill('running', 'ota-pipe-pill--active');
    updateCta('arrow-repeat ota-pipe-spin', 'Aggiornamento in corso…', true, 'ota-pipe-cta--running');

    let tag = targetTag;

    try {
      // ── STEP 1: Check ─────────────────────────────────────────
      setStepState('check', 'active');
      pipeLog('Verifica aggiornamenti disponibili…');

      const checkData = await TPL.jsonFetch('/api/ota/check', { method: 'POST' });
      await loadStatus();
      await loadReleases();

      // Handle repo not found — inform user but don't block if test updates exist
      if (checkData.repo_status === 'not_found') {
        pipeLog('Repository GitHub non raggiungibile — verifica test update locali.', 'warn');
      }

      const newer = checkData.newer_releases || [];
      if (!tag && newer.length > 0) {
        tag = newer[0].tag;
      }

      if (!tag) {
        // Check if a release is already prepared
        const prepared = _releases.find(r => r.is_prepared && r.is_newer);
        if (prepared) {
          tag = prepared.tag;
        } else if (_releases.some(r => r.is_newer)) {
          tag = _releases.find(r => r.is_newer)?.tag;
        }
      }

      if (!tag) {
        setStepState('check', 'done');
        fillLineBefore('prepare');
        pipeLog('Piattaforma aggiornata, nessun update disponibile.', 'ok');
        setPipelinePill('up to date', 'ota-pipe-pill--ok');
        updateCta('check-circle-fill', 'Piattaforma aggiornata', false, 'ota-pipe-cta--done');
        setPipelineStatus('<span class="text-success small"><i class="bi bi-check-circle-fill"></i> Nessun aggiornamento necessario</span>');
        _pipelineRunning = false;
        return;
      }

      pipeLog(`Aggiornamento trovato: ${tag}`, 'ok');
      setStepState('check', 'done');
      fillLineBefore('prepare');
      if (_pipelineAborted) throw new Error('Pipeline annullata');

      // ── STEP 2: Prepare ───────────────────────────────────────
      setStepState('prepare', 'active');
      const rel = _releases.find(r => r.tag === tag);
      if (rel && rel.is_prepared) {
        pipeLog(`${tag} già preparato, skip download.`, 'ok');
      } else {
        pipeLog(`Download e preparazione ${tag}…`);
        await TPL.jsonFetch(`/api/ota/prepare/${encodeURIComponent(tag)}`, { method: 'POST' });
        pipeLog(`Preparazione completata.`, 'ok');
      }
      setStepState('prepare', 'done');
      fillLineBefore('verify');
      if (_pipelineAborted) throw new Error('Pipeline annullata');

      // ── STEP 3: Verify (install/start runs preflight+sig+integrity+backup) ──
      setStepState('verify', 'active');
      pipeLog('Avvio verifica sicurezza (preflight, firma, integrità, backup)…');

      const installData = await TPL.jsonFetch(`/api/ota/install/start/${encodeURIComponent(tag)}`, { method: 'POST' });

      // Log steps from server
      if (installData.steps) {
        installData.steps.forEach(s => {
          const type = s.status === 'ok' ? 'ok' : s.status === 'failed' ? 'error' : 'info';
          pipeLog(`[${s.step}] ${s.detail || s.status}`, type);
        });
      }

      pipeLog('Verifiche superate — pronto per applicazione.', 'ok');
      setStepState('verify', 'done');
      fillLineBefore('apply');
      if (_pipelineAborted) throw new Error('Pipeline annullata');

      // ── STEP 4: Apply ─────────────────────────────────────────
      setStepState('apply', 'active');
      pipeLog('Applicazione file al progetto…');

      const applyData = await TPL.jsonFetch('/api/ota/install/apply', { method: 'POST' });

      pipeLog(`${applyData.applied_files || 0} file applicati.`, 'ok');
      if (applyData.categories) {
        Object.entries(applyData.categories).forEach(([cat, count]) => {
          pipeLog(`  ${cat}: ${count} file`, 'info');
        });
      }
      if (applyData.error_files?.length) {
        applyData.error_files.forEach(ef => pipeLog(`Errore: ${ef.file} — ${ef.error}`, 'error'));
      }
      if (applyData.restart_needed) {
        pipeLog('Riavvio API necessario per modifiche al codice.', 'warn');
      } else {
        pipeLog('File web aggiornati — modifiche attive immediatamente.', 'ok');
      }
      if (rollbackBtn) rollbackBtn.disabled = false;
      setStepState('apply', 'done');
      fillLineBefore('finalize');
      if (_pipelineAborted) throw new Error('Pipeline annullata');

      // ── STEP 5: Finalize ──────────────────────────────────────
      setStepState('finalize', 'active');
      pipeLog('Finalizzazione aggiornamento…');

      const finalData = await TPL.jsonFetch('/api/ota/install/finalize', { method: 'POST' });

      if (finalData.restart_scheduled) {
        pipeLog('Riavvio API programmato fra 2 secondi…', 'warn');
        setStepState('finalize', 'done');

        setPipelinePill('restarting', 'ota-pipe-pill--warn');
        updateCta('arrow-repeat ota-pipe-spin', 'Riavvio API in corso…', true, 'ota-pipe-cta--running');
        setPipelineStatus('<span class="text-warning small"><i class="bi bi-arrow-repeat ota-pipe-spin"></i> API in riavvio — attendere…</span>');

        // Wait for API to come back
        pipeLog('Attesa riavvio API…');
        await sleep(4000);

        let apiBack = false;
        for (let i = 0; i < 30; i++) {
          try {
            await TPL.jsonFetch('/api/health');
            apiBack = true;
            break;
          } catch { await sleep(2000); }
        }

        if (apiBack) {
          pipeLog('API riavviata con successo!', 'ok');
        } else {
          pipeLog('API non ancora disponibile — potrebbe richiedere più tempo.', 'warn');
        }
      } else {
        pipeLog('Nessun riavvio necessario — aggiornamento completato.', 'ok');
        setStepState('finalize', 'done');
      }

      // ── SUCCESS ───────────────────────────────────────────────
      setPipelinePill('completato', 'ota-pipe-pill--ok');
      updateCta('check-circle-fill', `Aggiornato a ${tag}`, false, 'ota-pipe-cta--done');
      setPipelineStatus(`<span class="text-success small"><i class="bi bi-check-circle-fill"></i> Aggiornamento ${esc(tag)} completato con successo!</span>`);
      pipeLog(`Pipeline completata: ${tag} applicato con successo.`, 'ok');
      showToast(`Aggiornamento ${tag} completato!`, 'success');

      await loadAll();

    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes('annullata')) {
        pipeLog('Pipeline annullata dall\'utente.', 'warn');
        setPipelinePill('annullato', 'ota-pipe-pill--warn');
        updateCta('arrow-repeat', 'Verifica aggiornamenti', false, '');
      } else {
        // Mark current step as error
        STEPS.forEach(s => {
          const el = document.querySelector(`.ota-pipe-step[data-step="${s}"]`);
          if (el && el.classList.contains('ota-pipe-step--active')) setStepState(s, 'error');
        });
        pipeLog(`ERRORE: ${errMsg}`, 'error');
        setPipelinePill('errore', 'ota-pipe-pill--err');
        updateCta('exclamation-triangle-fill', 'Errore — Riprova', false, 'ota-pipe-cta--error');
        setPipelineStatus(`<span class="text-danger small"><i class="bi bi-exclamation-triangle-fill"></i> ${esc(errMsg)}</span>`);
        showToast(`Pipeline fallita: ${errMsg}`, 'danger');
      }
    } finally {
      _pipelineRunning = false;
      if (cancelBtn) cancelBtn.disabled = true;
    }
  };

  /* ══ Install sub-actions ═══════════════════════════════════════ */
  const rollbackInstall = async () => {
    if (!confirm('Eseguire il rollback?')) return;
    const btn = q('otaPipeRollbackBtn');
    if (btn) btn.disabled = true;
    try {
      const data = await TPL.jsonFetch('/api/ota/install/rollback', { method: 'POST' });
      showToast(`Rollback completato: ${data.tag || '?'}`, 'success');
      pipeLog('Rollback completato.', 'ok');
      resetStepper();
      setPipelinePill('rollback', 'ota-pipe-pill--warn');
      updateCta('arrow-repeat', 'Verifica aggiornamenti', false, '');
    } catch (e) { showToast('Errore rollback: ' + e, 'danger'); }
    finally { if (btn) btn.disabled = false; }
  };

  const cancelInstall = async () => {
    _pipelineAborted = true;
    try {
      await TPL.jsonFetch('/api/ota/install', { method: 'DELETE' });
      showToast('Installazione annullata', 'info');
    } catch { }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  CTA HANDLER — Smart button action
   * ═══════════════════════════════════════════════════════════════ */

  const handleCtaClick = () => {
    if (_pipelineRunning) return;

    // Determine action based on current state
    if (_state.update_available) {
      // Find the best tag to update to
      const prepared = _releases.find(r => r.is_prepared && r.is_newer);
      const newest = _releases.find(r => r.is_newer);
      const tag = prepared?.tag || newest?.tag || null;
      runPipeline(tag);
    } else {
      // Just check for updates, then auto-run if found
      runPipeline();
    }
  };

  /* ═══════════════════════════════════════════════════════════════
   *  EVENT LISTENERS
   * ═══════════════════════════════════════════════════════════════ */

  q('otaPipeCta')?.addEventListener('click', handleCtaClick);
  q('otaCheckBtn')?.addEventListener('click', async () => {
    await checkUpdates();
    loadReleases();
  });
  q('otaDetailCloseBtn')?.addEventListener('click', () => q('otaDetailPanel')?.classList.add('d-none'));

  // Security
  q('otaSecChainBtn')?.addEventListener('click', verifyChain);
  q('otaSecRepairBtn')?.addEventListener('click', repairChain);
  q('otaSecSimBtn')?.addEventListener('click', runSimulation);
  q('otaSecRefreshBtn')?.addEventListener('click', loadTrustInfo);
  q('otaSecCfgSaveBtn')?.addEventListener('click', saveSecurityConfig);
  q('otaLockdownBtn')?.addEventListener('click', toggleLockdown);

  // Config
  q('otaCfgSaveBtn')?.addEventListener('click', saveConfig);

  // Snapshots
  q('otaSnapCreateBtn')?.addEventListener('click', createSnapshot);

  // Install controls
  q('otaPipeRollbackBtn')?.addEventListener('click', rollbackInstall);
  q('otaPipeCancelBtn')?.addEventListener('click', cancelInstall);

  // Test Update
  q('otaTestCreateBtn')?.addEventListener('click', createTestUpdate);
  q('otaTestDeliverBtn')?.addEventListener('click', deliverTestUpdate);
  q('otaTestVerifyBtn')?.addEventListener('click', verifyTestUpdate);
  q('otaTestCleanBtn')?.addEventListener('click', cleanupTestUpdate);

  // Pipeline log toggle
  q('otaPipeLogToggle')?.addEventListener('click', () => {
    const log = q('otaPipeLog');
    if (log) log.style.display = log.style.display === 'none' ? '' : 'none';
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    switch (e.key.toLowerCase()) {
      case 'r': e.preventDefault(); loadAll(); break;
      case 'c': e.preventDefault(); checkUpdates(); break;
      case 's': e.preventDefault(); runSimulation(); break;
      case 'u': e.preventDefault(); handleCtaClick(); break;
      case 'escape': q('otaDetailPanel')?.classList.add('d-none'); break;
    }
  });

  /* ═══════════════════════════════════════════════════════════════
   *  LOAD ALL
   * ═══════════════════════════════════════════════════════════════ */

  const loadAll = async () => {
    await Promise.all([
      loadStatus(),
      loadReleases(),
      loadChangelog(),
      loadRollback(),
      loadTrustInfo(),
      loadLockdownStatus(),
      loadTofuStatus(),
      loadSnapshots(),
      loadTestUpdateInfo(),
    ]);
  };

  loadAll();
})();
