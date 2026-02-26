/**
 * TPL Platform — OTA Update Center (dedicated page)
 *
 * Standalone JS for /ota page. Replicates OTA logic from dashboard-system.js
 * but with dedicated DOM IDs (otaPage*) and full-page layout.
 */
(() => {
  'use strict';

  const q = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

  let _state = {};
  let _releases = [];
  let _selectedTag = null;

  /* ── Helpers ───────────────────────────────────────────────── */
  const fmtDate = (iso) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('it-IT', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    catch { return iso; }
  };

  const showToast = (msg, type = 'info') => {
    const el = q('otaToast');
    if (!el) return;
    el.className = `alert alert-${type} alert-dismissible fade show`;
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

  /* ── Load Status ───────────────────────────────────────────── */
  const loadStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/status');
      _state = data;

      const curEl = q('otaPageCurrentVer');
      if (curEl) curEl.textContent = `v${data.current_version || '?'}`;

      const latestBox = q('otaPageLatestBox');
      const latestVer = q('otaPageLatestVer');
      const arrow = q('otaPageArrow');
      if (data.latest_version && data.update_available) {
        if (latestBox) latestBox.style.display = '';
        if (arrow) arrow.style.display = '';
        if (latestVer) latestVer.textContent = `v${data.latest_version}`;
      } else {
        if (latestBox) latestBox.style.display = 'none';
        if (arrow) arrow.style.display = 'none';
      }

      const badge = q('otaPageStatusBadge');
      if (badge) {
        if (data.update_available) {
          badge.className = 'ota-status-badge ota-badge-update';
          badge.innerHTML = '<i class="bi bi-arrow-up-circle-fill"></i> Aggiornamento disponibile';
        } else {
          badge.className = 'ota-status-badge ota-badge-ok';
          badge.innerHTML = '<i class="bi bi-check-circle-fill"></i> Aggiornato';
        }
      }

      const info = q('otaPageCheckInfo');
      if (info) {
        info.textContent = data.last_check
          ? `Ultimo controllo: ${fmtDate(data.last_check_iso)} · ${data.check_count || 0} controlli`
          : 'Ultimo controllo: mai';
      }

      const rl = q('otaPageRateLimit');
      if (rl) {
        const remaining = data.rate_limit_remaining ?? 60;
        rl.textContent = `API: ${remaining}/60`;
        rl.className = `ota-rate-limit ${remaining < 10 ? 'ota-rate-warn' : ''}`;
      }

      // Config fields
      const cfgAuto = q('otaPageCfgAutoCheck');
      const cfgInterval = q('otaPageCfgInterval');
      const cfgBranch = q('otaPageCfgBranch');
      const cfgPre = q('otaPageCfgPreRelease');
      if (cfgAuto) cfgAuto.checked = data.auto_check !== false;
      if (cfgInterval) cfgInterval.value = data.check_interval_minutes || 60;
      if (cfgBranch) cfgBranch.value = data.branch || 'main';
      if (cfgPre) cfgPre.checked = !!data.pre_release;

      return data;
    } catch (error) {
      console.warn('OTA status load failed:', error);
      return null;
    }
  };

  /* ── Check for updates ─────────────────────────────────────── */
  const checkUpdates = async () => {
    const badge = q('otaPageStatusBadge');
    if (badge) {
      badge.className = 'ota-status-badge ota-badge-checking';
      badge.innerHTML = '<i class="bi bi-arrow-repeat ota-spin"></i> Controllo…';
    }
    try {
      const data = await TPL.jsonFetch('/api/ota/check', { method: 'POST' });
      const newer = data.newer_releases || [];

      await loadStatus();

      const notif = q('otaPageNotification');
      if (newer.length > 0) {
        if (notif) {
          notif.className = 'ota-notification';
          notif.innerHTML = `
            <div class="ota-notif-body">
              <i class="bi bi-gift-fill ota-notif-icon"></i>
              <div class="ota-notif-text">
                <strong>${newer.length} aggiornament${newer.length === 1 ? 'o' : 'i'} disponibil${newer.length === 1 ? 'e' : 'i'}</strong>
                <div class="ota-notif-tags">${newer.map(r => `<span class="ota-tag ${r.dismissed ? 'ota-tag-dismissed' : ''}">${esc(r.tag)}</span>`).join(' ')}</div>
              </div>
            </div>`;
        }
        loadReleases();
      } else {
        if (notif) {
          if (data.repo_status === 'not_found') {
            notif.className = 'ota-notification';
            notif.innerHTML = `<div class="ota-notif-body"><i class="bi bi-info-circle-fill ota-notif-icon text-info"></i><div class="ota-notif-text"><strong>Repository non ancora disponibile</strong><div class="small text-muted mt-1">${esc(data.note || 'Il repository GitHub non è stato trovato. Verrà verificato automaticamente.')}</div></div></div>`;
          } else {
            notif.className = 'ota-notification ota-notif-ok';
            notif.innerHTML = `<div class="ota-notif-body"><i class="bi bi-check-circle-fill ota-notif-icon text-success"></i><span>La piattaforma è aggiornata alla versione più recente.</span></div>`;
          }
        }
      }
    } catch (error) {
      const badge2 = q('otaPageStatusBadge');
      if (badge2) {
        badge2.className = 'ota-status-badge ota-badge-error';
        badge2.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> Errore';
      }
      showToast(`Controllo OTA fallito: ${error}`, 'danger');
    }
  };

  /* ── Load releases ─────────────────────────────────────────── */
  const loadReleases = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/releases');
      _releases = data.releases || [];

      const pill = q('otaPageRelPill');
      if (pill) pill.textContent = `${_releases.length} release`;

      const container = q('otaPageReleaseList');
      if (!container) return;

      if (!_releases.length) {
        container.innerHTML = `<div class="ov-empty" style="padding:1.5rem">
          <i class="bi bi-inbox" style="font-size:1.6rem;opacity:.3"></i>
          <span class="ov-empty-text" style="margin-top:.4rem;font-size:.78rem">Nessuna release trovata nel repository</span>
          <span class="ov-empty-text" style="font-size:.7rem;opacity:.6">Premi "Verifica ora" per controllare GitHub</span>
        </div>`;
        return;
      }

      container.innerHTML = `
        <div class="ota-releases-grid">
          ${_releases.map((r, idx) => `
            <div class="ota-release-card ${r.is_current ? 'ota-rel-current' : ''} ${r.is_newer ? 'ota-rel-newer' : ''} ${r.is_prepared ? 'ota-rel-prepared' : ''}"
                 data-ota-tag="${esc(r.tag)}" style="animation:amCardIn .3s ease-out ${idx * 50}ms both">
              <div class="ota-rel-header">
                <span class="ota-rel-tag">${esc(r.tag)}</span>
                ${r.is_current ? '<span class="badge bg-primary">Corrente</span>' : ''}
                ${r.is_newer ? '<span class="badge bg-success">Nuovo</span>' : ''}
                ${r.prerelease ? '<span class="badge bg-warning text-dark">Pre-release</span>' : ''}
                ${r.is_prepared ? '<span class="badge bg-info text-dark">Preparato</span>' : ''}
              </div>
              <div class="ota-rel-name">${esc(r.name || r.tag)}</div>
              <div class="ota-rel-meta">
                <span><i class="bi bi-calendar3"></i> ${fmtDate(r.published_at)}</span>
                ${r.author ? `<span><i class="bi bi-person"></i> ${esc(r.author)}</span>` : ''}
              </div>
              ${r.body ? `<div class="ota-rel-body">${esc(r.body).substring(0, 250)}${r.body.length > 250 ? '…' : ''}</div>` : ''}
              <div class="ota-rel-actions">
                <button class="btn btn-outline-primary btn-sm" data-ota-detail="${esc(r.tag)}" type="button"><i class="bi bi-info-circle"></i> Dettagli</button>
                ${r.is_newer && !r.is_prepared ? `<button class="btn btn-outline-success btn-sm" data-ota-prepare="${esc(r.tag)}" type="button"><i class="bi bi-download"></i> Prepara</button>` : ''}
                ${r.is_prepared ? `<button class="btn btn-success btn-sm" data-ota-install="${esc(r.tag)}" type="button"><i class="bi bi-play-circle"></i> Guida installazione</button>` : ''}
              </div>
            </div>
          `).join('')}
        </div>`;

      // Attach listeners
      container.querySelectorAll('[data-ota-detail]').forEach(btn =>
        btn.addEventListener('click', () => showDetail(btn.dataset.otaDetail))
      );
      container.querySelectorAll('[data-ota-prepare]').forEach(btn =>
        btn.addEventListener('click', () => prepare(btn.dataset.otaPrepare))
      );
      container.querySelectorAll('[data-ota-install]').forEach(btn =>
        btn.addEventListener('click', () => showDetail(btn.dataset.otaInstall))
      );
    } catch (error) {
      console.warn('Failed to load releases:', error);
      const container = q('otaPageReleaseList');
      if (container) container.innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(String(error))}</span>`;
    }
  };

  /* ── Show detail ───────────────────────────────────────────── */
  const showDetail = async (tag) => {
    _selectedTag = tag;
    const panel = q('otaPageDetailPanel');
    const container = q('otaPageReleaseDetail');
    if (!panel || !container) return;

    panel.classList.remove('d-none');
    container.innerHTML = '<div class="text-center p-3"><i class="bi bi-hourglass-split ota-spin"></i> Caricamento dettagli…</div>';

    try {
      const [detail, diff] = await Promise.all([
        TPL.jsonFetch(`/api/ota/release/${encodeURIComponent(tag)}`),
        TPL.jsonFetch(`/api/ota/diff/${encodeURIComponent(tag)}`).catch(() => null),
      ]);

      let html = `
        <div class="ota-detail-header">
          <h5 class="mb-0"><i class="bi bi-tag"></i> ${esc(detail.name || tag)}</h5>
          <div class="ota-detail-badges">
            <span class="badge bg-secondary">${esc(tag)}</span>
            ${detail.is_current ? '<span class="badge bg-primary">Versione corrente</span>' : ''}
            ${detail.is_newer ? '<span class="badge bg-success">Aggiornamento</span>' : ''}
            ${detail.prerelease ? '<span class="badge bg-warning text-dark">Pre-release</span>' : ''}
            ${detail.is_prepared ? '<span class="badge bg-info text-dark">Preparato</span>' : ''}
          </div>
        </div>

        <div class="ota-detail-section">
          <h6><i class="bi bi-journal-richtext"></i> Note di rilascio</h6>
          <div class="ota-release-notes">${detail.body ? renderMarkdown(detail.body) : '<span class="text-muted">Nessuna nota disponibile</span>'}</div>
        </div>

        <div class="ota-detail-meta">
          <span><i class="bi bi-calendar3"></i> Pubblicato: ${fmtDate(detail.published_at)}</span>
          ${detail.author ? `<span><i class="bi bi-person"></i> Autore: ${esc(detail.author)}</span>` : ''}
          ${detail.html_url ? `<a href="${esc(detail.html_url)}" target="_blank" rel="noopener"><i class="bi bi-github"></i> GitHub</a>` : ''}
        </div>`;

      // Diff
      if (diff && (diff.commits?.length || diff.files_changed?.length)) {
        html += `
        <div class="ota-detail-section">
          <h6><i class="bi bi-git"></i> Modifiche (${diff.total_commits || 0} commit, ${diff.files_changed?.length || 0} file)</h6>
          ${diff.commits?.length ? `
            <div class="ota-commits-list">
              ${diff.commits.slice(0, 20).map(c => `
                <div class="ota-commit-item">
                  <code class="ota-commit-sha">${esc(c.sha)}</code>
                  <span class="ota-commit-msg">${esc(c.message)}</span>
                  <span class="ota-commit-author">${esc(c.author)}</span>
                </div>
              `).join('')}
              ${diff.commits.length > 20 ? `<div class="text-muted small">… e altri ${diff.commits.length - 20} commit</div>` : ''}
            </div>` : ''}
          ${diff.files_changed?.length ? `
            <details class="mt-2">
              <summary class="ota-files-summary"><i class="bi bi-file-diff"></i> ${diff.files_changed.length} file modificati</summary>
              <div class="ota-files-list">
                ${diff.files_changed.map(f => `
                  <div class="ota-file-item">
                    <i class="bi bi-${f.status === 'added' ? 'plus-circle text-success' : f.status === 'removed' ? 'dash-circle text-danger' : 'pencil text-warning'}"></i>
                    <span class="ota-file-name">${esc(f.filename)}</span>
                    <span class="ota-file-stat">+${f.additions} -${f.deletions}</span>
                  </div>
                `).join('')}
              </div>
            </details>` : ''}
        </div>`;
      }

      // Pre-flight
      if (detail.preflight) {
        const allPassed = detail.preflight.every(c => c.passed);
        html += `
        <div class="ota-detail-section">
          <h6><i class="bi bi-shield-check"></i> Pre-flight checks</h6>
          <div class="ota-preflight ${allPassed ? 'ota-pf-pass' : 'ota-pf-warn'}">
            ${detail.preflight.map(c => `
              <div class="ota-pf-item">
                <i class="bi bi-${c.passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i>
                <span>${esc(c.name)}</span>
                <span class="text-muted small">${esc(c.detail)}</span>
              </div>
            `).join('')}
          </div>
        </div>`;
      }

      // Changed files
      if (detail.changed_files?.length) {
        const categories = {};
        detail.changed_files.forEach(f => {
          const cat = f.category || 'Altro';
          if (!categories[cat]) categories[cat] = [];
          categories[cat].push(f);
        });
        html += `
        <div class="ota-detail-section">
          <h6><i class="bi bi-files"></i> File nell'aggiornamento (${detail.changed_files.length})</h6>
          ${Object.entries(categories).map(([cat, files]) => `
            <details>
              <summary class="ota-files-summary">${esc(cat)} (${files.length} file)</summary>
              <div class="ota-files-list">${files.map(f => `
                <div class="ota-file-item">
                  <i class="bi bi-file-earmark-code"></i>
                  <span class="ota-file-name">${esc(f.file)}</span>
                </div>
              `).join('')}</div>
            </details>
          `).join('')}
        </div>`;
      }

      // Install guide
      if (detail.install_guide) {
        const guide = detail.install_guide;
        html += `
        <div class="ota-detail-section ota-install-guide">
          <h6><i class="bi bi-list-check"></i> Guida installazione</h6>
          <div class="ota-steps">
            ${guide.steps.map(s => `
              <div class="ota-step" data-risk="${s.risk}">
                <div class="ota-step-num">${s.step}</div>
                <div class="ota-step-body">
                  <div class="ota-step-title">${esc(s.title)}</div>
                  <div class="ota-step-desc">${esc(s.description)}</div>
                  <div class="ota-step-cmd">
                    <code>${esc(s.command)}</code>
                    <button class="btn btn-link btn-sm ota-copy-btn" data-copy="${esc(s.command)}" title="Copia comando" type="button"><i class="bi bi-clipboard"></i></button>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
          <div class="ota-rollback-info mt-3">
            <h6><i class="bi bi-arrow-counterclockwise"></i> Rollback</h6>
            <p class="small text-muted">${esc(guide.rollback.description)}</p>
            <div class="ota-step-cmd">
              <code>${esc(guide.rollback.command)}</code>
              <button class="btn btn-link btn-sm ota-copy-btn" data-copy="${esc(guide.rollback.command)}" title="Copia" type="button"><i class="bi bi-clipboard"></i></button>
            </div>
          </div>
          ${guide.notes?.length ? `
          <div class="ota-notes mt-3">
            <h6><i class="bi bi-info-circle"></i> Note</h6>
            <ul class="small text-muted">${guide.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>
          </div>` : ''}
        </div>`;
      }

      // Actions
      html += `
        <div class="ota-detail-actions">
          ${detail.is_newer && !detail.is_prepared ? `<button class="btn btn-success" id="otaPagePrepareBtn" type="button"><i class="bi bi-download"></i> Scarica e prepara aggiornamento</button>` : ''}
          ${detail.is_prepared ? `<button class="btn btn-outline-danger btn-sm" id="otaPageCleanupBtn" type="button"><i class="bi bi-trash"></i> Rimuovi staging</button>` : ''}
          ${detail.is_newer ? `<button class="btn btn-outline-secondary btn-sm" id="otaPageDismissBtn" type="button"><i class="bi bi-bell-slash"></i> Ignora versione</button>` : ''}
        </div>`;

      container.innerHTML = html;

      // Attach listeners
      q('otaPagePrepareBtn')?.addEventListener('click', () => prepare(tag));
      q('otaPageCleanupBtn')?.addEventListener('click', () => cleanupStaging(tag));
      q('otaPageDismissBtn')?.addEventListener('click', () => dismiss(tag));

      // Copy buttons
      container.querySelectorAll('.ota-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          navigator.clipboard.writeText(btn.dataset.copy).then(() => {
            btn.innerHTML = '<i class="bi bi-check-lg text-success"></i>';
            setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 1500);
          }).catch(() => console.warn('Clipboard copy failed'));
        });
      });

      // Scroll to detail panel
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (error) {
      container.innerHTML = `<div class="text-danger p-3"><i class="bi bi-exclamation-triangle"></i> ${esc(String(error))}</div>`;
    }
  };

  /* ── Prepare ───────────────────────────────────────────────── */
  const prepare = async (tag) => {
    const progress = q('otaPageProgress');
    if (progress) {
      progress.className = 'ota-progress';
      progress.innerHTML = `
        <div class="ota-progress-bar">
          <div class="ota-progress-fill ota-progress-indeterminate"></div>
        </div>
        <div class="ota-progress-text"><i class="bi bi-download ota-spin"></i> Download e preparazione di <strong>${esc(tag)}</strong>…</div>`;
    }
    try {
      const data = await TPL.jsonFetch(`/api/ota/prepare/${encodeURIComponent(tag)}`, { method: 'POST' });
      const allPassed = data.all_checks_passed;
      if (progress) {
        progress.innerHTML = `
          <div class="ota-progress-bar">
            <div class="ota-progress-fill" style="width:100%;background:${allPassed ? 'var(--ota-success)' : 'var(--ota-warn)'}"></div>
          </div>
          <div class="ota-progress-text">
            <i class="bi bi-${allPassed ? 'check-circle-fill text-success' : 'exclamation-triangle-fill text-warning'}"></i>
            Preparazione completata: ${data.file_count || 0} file (${data.size_human || '?'})
            ${!allPassed ? ' — Alcuni controlli pre-flight non superati' : ''}
          </div>`;
      }
      showToast(`Versione ${tag} preparata con successo. Consulta la guida installazione.`, 'success');
      setTimeout(() => showDetail(tag), 500);
      await loadStatus();
      loadReleases();
    } catch (error) {
      if (progress) {
        progress.innerHTML = `<div class="ota-progress-text text-danger"><i class="bi bi-x-circle-fill"></i> Preparazione fallita: ${esc(String(error))}</div>`;
      }
      showToast(`Preparazione ${tag} fallita: ${error}`, 'danger');
    }
  };

  /* ── Cleanup staging ───────────────────────────────────────── */
  const cleanupStaging = async (tag) => {
    if (!confirm(`Rimuovere i file di staging per ${tag}?`)) return;
    try {
      await TPL.jsonFetch(`/api/ota/staging/${encodeURIComponent(tag)}`, { method: 'DELETE' });
      showToast(`Staging per ${tag} rimosso`, 'success');
      q('otaPageDetailPanel')?.classList.add('d-none');
      await loadStatus();
      loadReleases();
    } catch (error) {
      showToast(`Errore rimozione staging: ${error}`, 'danger');
    }
  };

  /* ── Dismiss ───────────────────────────────────────────────── */
  const dismiss = async (tag) => {
    try {
      await TPL.jsonFetch('/api/ota/dismiss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tag }),
      });
      showToast(`Notifica per ${tag} silenziata`, 'info');
      await loadStatus();
    } catch (error) {
      showToast(`Errore: ${error}`, 'danger');
    }
  };

  /* ── Save config ───────────────────────────────────────────── */
  const saveConfig = async () => {
    try {
      const cfg = {
        auto_check: q('otaPageCfgAutoCheck')?.checked ?? true,
        check_interval_minutes: parseInt(q('otaPageCfgInterval')?.value || '60', 10),
        branch: q('otaPageCfgBranch')?.value || 'main',
        pre_release: q('otaPageCfgPreRelease')?.checked ?? false,
      };
      await TPL.jsonFetch('/api/ota/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      const res = q('otaPageCfgResult');
      if (res) {
        res.innerHTML = '<span class="text-success"><i class="bi bi-check-lg"></i> Salvato</span>';
        setTimeout(() => { res.textContent = ''; }, 2000);
      }
    } catch (error) {
      const res = q('otaPageCfgResult');
      if (res) res.innerHTML = `<span class="text-danger">${esc(String(error))}</span>`;
    }
  };

  /* ── Load changelog ────────────────────────────────────────── */
  const loadChangelog = async () => {
    try {
      const data = await TPL.jsonFetch('/api/version/changelog');
      const el = q('otaPageChangelog');
      if (!el) return;
      if (!data.entries?.length) {
        el.innerHTML = '<div class="text-muted small p-2"><i class="bi bi-journal"></i> Nessuna voce nel changelog</div>';
        return;
      }
      el.innerHTML = data.entries.map(e => `
        <div class="mc-cl-item">
          <span class="mc-cl-ver">${esc(e.version)}</span>
          <span class="mc-cl-date">${esc(e.date || '')}</span>
          <ul class="mc-cl-list">${(e.changes || []).map(c => `<li class="mc-cl-change">${esc(c)}</li>`).join('')}</ul>
        </div>
      `).join('');
    } catch (error) {
      const el = q('otaPageChangelog');
      if (el) el.innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Load rollback points ──────────────────────────────────── */
  const loadRollback = async () => {
    try {
      const data = await TPL.jsonFetch('/api/version/rollback-points');
      const el = q('otaPageRollbackList');
      const pill = q('otaPageRbPill');
      if (!el) return;
      const pts = data.points || [];
      if (pill) pill.textContent = `${pts.length}`;
      if (!pts.length) {
        el.innerHTML = '<div class="text-muted small p-2"><i class="bi bi-clock-history"></i> Nessun punto di rollback</div>';
        return;
      }
      el.innerHTML = pts.map(p => `
        <div class="mc-rb-item">
          <div class="mc-rb-head">
            <span class="mc-rb-label">${esc(p.label || p.id)}</span>
            <span class="mc-rb-date">${fmtDate(p.created)}</span>
          </div>
          <div class="mc-rb-meta">
            <span class="small text-muted">${esc(p.description || '')}</span>
          </div>
        </div>
      `).join('');
    } catch (error) {
      const el = q('otaPageRollbackList');
      if (el) el.innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Events ────────────────────────────────────────────────── */
  q('otaPageCheckBtn')?.addEventListener('click', checkUpdates);
  q('otaPageCfgSaveBtn')?.addEventListener('click', saveConfig);
  q('otaPageBackBtn')?.addEventListener('click', () => {
    q('otaPageDetailPanel')?.classList.add('d-none');
  });

  // Host commands copy buttons
  document.querySelectorAll('.ota-copy-host').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.copy).then(() => {
        btn.innerHTML = '<i class="bi bi-check-lg text-success"></i>';
        setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 1500);
      }).catch(() => console.warn('Clipboard copy failed'));
    });
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'r' || e.key === 'R') { e.preventDefault(); loadAll(); }
    if (e.key === 'c' || e.key === 'C') { e.preventDefault(); checkUpdates(); }
  });

  /* ── Load all ──────────────────────────────────────────────── */
  const loadAll = async () => {
    await Promise.all([
      loadStatus(),
      loadReleases(),
      loadChangelog(),
      loadRollback(),
    ]);
  };

  loadAll();
})();
