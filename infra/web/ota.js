/**
 * TPL Platform — OTA Update Center v2
 *
 * Fully redesigned JS for /ota page matching the ota2-* design system.
 * Handles KPI cards, glassmorphic hero, click-to-copy commands,
 * security simulation/chain verification, and keyboard shortcuts.
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

  const fmtDateShort = (iso) => {
    if (!iso) return 'mai';
    try { return new Date(iso).toLocaleString('it-IT', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' }); }
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

  /* ── Load Status (KPI cards) ───────────────────────────────── */
  const loadStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/status');
      _state = data;

      // KPI: Current version
      const curEl = q('otaPageCurrentVer');
      if (curEl) curEl.textContent = `v${data.current_version || '?'}`;

      // KPI: Latest version
      const latestVer = q('otaPageLatestVer');
      if (latestVer) {
        latestVer.textContent = data.latest_version ? `v${data.latest_version}` : '—';
      }

      // KPI: Latest card accent
      const latestKpi = q('otaKpiLatest');
      if (latestKpi) {
        latestKpi.dataset.accent = data.update_available ? 'success' : 'primary';
      }

      // KPI badge: status indicator
      const badge = q('otaPageStatusBadge');
      if (badge) {
        if (data.update_available) {
          badge.className = 'ota2-kpi-badge ota2-kpi-badge--update';
          badge.innerHTML = '<i class="bi bi-arrow-up-circle-fill"></i> Disponibile';
        } else {
          badge.className = 'ota2-kpi-badge ota2-kpi-badge--ok';
          badge.innerHTML = '<i class="bi bi-check-circle-fill"></i> Aggiornato';
        }
      }

      // KPI: Last check (short format for card)
      const info = q('otaPageCheckInfo');
      if (info) {
        info.textContent = data.last_check_iso ? fmtDateShort(data.last_check_iso) : 'mai';
      }

      // KPI sub: Rate limit
      const rl = q('otaPageRateLimit');
      if (rl) {
        const remaining = data.rate_limit_remaining ?? 60;
        rl.textContent = `API: ${remaining}/60`;
        rl.style.color = remaining < 10 ? 'var(--ota-danger, #ef4444)' : '';
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
      badge.className = 'ota2-kpi-badge ota2-kpi-badge--checking';
      badge.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> …';
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
        badge2.className = 'ota2-kpi-badge ota2-kpi-badge--error';
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

      // KPI: release count
      const kpiRelCount = q('otaKpiRelCount');
      if (kpiRelCount) kpiRelCount.textContent = _releases.length;

      const pill = q('otaPageRelPill');
      if (pill) pill.textContent = `${_releases.length} release`;

      const container = q('otaPageReleaseList');
      if (!container) return;

      if (!_releases.length) {
        container.innerHTML = `<div class="ov-empty" style="padding:1.5rem">
          <i class="bi bi-inbox" style="font-size:1.6rem;opacity:.3"></i>
          <span class="ov-empty-text" style="margin-top:.4rem;font-size:.78rem">Nessuna release trovata nel repository</span>
          <span class="ov-empty-text" style="font-size:.7rem;opacity:.6">Premi "Verifica aggiornamenti" per controllare GitHub</span>
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
    container.innerHTML = '<div class="text-center p-3"><i class="bi bi-hourglass-split ota2-spinner"></i> Caricamento dettagli…</div>';

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
        <div class="ota-progress-text"><i class="bi bi-download ota2-spinner"></i> Download e preparazione di <strong>${esc(tag)}</strong>…</div>`;
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

  /* ── Security: Load trust info ─────────────────────────────── */
  const loadTrustInfo = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/trust-info');

      // Card badge
      const badge = q('otaSecBadge');
      if (badge) {
        if (data.publisher_key_loaded) {
          badge.className = 'ota2-sec-badge ota2-sec-badge--ok';
          badge.innerHTML = '<i class="bi bi-shield-fill-check"></i> Protetto';
        } else {
          badge.className = 'ota2-sec-badge ota2-sec-badge--err';
          badge.innerHTML = '<i class="bi bi-shield-fill-exclamation"></i> Chiave mancante';
        }
      }

      // Hero security chip
      const heroBadge = q('otaHeroSecBadge');
      if (heroBadge) {
        if (data.publisher_key_loaded) {
          heroBadge.innerHTML = `<i class="bi bi-shield-lock-fill"></i> Ed25519 · ${data.audit_entries || 0} audit`;
        } else {
          heroBadge.innerHTML = '<i class="bi bi-shield-exclamation"></i> Chiave mancante';
          heroBadge.style.borderColor = 'rgba(239,68,68,.3)';
          heroBadge.style.color = '#fca5a5';
        }
      }

      // Key rows
      const pubKey = q('otaSecPublisherKey');
      if (pubKey) pubKey.innerHTML = data.publisher_key_loaded
        ? `<span class="text-success"><i class="bi bi-check-circle-fill"></i></span> <code>${esc(data.publisher_key_fingerprint || '—')}</code>`
        : `<span class="text-danger"><i class="bi bi-x-circle-fill"></i></span> Non caricata`;

      const platKey = q('otaSecPlatformKey');
      if (platKey) platKey.innerHTML = data.platform_key_fingerprint
        ? `<span class="text-success"><i class="bi bi-check-circle-fill"></i></span> <code>${esc(data.platform_key_fingerprint)}</code>`
        : `<span class="text-muted">—</span>`;

      const algos = q('otaSecAlgorithms');
      if (algos && data.algorithms) {
        algos.innerHTML = `${esc(data.algorithms.signing)} · ${esc(data.algorithms.hashing)}`;
      }

      const chain = q('otaSecChainInfo');
      if (chain) {
        chain.innerHTML = `${data.audit_entries || 0} voci · <code>${esc((data.audit_chain_hash || '—').substring(0, 16))}…</code>`;
      }

      // Load security config
      const status = await TPL.jsonFetch('/api/ota/status');
      if (status) {
        const cfgSig = q('otaSecCfgSignature');
        const cfgCheck = q('otaSecCfgChecksum');
        const cfgQuar = q('otaSecCfgQuarantine');
        const cfgRisk = q('otaSecCfgMaxRisk');
        if (cfgSig) cfgSig.checked = status.require_signature !== false;
        if (cfgCheck) cfgCheck.checked = status.require_checksum !== false;
        if (cfgQuar) cfgQuar.checked = status.quarantine_suspicious !== false;
        if (cfgRisk) cfgRisk.value = status.max_risk_score ?? 30;
      }

      return data;
    } catch (error) {
      console.warn('Security trust info load failed:', error);
      return null;
    }
  };

  /* ── Security: Run simulation ──────────────────────────────── */
  const runSimulation = async () => {
    const btn = q('otaSecSimulateBtn');
    const results = q('otaSecResults');
    if (!results) return;

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Simulazione…';
    }
    results.className = '';
    results.innerHTML = '<div class="text-center p-3"><i class="bi bi-hourglass-split ota2-spinner"></i> Esecuzione simulazione di sicurezza…</div>';

    try {
      const data = await TPL.jsonFetch('/api/ota/simulate', { method: 'POST' });
      const cert = data.certification || {};
      const scan = data.security_scan || {};
      const preflight = data.preflight || [];

      const passedPf = preflight.filter(c => c.passed).length;
      const totalPf = preflight.length;
      const allPass = cert.certified;

      let html = `<div class="ota2-sec-results">`;

      // Header with certification badge
      html += `<div class="ota2-sec-result-header">
        <span class="ota2-cert-badge ${allPass ? 'ota2-cert-badge--pass' : 'ota2-cert-badge--fail'}">
          <i class="bi bi-${allPass ? 'patch-check-fill' : 'patch-exclamation-fill'}"></i>
          ${allPass ? 'CERTIFICATO' : 'NON CERTIFICATO'}
        </span>
        <h6>Simulazione <code>${esc(data.tag || '—')}</code></h6>
        <span class="ms-auto small text-muted">${fmtDate(cert.certified_at)}</span>
      </div>`;

      // Key verification checks (2-col grid)
      html += `<div class="ota2-sec-checks">
        <div class="ota2-sec-check">
          <i class="bi bi-${cert.signature_verified ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i>
          <span>Firma Ed25519</span>
        </div>
        <div class="ota2-sec-check">
          <i class="bi bi-${cert.integrity_verified ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i>
          <span>Integrità SHA-256</span>
        </div>
        <div class="ota2-sec-check">
          <i class="bi bi-${cert.preflight_passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i>
          <span>Pre-flight (${passedPf}/${totalPf})</span>
        </div>
        <div class="ota2-sec-check">
          <i class="bi bi-${scan.verdict === 'clean' ? 'check-circle-fill text-success' : 'exclamation-triangle-fill text-warning'}"></i>
          <span>Scan: ${esc(scan.verdict || '—')} (${scan.risk_score || 0}/100)</span>
        </div>
      </div>`;

      // Manifest summary (dl rows)
      const ms = data.manifest_summary || {};
      html += `<div class="mb-2">
        <div class="ota2-sec-dl"><span class="ota2-sec-dl-label">File nel manifest</span><span class="ota2-sec-dl-value">${ms.total_files || 0}</span></div>
        <div class="ota2-sec-dl"><span class="ota2-sec-dl-label">Dimensione totale</span><span class="ota2-sec-dl-value">${esc(ms.total_size_human || '—')}</span></div>
        <div class="ota2-sec-dl"><span class="ota2-sec-dl-label">Firma (Ed25519)</span><span class="ota2-sec-dl-value"><code>${esc((data.signature?.signature_preview || '—').substring(0, 40))}…</code></span></div>
      </div>`;

      // Preflight details (collapsible)
      if (preflight.length) {
        const categories = {};
        preflight.forEach(c => { const cat = c.category || 'other'; if (!categories[cat]) categories[cat] = []; categories[cat].push(c); });

        html += `<details class="ota2-details mt-2"><summary><i class="bi bi-list-check"></i> Pre-flight dettaglio (${passedPf}/${totalPf})</summary><div class="ota2-details-body">`;
        for (const [cat, checks] of Object.entries(categories)) {
          const catLabel = { filesystem: 'File System', structure: 'Struttura', system: 'Sistema', crypto: 'Crittografia', security: 'Sicurezza' }[cat] || cat;
          html += `<div class="mb-2"><strong class="small text-uppercase" style="opacity:.6">${esc(catLabel)}</strong>`;
          checks.forEach(c => {
            html += `<div class="ota2-sec-check"><i class="bi bi-${c.passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i><span>${esc(c.name)}</span><span class="ms-auto small text-muted">${esc(c.detail || '')}</span></div>`;
          });
          html += `</div>`;
        }
        html += `</div></details>`;
      }

      // Integrity details (collapsible)
      if (data.integrity?.results?.length) {
        html += `<details class="ota2-details mt-2"><summary><i class="bi bi-file-earmark-lock2"></i> Integrità file (${data.integrity.files_checked} verificati)</summary><div class="ota2-details-body">`;
        data.integrity.results.forEach(f => {
          html += `<div class="ota2-sec-check"><i class="bi bi-${f.passed ? 'check-circle-fill text-success' : 'x-circle-fill text-danger'}"></i><span><code>${esc(f.file)}</code></span><span class="ms-auto small text-muted">${f.size}B</span></div>`;
        });
        html += `</div></details>`;
      }

      html += `</div>`;
      results.innerHTML = html;

      showToast(allPass ? 'Simulazione completata: CERTIFICATO ✓' : 'Simulazione completata: NON CERTIFICATO ✗', allPass ? 'success' : 'warning');
      loadTrustInfo();
    } catch (error) {
      results.innerHTML = `<div class="ota2-sec-results"><div class="text-danger"><i class="bi bi-exclamation-triangle"></i> Simulazione fallita: ${esc(String(error))}</div></div>`;
      showToast(`Simulazione fallita: ${error}`, 'danger');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-circle"></i> Simula sicurezza';
      }
    }
  };

  /* ── Security: Verify audit chain ──────────────────────────── */
  const verifyChain = async () => {
    const btn = q('otaSecVerifyChainBtn');
    const repairBtn = q('otaSecRepairChainBtn');
    const results = q('otaSecResults');
    if (!results) return;

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Verifica…';
    }
    results.className = '';

    try {
      const data = await TPL.jsonFetch('/api/ota/security/verify-chain', { method: 'POST' });

      let html = `<div class="ota2-sec-results">
        <div class="ota2-sec-result-header">
          <span class="ota2-cert-badge ${data.valid ? 'ota2-cert-badge--pass' : 'ota2-cert-badge--fail'}">
            <i class="bi bi-${data.valid ? 'link-45deg' : 'unlink'}"></i>
            ${data.valid ? 'CATENA VALIDA' : 'CATENA COMPROMESSA'}
          </span>
          <h6>Verifica Audit Chain</h6>
        </div>
        <div class="ota2-sec-dl"><span class="ota2-sec-dl-label">Voci nella catena</span><span class="ota2-sec-dl-value">${data.entries || 0}</span></div>
        ${!data.valid && data.broken_at !== null ? `<div class="ota2-sec-dl"><span class="ota2-sec-dl-label">Rottura a indice</span><span class="ota2-sec-dl-value text-danger">#${data.broken_at}</span></div>` : ''}
        ${data.total_segments ? `<div class="ota2-sec-dl"><span class="ota2-sec-dl-label">Segmenti</span><span class="ota2-sec-dl-value">${data.total_segments}</span></div>` : ''}
        ${data.valid ? `<div class="small text-success mt-2"><i class="bi bi-shield-fill-check"></i> Tutti gli hash della catena sono consistenti. Nessuna manomissione rilevata.</div>` :
            data.repairable ? `<div class="small text-warning mt-2"><i class="bi bi-wrench-adjustable"></i> La catena presenta fork da riavvio container — riparabile automaticamente.</div>` :
            `<div class="small text-danger mt-2"><i class="bi bi-shield-fill-exclamation"></i> La catena di audit è stata alterata. Possibile manomissione dei log.</div>`}
        ${data.repair_hint ? `<div class="small text-info mt-1"><i class="bi bi-info-circle"></i> ${esc(data.repair_hint)}</div>` : ''}
      </div>`;

      results.innerHTML = html;

      // Show/hide repair button
      if (repairBtn) {
        repairBtn.style.display = (!data.valid && data.repairable) ? '' : 'none';
      }

      showToast(data.valid ? 'Audit chain: VALIDA ✓' : 'Audit chain: COMPROMESSA ✗', data.valid ? 'success' : 'danger');
      loadTrustInfo();
    } catch (error) {
      results.innerHTML = `<div class="ota2-sec-results"><div class="text-danger"><i class="bi bi-exclamation-triangle"></i> Verifica fallita: ${esc(String(error))}</div></div>`;
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-link-45deg"></i> Verifica chain';
      }
    }
  };

  /* ── Security: Save security config ────────────────────────── */
  const saveSecurityConfig = async () => {
    try {
      const cfg = {
        require_signature: q('otaSecCfgSignature')?.checked ?? true,
        require_checksum: q('otaSecCfgChecksum')?.checked ?? true,
        quarantine_suspicious: q('otaSecCfgQuarantine')?.checked ?? true,
        tofu_enabled: q('otaSecCfgTofu')?.checked ?? true,
        max_risk_score: parseInt(q('otaSecCfgMaxRisk')?.value || '30', 10),
      };
      await TPL.jsonFetch('/api/ota/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      const res = q('otaSecCfgResult');
      if (res) {
        res.innerHTML = '<span class="text-success"><i class="bi bi-check-lg"></i> Policy salvata</span>';
        setTimeout(() => { res.textContent = ''; }, 2000);
      }
    } catch (error) {
      const res = q('otaSecCfgResult');
      if (res) res.innerHTML = `<span class="text-danger">${esc(String(error))}</span>`;
    }
  };

  /* ── Lockdown Mode ─────────────────────────────────────────── */
  const loadLockdownStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/lockdown');
      const el = q('otaLockdownStatus');
      const btn = q('otaLockdownToggle');
      if (data.active) {
        if (el) el.innerHTML = '<i class="bi bi-lock-fill text-danger"></i> <strong class="text-danger">ATTIVO</strong>';
        if (btn) { btn.innerHTML = '<i class="bi bi-unlock-fill"></i> Disattiva lockdown'; btn.classList.remove('ota2-action-btn--danger'); btn.classList.add('ota2-action-btn--primary'); }
      } else {
        if (el) el.innerHTML = '<i class="bi bi-unlock-fill text-success"></i> Inattivo';
        if (btn) { btn.innerHTML = '<i class="bi bi-lock-fill"></i> Attiva lockdown'; btn.classList.add('ota2-action-btn--danger'); btn.classList.remove('ota2-action-btn--primary'); }
      }
    } catch { /* ignore */ }
  };

  const toggleLockdown = async () => {
    try {
      const current = await TPL.jsonFetch('/api/ota/security/lockdown');
      const newState = !current.active;
      if (newState && !confirm('Sei sicuro di voler attivare il LOCKDOWN? Tutte le operazioni OTA verranno bloccate.')) return;
      await TPL.jsonFetch('/api/ota/security/lockdown', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: newState, reason: newState ? 'manual_lockdown' : 'manual_unlock' }),
      });
      showToast(newState ? 'Lockdown attivato' : 'Lockdown disattivato', newState ? 'warning' : 'success');
      loadLockdownStatus();
    } catch (e) {
      showToast('Errore lockdown: ' + e, 'danger');
    }
  };

  /* ── TOFU ──────────────────────────────────────────────────── */
  const loadTofuStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/security/tofu-status');
      const pins = q('otaTofuPins');
      const status = q('otaTofuStatus');
      if (pins) pins.textContent = `${data.total_pinned_keys} key pinned`;
      if (status) {
        status.textContent = data.tofu_enabled ? 'Attivo' : 'Disattivato';
        status.style.color = data.tofu_enabled ? 'var(--bs-success)' : 'var(--bs-secondary)';
      }
    } catch { /* ignore */ }
  };

  const verifyTofu = async () => {
    const res = q('otaTofuResult');
    try {
      const data = await TPL.jsonFetch('/api/ota/security/tofu-verify', { method: 'POST' });
      if (data.trusted) {
        if (res) res.innerHTML = `<span class="text-success"><i class="bi bi-check-circle-fill"></i> Trusted${data.auto_pinned ? ' (pinned)' : ''}</span>`;
      } else {
        if (res) res.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle-fill"></i> ${data.status}</span>`;
      }
      setTimeout(() => { if (res) res.textContent = ''; }, 4000);
      loadTofuStatus();
    } catch (e) {
      if (res) res.innerHTML = `<span class="text-danger">${esc(String(e))}</span>`;
    }
  };

  /* ── Metrics ───────────────────────────────────────────────── */
  const loadMetrics = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/metrics');
      const m = data.metrics || {};
      const el = q('otaMetricsBody');
      if (el) el.innerHTML = `
        <div class="ota2-metrics-grid">
          <div class="ota2-metric"><span class="ota2-metric-val">${m.total_checks || 0}</span><span class="ota2-metric-lbl">Check</span></div>
          <div class="ota2-metric"><span class="ota2-metric-val">${m.total_simulations || 0}</span><span class="ota2-metric-lbl">Simulazioni</span></div>
          <div class="ota2-metric"><span class="ota2-metric-val">${m.total_prepares || 0}</span><span class="ota2-metric-lbl">Preparazioni</span></div>
          <div class="ota2-metric"><span class="ota2-metric-val">${m.successful_verifications || 0}</span><span class="ota2-metric-lbl">Verify OK</span></div>
          <div class="ota2-metric"><span class="ota2-metric-val">${m.failed_verifications || 0}</span><span class="ota2-metric-lbl">Verify FAIL</span></div>
          <div class="ota2-metric"><span class="ota2-metric-val">${m.events_24h || 0}</span><span class="ota2-metric-lbl">Events 24h</span></div>
        </div>
        <div class="small text-muted mt-2">
          Uptime engine: ${Math.floor((data.engine_uptime_seconds || 0) / 60)}min &bullet;
          Policy: v${esc(data.security_policy || '?')}
        </div>`;
    } catch (e) {
      const el = q('otaMetricsBody');
      if (el) el.innerHTML = `<span class="text-muted small">Non disponibile</span>`;
    }
  };

  /* ── Health Check ──────────────────────────────────────────── */
  const runHealthCheck = async () => {
    const el = q('otaHealthBody');
    const btn = q('otaHealthRunBtn');
    if (btn) btn.disabled = true;
    if (btn) btn.innerHTML = '<span class="ota2-spinner"></span> Checking…';
    try {
      const data = await TPL.jsonFetch('/api/ota/health');
      const icon = data.healthy ? '<i class="bi bi-heart-fill text-success"></i>' : '<i class="bi bi-heart-fill text-danger"></i>';
      let html = `<div class="mb-2">${icon} <strong>${data.healthy ? 'Healthy' : 'UNHEALTHY'}</strong> — ${data.passed}/${data.total_checks} check</div>`;
      html += '<div class="ota2-health-checks">';
      for (const c of (data.checks || [])) {
        const ci = c.passed ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
        html += `<div class="ota2-health-check">${ci} <strong>${esc(c.check)}</strong> <span class="text-muted">${esc(c.detail)}</span></div>`;
      }
      html += '</div>';
      html += `<div class="small text-muted mt-1">${data.total_latency_ms}ms — ${fmtDateShort(data.checked_at)}</div>`;
      if (el) el.innerHTML = html;
    } catch (e) {
      if (el) el.innerHTML = `<span class="text-danger">${esc(String(e))}</span>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-heart-pulse"></i> Esegui health check'; }
    }
  };

  /* ── Rollback Snapshots ────────────────────────────────────── */
  const loadSnapshots = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/rollback/snapshots');
      const el = q('otaPageSnapshotList');
      const pill = q('otaPageSnapPill');
      if (pill) pill.textContent = data.total || 0;
      if (!el) return;

      if (!data.snapshots || data.snapshots.length === 0) {
        el.innerHTML = '<div class="text-muted small">Nessun snapshot disponibile</div>';
        return;
      }

      el.innerHTML = data.snapshots.map(s => `
        <div class="ota2-snap-item">
          <div class="d-flex justify-content-between align-items-center">
            <strong class="small"><i class="bi bi-camera-fill me-1"></i>${esc(s.snap_id || s.tag || '?')}</strong>
            <span class="badge bg-secondary">${s.files_saved || 0} files</span>
          </div>
          <div class="small text-muted">${fmtDateShort(s.created_at)} — v${esc(s.platform_version || '?')}</div>
        </div>
      `).join('');
    } catch {
      const el = q('otaPageSnapshotList');
      if (el) el.innerHTML = '<div class="text-muted small">Non disponibile</div>';
    }
  };

  const createSnapshot = async () => {
    const btn = q('otaSnapCreateBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="ota2-spinner"></span> Creazione…'; }
    try {
      await TPL.jsonFetch('/api/ota/rollback/create-snapshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tag: `manual-${Date.now()}` }),
      });
      showToast('Snapshot creato', 'success');
      loadSnapshots();
    } catch (e) {
      showToast('Errore snapshot: ' + e, 'danger');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-camera"></i> Crea snapshot'; }
    }
  };

  /* ── Repair Chain ──────────────────────────────────────────── */

  const repairChain = async () => {
    const btn = q('otaSecRepairChainBtn');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Riparazione…';
    }

    try {
      const data = await TPL.jsonFetch('/api/ota/security/repair-chain', { method: 'POST' });

      if (data.repaired) {
        showToast(`Chain riparata: ${data.repaired_count} voci corrette su ${data.entries}`, 'success');
        // Hide repair button
        if (btn) btn.style.display = 'none';
        // Re-verify to show updated results
        await verifyChain();
      } else {
        showToast(`Riparazione non riuscita: ${data.reason || 'errore sconosciuto'}`, 'warning');
      }
    } catch (e) {
      showToast('Errore riparazione chain: ' + e, 'danger');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-wrench-adjustable"></i> Ripara chain';
      }
    }
  };

  /* ── OTA Install System ────────────────────────────────────── */

  const _installStepIcon = (status) => {
    switch (status) {
      case 'ok': return '<i class="bi bi-check-circle-fill text-success"></i>';
      case 'running': return '<i class="bi bi-arrow-repeat ota2-spinner text-primary"></i>';
      case 'failed': return '<i class="bi bi-x-circle-fill text-danger"></i>';
      case 'warning': return '<i class="bi bi-exclamation-triangle-fill text-warning"></i>';
      default: return '<i class="bi bi-circle text-muted"></i>';
    }
  };

  const loadInstallStatus = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/install/status');
      const pill = q('otaInstallPill');
      const statusEl = q('otaInstallStatus');
      const progressWrap = q('otaInstallProgressWrap');
      const progressBar = q('otaInstallProgressBar');
      const progressText = q('otaInstallProgressText');
      const tagEl = q('otaInstallTag');
      const stepsEl = q('otaInstallSteps');
      const startBtn = q('otaInstallStartBtn');
      const applyBtn = q('otaInstallApplyBtn');
      const rollbackBtn = q('otaInstallRollbackBtn');
      const cancelBtn = q('otaInstallCancelBtn');
      const hostCmdWrap = q('otaInstallHostCmd');

      const status = data.status || 'idle';

      // Pill color
      if (pill) {
        const cls = { idle: '', installing: 'ota2-pill--info', ready: 'ota2-pill--success', applying: 'ota2-pill--warning', applied: 'ota2-pill--success', failed: 'ota2-pill--danger' };
        pill.className = 'ota2-pill ' + (cls[status] || '');
        pill.textContent = status;
      }

      // Status display
      if (statusEl) {
        const icons = { idle: 'circle text-muted', installing: 'arrow-repeat ota2-spinner text-primary', ready: 'check-circle text-success', applying: 'gear-wide-connected ota2-spinner text-warning', applied: 'check-circle-fill text-success', failed: 'x-circle-fill text-danger' };
        const labels = { idle: 'Nessuna installazione in corso', installing: `Installazione ${data.tag || ''} in corso…`, ready: `${data.tag || ''} pronto per l'applicazione`, applying: `Applicazione ${data.tag || ''} in corso…`, applied: `${data.tag || ''} applicato con successo`, failed: `Installazione ${data.tag || ''} fallita` };
        statusEl.innerHTML = `<div class="d-flex align-items-center gap-2 mb-1">
          <i class="bi bi-${icons[status] || 'circle text-muted'}"></i>
          <span class="small fw-semibold">${labels[status] || status}</span>
        </div>`;
        if (data.error) {
          statusEl.innerHTML += `<div class="small text-danger"><i class="bi bi-exclamation-triangle"></i> ${esc(data.error)}</div>`;
        }
        if (data.started_at && status !== 'idle') {
          statusEl.innerHTML += `<div class="text-muted" style="font-size:0.75rem">Avviato: ${fmtDate(data.started_at)} da ${esc(data.started_by || '?')}</div>`;
        }
      }

      // Progress
      if (progressWrap) {
        if (status !== 'idle') {
          progressWrap.classList.remove('d-none');
          const pct = data.total_steps ? Math.round((data.progress / data.total_steps) * 100) : 0;
          if (progressBar) progressBar.style.width = pct + '%';
          if (progressText) progressText.textContent = `${data.progress || 0} / ${data.total_steps || 5}`;
          if (tagEl) tagEl.textContent = data.tag || '—';
        } else {
          progressWrap.classList.add('d-none');
        }
      }

      // Steps log
      if (stepsEl && data.steps && data.steps.length > 0) {
        stepsEl.classList.remove('d-none');
        stepsEl.innerHTML = data.steps.map(s =>
          `<div class="ota2-install-step">
            ${_installStepIcon(s.status)}
            <span class="ota2-install-step-name">${esc(s.step)}</span>
            <span class="ota2-install-step-detail">${esc(s.detail || '')}</span>
          </div>`
        ).join('');
      } else if (stepsEl) {
        stepsEl.classList.add('d-none');
      }

      // Button states
      if (startBtn) startBtn.disabled = (status === 'installing' || status === 'applying');
      if (applyBtn) applyBtn.disabled = (status !== 'ready');
      if (rollbackBtn) rollbackBtn.disabled = (status === 'idle' || status === 'installing');
      if (cancelBtn) cancelBtn.disabled = (status === 'idle' || status === 'applying' || status === 'applied');

      // Host command
      if (hostCmdWrap && status === 'applied' && data.applied_at) {
        hostCmdWrap.classList.remove('d-none');
      } else if (hostCmdWrap) {
        hostCmdWrap.classList.add('d-none');
      }

    } catch (e) {
      // Silently ignore on load
    }
  };

  const startInstall = async () => {
    // Determine which tag to install: use selected tag or latest available
    let tag = _selectedTag;
    if (!tag && _releases.length > 0) {
      // Find latest staged release or first available
      const staged = _releases.find(r => r.staged);
      tag = staged ? staged.tag_name : _releases[0]?.tag_name;
    }
    if (!tag) {
      showToast('Nessuna release disponibile per l\'installazione. Prepara prima una release.', 'warning');
      return;
    }

    const btn = q('otaInstallStartBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Avvio…'; }
    const resultEl = q('otaInstallResult');
    if (resultEl) resultEl.innerHTML = '';

    try {
      const data = await TPL.jsonFetch(`/api/ota/install/start/${encodeURIComponent(tag)}`, { method: 'POST' });
      showToast(`Installazione ${tag} pronta — ${(data.manifest?.files_count || 0)} file verificati`, 'success');
      await loadInstallStatus();
    } catch (e) {
      showToast('Errore avvio installazione: ' + e, 'danger');
      if (resultEl) resultEl.innerHTML = `<span class="text-danger">${esc(String(e))}</span>`;
      await loadInstallStatus();
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-play-fill"></i> Installa'; }
    }
  };

  const applyInstall = async () => {
    const btn = q('otaInstallApplyBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Applicazione…'; }

    try {
      const data = await TPL.jsonFetch('/api/ota/install/apply', { method: 'POST' });
      showToast(`Aggiornamento applicato: ${data.applied_files || 0} file — ${data.host_command || ''}`, 'success');

      // Show host command
      const cmdText = q('otaInstallHostCmdText');
      const cmdCopy = q('otaInstallHostCmdCopy');
      if (cmdText && data.host_command) {
        cmdText.textContent = data.host_command;
        if (cmdCopy) cmdCopy.dataset.copy = data.host_command;
      }

      const resultEl = q('otaInstallResult');
      if (resultEl && data.message) {
        resultEl.innerHTML = `<span class="text-success"><i class="bi bi-check-circle"></i> ${esc(data.message)}</span>`;
      }

      await loadInstallStatus();
    } catch (e) {
      showToast('Errore applicazione: ' + e, 'danger');
      await loadInstallStatus();
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-check-circle"></i> Applica'; }
    }
  };

  const rollbackInstall = async () => {
    if (!confirm('Vuoi eseguire il rollback dell\'installazione corrente?')) return;

    const btn = q('otaInstallRollbackBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat ota2-spinner"></i> Rollback…'; }

    try {
      const data = await TPL.jsonFetch('/api/ota/install/rollback', { method: 'POST' });
      showToast(`Rollback completato: ${data.tag || '?'}`, 'success');
      await loadInstallStatus();
    } catch (e) {
      showToast('Errore rollback: ' + e, 'danger');
      await loadInstallStatus();
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-arrow-counterclockwise"></i> Rollback'; }
    }
  };

  const cancelInstall = async () => {
    if (!confirm('Vuoi annullare l\'installazione in corso?')) return;

    try {
      const data = await TPL.jsonFetch('/api/ota/install', { method: 'DELETE' });
      showToast(`Installazione annullata: ${data.tag || '?'}`, 'info');
      await loadInstallStatus();
    } catch (e) {
      showToast('Errore annullamento: ' + e, 'danger');
    }
  };

  /* ── Test Update Delivery ──────────────────────────────────── */

  const loadTestUpdateInfo = async () => {
    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/info');
      const info = q('otaTestInfo');
      const pill = q('otaTestPill');
      const deliverBtn = q('otaTestDeliverBtn');
      const verifyBtn = q('otaTestVerifyBtn');
      const cleanBtn = q('otaTestCleanBtn');

      if (!data.exists) {
        if (info) info.innerHTML = '<span class="text-muted small">Nessun test update creato</span>';
        if (pill) { pill.textContent = '—'; pill.className = 'ota2-pill'; }
        if (deliverBtn) deliverBtn.disabled = true;
        if (verifyBtn) verifyBtn.disabled = true;
        if (cleanBtn) cleanBtn.disabled = true;
        return;
      }

      const certified = data.certified;
      const delivered = data.delivered;

      if (pill) {
        pill.textContent = delivered ? 'Consegnato' : (certified ? 'Pronto' : 'Non cert.');
        pill.className = `ota2-pill ${delivered ? 'ota2-pill--delivered' : (certified ? 'ota2-pill--ready' : 'ota2-pill--warn')}`;
      }

      if (info) {
        info.innerHTML = `
          <div class="ota2-test-info-grid">
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">Versione</span>
              <span class="ota2-test-info-value">v${esc(data.version)}</span>
            </div>
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">File</span>
              <span class="ota2-test-info-value">${data.file_count || data.staged_files || '—'}</span>
            </div>
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">Certificato</span>
              <span class="ota2-test-info-value">${certified ? '<i class="bi bi-check-circle-fill text-success"></i> Sì' : '<i class="bi bi-x-circle-fill text-danger"></i> No'}</span>
            </div>
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">Rischio</span>
              <span class="ota2-test-info-value">${data.risk_score ?? '—'}/100</span>
            </div>
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">Creato</span>
              <span class="ota2-test-info-value">${fmtDateShort(data.created_at)}</span>
            </div>
            <div class="ota2-test-info-item">
              <span class="ota2-test-info-label">Stato</span>
              <span class="ota2-test-info-value">${delivered
                ? '<i class="bi bi-send-check-fill text-primary"></i> Consegnato'
                : '<i class="bi bi-hourglass-split text-warning"></i> In attesa'}</span>
            </div>
          </div>
        `;
      }

      if (deliverBtn) deliverBtn.disabled = !certified || delivered;
      if (verifyBtn) verifyBtn.disabled = false;
      if (cleanBtn) cleanBtn.disabled = false;
    } catch {
      const info = q('otaTestInfo');
      if (info) info.innerHTML = '<span class="text-muted small">Errore caricamento</span>';
    }
  };

  const createTestUpdate = async () => {
    const btn = q('otaTestCreateBtn') || q('otaTestCreateBtn2');
    const result = q('otaTestResult');
    const allBtns = [q('otaTestCreateBtn'), q('otaTestCreateBtn2')];
    allBtns.forEach(b => { if (b) { b.disabled = true; b.innerHTML = '<span class="ota2-spinner"></span> Creazione…'; } });
    if (result) result.innerHTML = '';

    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/create', { method: 'POST' });

      if (result) {
        const cert = data.certification || {};
        result.innerHTML = `
          <div class="alert alert-${cert.certified ? 'success' : 'warning'} py-2 px-3 small">
            <strong>${cert.certified ? '✓ Pacchetto certificato' : '⚠ Certificazione incompleta'}</strong><br>
            Tag: <code>${esc(data.tag)}</code> · File: ${data.manifest_summary?.total_files || '?'} · 
            Dimensione: ${data.manifest_summary?.total_size_human || '?'}<br>
            Firma: ${cert.signature_verified ? '✓' : '✗'} · 
            Integrità: ${cert.integrity_verified ? '✓' : '✗'} · 
            Pre-flight: ${cert.preflight_passed ? '✓' : '✗'} · 
            Rischio: ${cert.risk_score}/100
          </div>
        `;
      }

      showToast(`Test update v${data.version} creato e ${data.certification?.certified ? 'certificato' : 'non certificato'}`, data.certification?.certified ? 'success' : 'warning');
      loadTestUpdateInfo();
    } catch (e) {
      showToast('Errore creazione test update: ' + e, 'danger');
      if (result) result.innerHTML = `<div class="alert alert-danger py-2 px-3 small">${esc(String(e))}</div>`;
    } finally {
      allBtns.forEach(b => { if (b) { b.disabled = false; b.innerHTML = '<i class="bi bi-box-seam"></i> Crea test update'; } });
      if (q('otaTestCreateBtn2')) { q('otaTestCreateBtn2').innerHTML = '<i class="bi bi-plus-circle"></i> Crea pacchetto'; }
    }
  };

  const deliverTestUpdate = async () => {
    if (!confirm('Consegnare il test update v3.1.0-rc1 come aggiornamento OTA disponibile?')) return;
    const btn = q('otaTestDeliverBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="ota2-spinner"></span> Consegna…'; }

    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/deliver', { method: 'POST' });
      showToast(`Test update ${data.version} consegnato via OTA!`, 'success');

      const result = q('otaTestResult');
      if (result) {
        result.innerHTML = `
          <div class="alert alert-success py-2 px-3 small">
            <strong><i class="bi bi-send-check-fill"></i> Update consegnato</strong><br>
            ${esc(data.message || '')}
          </div>
        `;
      }

      // Refresh everything to show the new "available" update
      await loadAll();
    } catch (e) {
      showToast('Errore consegna: ' + e, 'danger');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-send"></i> Consegna OTA'; }
      loadTestUpdateInfo();
    }
  };

  const verifyTestUpdate = async () => {
    const btn = q('otaTestVerifyBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="ota2-spinner"></span> Verifica…'; }
    const result = q('otaTestResult');

    try {
      const data = await TPL.jsonFetch('/api/ota/test-update/verify');

      if (result) {
        const checks = (data.preflight || []);
        const passedPf = checks.filter(c => c.passed).length;
        const integ = data.integrity_checks || [];
        const passedInt = integ.filter(r => r.passed).length;

        result.innerHTML = `
          <div class="alert alert-${data.certified ? 'success' : 'danger'} py-2 px-3 small">
            <strong>${data.certified ? '✓ Verifica superata' : '✗ Verifica fallita'}</strong><br>
            <table class="table table-sm table-borderless mb-0 small">
              <tr><td>Firma Ed25519</td><td>${data.signature_valid ? '<i class="bi bi-check-circle-fill text-success"></i> Valida' : '<i class="bi bi-x-circle-fill text-danger"></i> Non valida'}</td></tr>
              <tr><td>Integrità file</td><td>${data.all_integrity_ok ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>'} ${passedInt}/${integ.length} file OK</td></tr>
              <tr><td>Pre-flight</td><td>${data.all_preflight_ok ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>'} ${passedPf}/${checks.length} check OK</td></tr>
              <tr><td>Scan sicurezza</td><td>${data.scan?.verdict || '—'} (rischio: ${data.scan?.risk_score ?? '?'}/100)</td></tr>
            </table>
          </div>
        `;
      }

      showToast(data.certified ? 'Test update verificato e certificato' : 'Verifica fallita', data.certified ? 'success' : 'danger');
    } catch (e) {
      showToast('Errore verifica: ' + e, 'danger');
      if (result) result.innerHTML = `<div class="alert alert-danger py-2 px-3 small">${esc(String(e))}</div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-shield-check"></i> Verifica'; }
    }
  };

  const cleanupTestUpdate = async () => {
    if (!confirm('Rimuovere il test update e tutte le tracce dal sistema OTA?')) return;
    const btn = q('otaTestCleanBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="ota2-spinner"></span> Rimozione…'; }

    try {
      await TPL.jsonFetch('/api/ota/test-update', { method: 'DELETE' });
      showToast('Test update rimosso', 'success');
      q('otaTestResult').innerHTML = '';
      await loadAll();
    } catch (e) {
      showToast('Errore rimozione: ' + e, 'danger');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-trash3"></i> Rimuovi'; }
      loadTestUpdateInfo();
    }
  };

  /* ── Event listeners ───────────────────────────────────────── */
  q('otaPageCheckBtn')?.addEventListener('click', checkUpdates);
  q('otaPageCfgSaveBtn')?.addEventListener('click', saveConfig);
  q('otaPageBackBtn')?.addEventListener('click', () => {
    q('otaPageDetailPanel')?.classList.add('d-none');
  });

  // Security buttons
  q('otaSecSimulateBtn')?.addEventListener('click', runSimulation);
  q('otaSecVerifyChainBtn')?.addEventListener('click', verifyChain);
  q('otaSecRepairChainBtn')?.addEventListener('click', repairChain);
  q('otaSecRefreshBtn')?.addEventListener('click', loadTrustInfo);
  q('otaSecCfgSaveBtn')?.addEventListener('click', saveSecurityConfig);

  // New feature buttons
  q('otaLockdownToggle')?.addEventListener('click', toggleLockdown);
  q('otaTofuVerifyBtn')?.addEventListener('click', verifyTofu);
  q('otaHealthRunBtn')?.addEventListener('click', runHealthCheck);
  q('otaSnapCreateBtn')?.addEventListener('click', createSnapshot);

  // Install buttons
  q('otaInstallStartBtn')?.addEventListener('click', startInstall);
  q('otaInstallApplyBtn')?.addEventListener('click', applyInstall);
  q('otaInstallRollbackBtn')?.addEventListener('click', rollbackInstall);
  q('otaInstallCancelBtn')?.addEventListener('click', cancelInstall);

  // Test Update buttons
  q('otaTestCreateBtn')?.addEventListener('click', createTestUpdate);
  q('otaTestCreateBtn2')?.addEventListener('click', createTestUpdate);
  q('otaTestDeliverBtn')?.addEventListener('click', deliverTestUpdate);
  q('otaTestVerifyBtn')?.addEventListener('click', verifyTestUpdate);
  q('otaTestCleanBtn')?.addEventListener('click', cleanupTestUpdate);

  // Host CLI: click-to-copy on ota2-cmd elements
  document.querySelectorAll('.ota2-cmd[data-copy]').forEach(cmd => {
    cmd.style.cursor = 'pointer';
    cmd.addEventListener('click', () => {
      const text = cmd.dataset.copy;
      navigator.clipboard.writeText(text).then(() => {
        cmd.classList.add('ota2-cmd--copied');
        setTimeout(() => cmd.classList.remove('ota2-cmd--copied'), 1500);
      }).catch(() => console.warn('Clipboard copy failed'));
    });
  });

  // Keyboard shortcuts: R=refresh, C=check, S=simulate, Esc=close detail
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    switch (e.key.toLowerCase()) {
      case 'r': e.preventDefault(); loadAll(); break;
      case 'c': e.preventDefault(); checkUpdates(); break;
      case 's': e.preventDefault(); runSimulation(); break;
      case 't': e.preventDefault(); createTestUpdate(); break;
      case 'i': e.preventDefault(); startInstall(); break;
      case 'escape':
        q('otaPageDetailPanel')?.classList.add('d-none');
        break;
    }
  });

  /* ── Load all ──────────────────────────────────────────────── */
  const loadAll = async () => {
    await Promise.all([
      loadStatus(),
      loadReleases(),
      loadChangelog(),
      loadRollback(),
      loadTrustInfo(),
      loadLockdownStatus(),
      loadTofuStatus(),
      loadMetrics(),
      loadSnapshots(),
      loadTestUpdateInfo(),
      loadInstallStatus(),
    ]);
  };

  loadAll();
})();
