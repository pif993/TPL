(() => {
  const q = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const guardBanner = q("g");
  const list = q("ml");

  let _modules = [];
  let _page = 1;
  const PER_PAGE = 9;
  let _viewMode = 'grid'; // 'grid' | 'list'

  /* ── Module-specific icons ───────────────────────────────── */
  const MOD_ICONS = {
    traefik:          'bi-signpost-split',
    web_gui:          'bi-window-desktop',
    ux_linear:        'bi-palette',
    api_base:         'bi-plug',
    api_engine_host:  'bi-cpu',
    auth_local:       'bi-key',
    auth_keycloak:    'bi-shield-lock',
    language_engine:  'bi-translate',
    log_engine:       'bi-journal-text',
    communication_engine: 'bi-chat-dots',
    security_hardening: 'bi-shield-check',
    encryption:       'bi-lock',
    ai_log_analysis:  'bi-robot',
    system_monitoring_ai: 'bi-activity',
    user_management:  'bi-people',
    router_manager:   'bi-diagram-3',
    template_manager: 'bi-file-earmark-code',
    version_manager:  'bi-git',
    ota_update:       'bi-cloud-arrow-down',
    resilience:       'bi-heart-pulse',
    self_diagnosis:   'bi-clipboard2-pulse',
    vault:            'bi-safe',
  };
  const MOD_CATEGORIES = {
    traefik: 'Infrastruttura', vault: 'Infrastruttura',
    web_gui: 'Interfaccia', ux_linear: 'Interfaccia',
    api_base: 'Core', api_engine_host: 'Core',
    auth_local: 'Autenticazione', auth_keycloak: 'Autenticazione',
    language_engine: 'Servizi', log_engine: 'Servizi',
    communication_engine: 'Servizi', encryption: 'Sicurezza',
    security_hardening: 'Sicurezza', ai_log_analysis: 'AI',
    system_monitoring_ai: 'AI', user_management: 'Gestione',
    router_manager: 'Gestione', template_manager: 'Gestione',
    version_manager: 'Gestione', ota_update: 'Gestione',
    resilience: 'Sistema', self_diagnosis: 'Sistema',
  };
  const CAT_COLORS = {
    Infrastruttura: '#3b82f6', Interfaccia: '#8b5cf6', Core: '#ec4899',
    Autenticazione: '#f59e0b', Servizi: '#06b6d4', Sicurezza: '#ef4444',
    AI: '#10b981', Gestione: '#6366f1', Sistema: '#64748b',
  };
  const modIcon = (id) => {
    const key = (id || '').replace(/^\d+_/, '');
    return MOD_ICONS[key] || 'bi-puzzle';
  };
  const modCategory = (id) => {
    const key = (id || '').replace(/^\d+_/, '');
    return MOD_CATEGORIES[key] || 'Altro';
  };

  const setGuard = (ok, text) => {
    guardBanner.className = 'ov-role-chip';
    guardBanner.innerHTML = `<i class="bi ${ok ? 'bi-check-circle' : 'bi-x-circle'}"></i> ${text}`;
  };

  const guard = async () => {
    if (!TPL.token()) { window.location.href = "/login"; return false; }
    try {
      const me = await TPL.jsonFetch("/api/me");
      if (!(me.roles || []).includes("admin")) { setGuard(false, "Accesso negato"); return false; }
      setGuard(true, `admin: ${me.sub}`);
      return true;
    } catch (_) { setGuard(false, "Sessione non valida"); return false; }
  };

  /* ── Stats bar ───────────────────────────────────────────── */
  const renderStats = (modules) => {
    const el = q('amStats');
    if (!el) return;
    const installed = modules.filter(m => m.installed).length;
    const available = modules.length - installed;
    const updates = modules.filter(m => m.needs_update).length;
    const pct = modules.length ? Math.round((installed / modules.length) * 100) : 0;
    el.innerHTML = `
      <div class="am-stats-bar">
        <span class="am-stat-chip am-stat-chip--installed"><i class="bi bi-check-circle-fill"></i> ${installed} installati</span>
        <span class="am-stat-chip am-stat-chip--available"><i class="bi bi-circle"></i> ${available} disponibili</span>
        ${updates ? `<span class="am-stat-chip am-stat-chip--update"><i class="bi bi-arrow-up-circle-fill"></i> ${updates} aggiornamenti</span>` : ''}
        <span class="am-stat-chip" style="margin-left:auto"><i class="bi bi-percent"></i> ${pct}% installato</span>
      </div>
    `;
  };

  /* ── Module list (read-only) ─────────────────────────────── */
  const renderModules = (modules) => {
    const pill = q('amCountPill');
    const search = (q('amSearch')?.value || '').toLowerCase();
    const filter = q('amFilter')?.value || 'all';

    let filtered = modules;
    if (search) filtered = filtered.filter(m =>
      (m.id||'').toLowerCase().includes(search) ||
      (m.desc||'').toLowerCase().includes(search) ||
      modCategory(m.id).toLowerCase().includes(search));
    if (filter === 'installed') filtered = filtered.filter(m => m.installed);
    if (filter === 'available') filtered = filtered.filter(m => !m.installed);

    if (pill) pill.textContent = `${filtered.length}/${modules.length}`;

    // Stats bar (always shows total)
    renderStats(modules);

    if (!filtered.length) {
      list.innerHTML = `<div class="ov-empty">
        <i class="bi bi-search" style="font-size:2rem;opacity:.4"></i>
        <span class="ov-empty-text" style="margin-top:.5rem">Nessun modulo corrisponde al filtro</span>
        <button class="btn btn-sm btn-outline-primary mt-2" onclick="document.getElementById('amSearch').value='';document.getElementById('amFilter').value='all';document.getElementById('amSearch').dispatchEvent(new Event('input'))">
          <i class="bi bi-arrow-counterclockwise"></i> Reset filtri
        </button>
      </div>`;
      return;
    }

    // Pagination
    const totalPages = Math.ceil(filtered.length / PER_PAGE);
    if (_page > totalPages) _page = totalPages;
    if (_page < 1) _page = 1;
    const start = (_page - 1) * PER_PAGE;
    const paged = filtered.slice(start, start + PER_PAGE);

    const viewClass = _viewMode === 'list' ? ' am-list-view' : '';
    const cardsHtml = paged.map((m, idx) => {
      const inst = m.installed;
      const name = (m.id||'').replace(/^\d+_/,'').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const icon = modIcon(m.id);
      const cat = modCategory(m.id);
      const catColor = CAT_COLORS[cat] || '#64748b';
      const delay = idx * 40;
      return `<div class="ov-mod-card" style="animation:amCardIn .3s ease-out ${delay}ms both" title="${esc(m.desc || name)}">
        <div class="ov-mod-icon ${inst?'mod-installed':'mod-available'}"><i class="bi ${icon}"></i></div>
        <div class="ov-mod-info">
          <div class="ov-mod-name">${esc(name)}</div>
          <div class="ov-mod-status">
            ${inst ? '<span style="color:#16a34a">● Installato</span>' : '<span style="color:#94a3b8">○ Disponibile</span>'}
            ${m.ver ? `<span class="am-ver">v${esc(m.ver)}</span>` : ''}
            <span style="font-size:.6rem;padding:.08rem .35rem;border-radius:.2rem;background:${catColor}18;color:${catColor};font-weight:600">${esc(cat)}</span>
          </div>
          ${m.desc ? `<div class="am-desc">${esc(m.desc)}</div>` : ''}
        </div>
        ${m.needs_update ? '<span class="am-update-badge" title="Aggiornamento disponibile"><i class="bi bi-arrow-up-circle-fill"></i></span>' : ''}
      </div>`;
    }).join('');

    // Pagination controls
    let paginationHtml = '';
    if (totalPages > 1) {
      const pages = [];
      pages.push(`<button class="am-page-btn" ${_page <= 1 ? 'disabled' : ''} data-page="${_page-1}" title="Pagina precedente"><i class="bi bi-chevron-left"></i></button>`);
      for (let p = 1; p <= totalPages; p++) {
        pages.push(`<button class="am-page-btn ${p === _page ? 'am-page-active' : ''}" data-page="${p}" title="Pagina ${p}">${p}</button>`);
      }
      pages.push(`<button class="am-page-btn" ${_page >= totalPages ? 'disabled' : ''} data-page="${_page+1}" title="Pagina successiva"><i class="bi bi-chevron-right"></i></button>`);
      paginationHtml = `<div class="am-pagination">
        ${pages.join('')}
        <span class="am-page-info">${start+1}–${Math.min(start+PER_PAGE, filtered.length)} di ${filtered.length}</span>
      </div>`;
    }

    list.innerHTML = `<div class="ov-mod-grid${viewClass}">${cardsHtml}</div>${paginationHtml}`;

    // Bind pagination clicks
    list.querySelectorAll('.am-page-btn[data-page]').forEach(btn => {
      btn.addEventListener('click', () => {
        const p = parseInt(btn.dataset.page);
        if (p >= 1 && p <= totalPages) { _page = p; renderModules(modules); }
      });
    });
  };

  /* ── Bundle info ─────────────────────────────────────────── */
  const loadBundleInfo = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/bundle');
      const el = q('amBundleInfo');
      if (data.mode === 'legacy') {
        el.innerHTML = `
          <div class="am-bundle-legacy">
            <i class="bi bi-info-circle text-info"></i>
            <div>
              <div class="am-bundle-mode">Modalit&agrave; Legacy</div>
              <div class="am-bundle-note">${esc(data.message)}</div>
              <div class="am-bundle-detail"><i class="bi bi-folder2-open me-1"></i>${data.modules_count} moduli in <code>${esc(data.modules_dir)}</code></div>
            </div>
          </div>`;
        return;
      }
      const m = data.manifest || {};
      const s = data.signature || {};
      const i = data.integrity || {};
      el.innerHTML = `
        <div class="am-bundle-grid">
          <div class="am-bundle-field"><span class="am-bf-label">Release</span><span class="am-bf-val">${esc(data.release_id || '?')}</span></div>
          <div class="am-bundle-field"><span class="am-bf-label">Versione</span><span class="am-bf-val am-bf-ver">v${esc(m.version || '?')}</span></div>
          <div class="am-bundle-field"><span class="am-bf-label">Canale</span><span class="am-bf-val">${esc(m.channel || '?')}</span></div>
          <div class="am-bundle-field"><span class="am-bf-label">Moduli</span><span class="am-bf-val">${data.modules_count || 0}</span></div>
          <div class="am-bundle-field"><span class="am-bf-label">Creato</span><span class="am-bf-val">${esc(m.created || '?')}</span></div>
          <div class="am-bundle-field"><span class="am-bf-label">Min. piattaforma</span><span class="am-bf-val">${esc(m.min_platform_version || '?')}</span></div>
        </div>
        <div class="am-bundle-row mt-2">
          <span class="am-sig-badge ${s.signed ? 'am-sig-ok' : 'am-sig-no'}">
            <i class="bi ${s.signed ? 'bi-shield-check' : 'bi-shield-x'}"></i>
            ${s.signed ? 'Firmato' : 'Non firmato'}
          </span>
          ${s.algorithm ? `<span class="am-sig-algo">${esc(s.algorithm)}</span>` : ''}
          ${s.key_fingerprint ? `<span class="am-sig-fp" title="Fingerprint chiave">${esc(s.key_fingerprint)}</span>` : ''}
          <span class="am-integrity-badge ${i.status === 'ok' ? 'am-int-ok' : 'am-int-err'}">
            <i class="bi ${i.status === 'ok' ? 'bi-check-circle' : 'bi-exclamation-triangle'}"></i>
            ${i.verified || 0}/${i.total || 0} verificati
          </span>
        </div>`;
    } catch (e) {
      q('amBundleInfo').innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e)}</span>`;
    }
  };

  /* ── Security checklist ──────────────────────────────────── */
  const loadSecChecklist = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/security-checklist');
      const pill = q('amSecPill');
      if (pill) {
        pill.textContent = `${data.score}/100 ${data.grade}`;
        pill.className = 'ov-pill ' + (data.score >= 80 ? 'ov-pill--success' : data.score >= 50 ? 'ov-pill--warning' : 'ov-pill--danger');
      }
      const el = q('amSecChecklist');
      el.innerHTML = data.checks.map(c => `
        <div class="am-sec-check">
          <span class="am-sec-dot am-sec-${c.status}"></span>
          <div class="am-sec-body">
            <span class="am-sec-label">${esc(c.label)}</span>
            <span class="am-sec-desc">${esc(c.description)}</span>
          </div>
          <span class="am-sec-sev am-sev-${c.severity}">${esc(c.severity)}</span>
        </div>
      `).join('');
    } catch (e) {
      q('amSecChecklist').innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e)}</span>`;
    }
  };

  /* ── Releases ────────────────────────────────────────────── */
  const loadReleases = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/releases');
      const pill = q('amRelPill');
      if (pill) pill.textContent = `${data.total} release`;
      const el = q('amReleases');
      if (!data.releases.length) {
        el.innerHTML = `<div class="ov-empty" style="padding:1.5rem">
          <i class="bi bi-inbox" style="font-size:1.6rem;opacity:.3"></i>
          <span class="ov-empty-text" style="margin-top:.4rem;font-size:.78rem">Nessuna release installata</span>
          <code style="font-size:.7rem;margin-top:.3rem;opacity:.6">tpl-modules install &lt;bundle&gt;</code>
        </div>`;
        return;
      }
      el.innerHTML = data.releases.map(r => `
        <div class="am-rel-item ${r.is_current ? 'am-rel-current' : ''}">
          <div class="am-rel-head">
            <span class="am-rel-ver">v${esc(r.version)}</span>
            ${r.is_current ? '<span class="am-rel-badge">CORRENTE</span>' : ''}
            <span class="am-rel-ch">${esc(r.channel)}</span>
          </div>
          <div class="am-rel-meta">
            <span><i class="bi bi-puzzle"></i> ${r.modules_count} moduli</span>
            <span><i class="bi bi-calendar"></i> ${esc(r.created)}</span>
            <span>${r.signed ? '<i class="bi bi-shield-check text-success"></i> Firmato' : '<i class="bi bi-shield-x text-muted"></i>'}</span>
          </div>
          <div class="am-rel-id">${esc(r.id)}</div>
        </div>
      `).join('');
    } catch (e) {
      q('amReleases').innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e)}</span>`;
    }
  };

  /* ── Integrity ───────────────────────────────────────────── */
  const loadIntegrity = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/integrity');
      const el = q('amIntegrity');
      if (!data.files || !data.files.length) {
        el.innerHTML = `<div class="ov-empty" style="padding:1.5rem">
          <i class="bi bi-fingerprint" style="font-size:1.6rem;opacity:.3"></i>
          <span class="ov-empty-text" style="margin-top:.4rem;font-size:.78rem">Nessun file da verificare</span>
        </div>`;
        return;
      }
      const okCount = data.files.filter(f => f.status === 'ok').length;
      el.innerHTML = `
        <div class="am-int-summary">
          <span class="am-int-mode">${esc(data.mode || '?')}</span>
          <span class="${data.status === 'ok' ? 'text-success' : data.status === 'unverified' ? 'text-muted' : 'text-danger'}">
            ${data.status === 'ok' ? `<i class="bi bi-check-circle me-1"></i>${okCount}/${data.files.length} verificati` : data.status === 'unverified' ? '<i class="bi bi-dash-circle me-1"></i>Non verificato (no manifest)' : '<i class="bi bi-x-circle me-1"></i>Errore integrit\u00e0'}
          </span>
        </div>
        ${data.files.map(f => `
          <div class="am-int-file">
            <span class="am-int-dot am-int-${f.status}"></span>
            <span class="am-int-name">${esc(f.file)}</span>
            <span class="am-int-hash">${esc(f.hash || '\u2014')}</span>
          </div>
        `).join('')}`;
    } catch (e) {
      q('amIntegrity').innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e)}</span>`;
    }
  };

  /* ── Distribution config ─────────────────────────────────── */
  const loadDistConfig = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/distribution-config');
      const el = q('amDistConfig');
      const rows = [
        ['Percorso moduli', data.modules_dir, 'bi-folder2-open'],
        ['Base releases', data.modules_base, 'bi-folder-symlink'],
        ['Directory releases', data.releases_dir, 'bi-collection'],
        ['Symlink corrente', data.current_link, 'bi-link-45deg'],
        ['Firma obbligatoria', data.require_signature ? 'S\u00ec' : 'No', 'bi-pen'],
        ['Canale aggiornamenti', data.update_channel, 'bi-broadcast'],
        ['URL aggiornamenti', data.update_url || '(non configurato)', 'bi-globe'],
        ['Max release', data.max_releases, 'bi-stack'],
        ['Control plane', data.control_plane_enabled ? '\u26a0 ABILITATO (dev)' : '\u2713 Disabilitato (prod)', 'bi-toggles'],
        ['Bundle attivo', data.bundle_active ? 'S\u00ec' : 'No \u2014 modalit\u00e0 legacy', 'bi-box-seam'],
      ];
      el.innerHTML = `<div class="am-config-grid">${rows.map(([k,v,ico]) =>
        `<div class="am-cfg-row"><span class="am-cfg-key"><i class="bi ${ico} me-1" style="opacity:.5"></i>${esc(k)}</span><span class="am-cfg-val">${esc(v)}</span></div>`
      ).join('')}</div>`;
    } catch (e) {
      q('amDistConfig').innerHTML = `<span class="text-danger small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e)}</span>`;
    }
  };

  /* ── Module list ─────────────────────────────────────────── */
  const loadModules = async () => {
    try {
      const data = await TPL.jsonFetch('/api/modules/state');
      _modules = data.modules || [];
      renderModules(_modules);
    } catch (e) {
      list.innerHTML = `<div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">${esc(e)}</span></div>`;
    }
  };

  /* ── Events ──────────────────────────────────────────────── */
  q('amRefreshBundle')?.addEventListener('click', () => {
    const btn = q('amRefreshBundle');
    const ico = btn?.querySelector('i');
    if (ico) { ico.style.animation = 'ovLoginSpin .6s linear'; setTimeout(() => ico.style.animation = '', 700); }
    loadAll();
  });
  q('amSearch')?.addEventListener('input', () => { _page = 1; renderModules(_modules); });
  q('amFilter')?.addEventListener('change', () => { _page = 1; renderModules(_modules); });

  // View toggle (grid / list)
  document.querySelectorAll('.am-view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.am-view-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _viewMode = btn.dataset.view || 'grid';
      renderModules(_modules);
    });
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'r' || e.key === 'R') { e.preventDefault(); loadAll(); }
    if (e.key === '/' || e.key === 'f' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); q('amSearch')?.focus(); }
    if (e.key === 'g') { _viewMode = _viewMode === 'grid' ? 'list' : 'grid'; document.querySelectorAll('.am-view-btn').forEach(b => b.classList.toggle('active', b.dataset.view === _viewMode)); renderModules(_modules); }
  });

  /* ── Load all ────────────────────────────────────────────── */
  const loadAll = async () => {
    await Promise.all([
      loadBundleInfo(),
      loadSecChecklist(),
      loadModules(),
      loadReleases(),
      loadIntegrity(),
      loadDistConfig(),
    ]);
  };

  (async () => {
    if (await guard()) await loadAll();
  })();
})();
