(() => {
  const q = (id) => document.getElementById(id);
  const feedback = q('feedback');

  const state = {
    me: null,
    isAdmin: false,
    currentView: 'overview',
    routeControl: null
  };

  const showMessage = (text, type = 'info') => {
    if (!feedback) return;
    feedback.className = `alert alert-${type}`;
    feedback.textContent = text;
    feedback.classList.remove('d-none');

    /* Trigger notifications for important messages */
    if (type === 'danger') {
      tplNotify('TPL — Errore', text);
    } else if (type === 'warning') {
      tplPlayNotifSound();
    }
  };

  const clearMessage = () => {
    if (!feedback) return;
    feedback.classList.add('d-none');
  };

  // -----------------------------------------------------------------------
  // Preferences Engine
  // -----------------------------------------------------------------------
  const _tplPrefDefaults = {
    notif_browser: false,
    notif_sound:   true,
    compact_mode:  false,
    auto_refresh:  true,
    show_welcome:  true,
  };

  /** Read a single preference value (or all if key omitted) */
  const tplPref = (key) => {
    const saved = JSON.parse(localStorage.getItem('tpl_prefs') || '{}');
    const merged = { ..._tplPrefDefaults, ...saved };
    return key !== undefined ? merged[key] : merged;
  };

  /** Write a single preference */
  const tplSetPref = (key, value) => {
    const current = JSON.parse(localStorage.getItem('tpl_prefs') || '{}');
    current[key] = value;
    localStorage.setItem('tpl_prefs', JSON.stringify(current));
    tplApplyPrefs();
  };

  /* ── Notification sound (lazy-loaded) ── */
  let _notifAudioCtx = null;
  const tplPlayNotifSound = () => {
    if (!tplPref('notif_sound')) return;
    try {
      if (!_notifAudioCtx) _notifAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const ctx = _notifAudioCtx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.3);
    } catch (_e) { /* AudioContext not available */ }
  };

  /* ── Browser notifications ── */
  const tplNotify = (title, body, icon = 'bi-bell') => {
    /* Sound */
    tplPlayNotifSound();

    /* Browser notification */
    if (!tplPref('notif_browser')) return;
    if (!('Notification' in window)) return;
    if (Notification.permission === 'granted') {
      new Notification(title, { body, icon: '/favicon.ico', tag: 'tpl-' + Date.now() });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(p => {
        if (p === 'granted') {
          new Notification(title, { body, icon: '/favicon.ico', tag: 'tpl-' + Date.now() });
        }
      });
    }
  };

  /* ── Overview auto-refresh timer ── */
  let _ovAutoRefreshTimer = null;
  const OV_REFRESH_INTERVAL = 30000; /* 30 seconds */

  const tplStartOverviewRefresh = () => {
    tplStopOverviewRefresh();
    if (!tplPref('auto_refresh')) return;
    _ovAutoRefreshTimer = setInterval(() => {
      if (state.currentView === 'overview') {
        loadOverview();
      }
    }, OV_REFRESH_INTERVAL);
  };

  const tplStopOverviewRefresh = () => {
    if (_ovAutoRefreshTimer) { clearInterval(_ovAutoRefreshTimer); _ovAutoRefreshTimer = null; }
  };

  /* ── Apply all preferences (called on init + on toggle change) ── */
  const tplApplyPrefs = () => {
    const prefs = tplPref();

    /* Compact mode */
    document.body.classList.toggle('tpl-compact', !!prefs.compact_mode);

    /* Auto-refresh: overview timer */
    if (prefs.auto_refresh) {
      if (!_ovAutoRefreshTimer && state.currentView === 'overview') tplStartOverviewRefresh();
    } else {
      tplStopOverviewRefresh();
    }

    /* Auto-refresh: also sync sec/rt existing toggles */
    const secCb = q('secAutoRefresh');
    if (secCb && secCb.checked !== prefs.auto_refresh) {
      secCb.checked = prefs.auto_refresh;
      secToggleAutoRefresh(prefs.auto_refresh);
    }
    const rtCb = q('rtAutoRefresh');
    if (rtCb && rtCb.checked !== prefs.auto_refresh) {
      rtCb.checked = prefs.auto_refresh;
      rtToggleAutoRefresh(prefs.auto_refresh);
    }

    /* Welcome hero */
    const heroEl = document.querySelector('#view-overview .ov-hero');
    if (heroEl) heroEl.classList.toggle('ov-hero--hidden', !prefs.show_welcome);

    /* Auto-refresh badge in overview */
    const badge = q('ovAutoRefreshBadge');
    if (badge) badge.classList.toggle('d-none', !prefs.auto_refresh);

    /* Browser notifications: request permission proactively */
    if (prefs.notif_browser && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  };

  const setAdminVisibility = () => {
    document.querySelectorAll('.admin-only').forEach((el) => {
      if (state.isAdmin) el.classList.remove('d-none');
      else el.classList.add('d-none');
    });
    /* Update centralised sidebar admin sections */
    if (window.TPLSidebar) window.TPLSidebar.setAdmin(state.isAdmin);
  };

  const setIdentity = () => {
    const roles = state.me?.roles || [];
    q('identityBox').textContent = `${state.me?.sub || TPL.t('label.username','user')} · ${roles.join(', ') || 'user'}`;
    /* Update centralised sidebar username */
    if (window.TPLSidebar) window.TPLSidebar.setUser(state.me?.sub || 'user');
  };

  const viewMeta = {
    overview:  { label: 'Overview',         icon: 'bi-speedometer2' },
    workspace: { label: 'Workspace',        icon: 'bi-collection' },
    myprofile: { label: 'Il mio profilo',   icon: 'bi-person-circle' },
    users:     { label: 'Gestione Utenti',  icon: 'bi-people' },
    modules:   { label: 'Centro Controllo',  icon: 'bi-cpu' },
    security:  { label: 'Security Center',  icon: 'bi-shield-lock-fill' },
    audit:     { label: 'Audit',            icon: 'bi-journal-text' },
    routes:    { label: 'Route Control',    icon: 'bi-signpost-split' },
    ai:        { label: 'AI Center',        icon: 'bi-robot' },
  };

  const switchView = async (view) => {
    if (!state.isAdmin && ['users', 'modules', 'security', 'audit', 'routes', 'ai'].includes(view)) {
      showMessage(TPL.t('msg.admin_only', 'Sezione disponibile solo per admin.'), 'warning');
      return;
    }

    state.currentView = view;
    document.querySelectorAll('.dash-view').forEach((el) => el.classList.add('d-none'));
    q(`view-${view}`)?.classList.remove('d-none');

    /* Stop overview auto-refresh when leaving overview */
    if (view !== 'overview') tplStopOverviewRefresh();

    /* Highlight active item in centralised sidebar */
    if (window.TPLSidebar) window.TPLSidebar.setActiveView(view);

    // Update breadcrumb & content header
    const meta = viewMeta[view] || { label: view, icon: 'bi-circle' };
    const titleEl = q('contentTitle');
    const bcEl = q('breadcrumbCurrent');
    if (titleEl) titleEl.innerHTML = `<i class="bi ${meta.icon} me-2"></i>${meta.label}`;
    if (bcEl) bcEl.textContent = meta.label;

    // Close sidebar on mobile after navigation
    if (window.innerWidth < 992 && window.TPLSidebar) {
      window.TPLSidebar.collapse();
    }

    clearMessage();

    if (view === 'overview') await loadOverview();
    if (view === 'workspace') await loadWorkspace();
    if (view === 'users') await loadUsersView();
    if (view === 'myprofile') await loadMyProfile();
    if (view === 'modules') await loadModules();
    if (view === 'security') await loadSecurity();
    if (view === 'audit') await loadAudit();
    if (view === 'routes') await loadRoutesPanel();
    if (view === 'ai') await loadAICenter();
  };

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------
  const esc = (s) => {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  };

  const fmtDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString('it-IT');
  };

  const getModal = (id) => {
    const el = document.getElementById(id);
    if (!el) return null;
    return bootstrap.Modal.getOrCreateInstance(el);
  };

  // -----------------------------------------------------------------------
  // OVERVIEW
  // -----------------------------------------------------------------------
  const ovTimeGreet = () => {
    const h = new Date().getHours();
    if (h < 12) return 'Buongiorno';
    if (h < 18) return 'Buon pomeriggio';
    return 'Buonasera';
  };

  /* ── Overview sub-renderers ── */

  const ovRenderServicesPanel = (h) => {
    const el = q('ovServGrid');
    if (!h) { el.innerHTML = '<span class="text-muted small">Dati non disponibili</span>'; return; }
    const run = h.services?.running ?? 0, tot = h.services?.total ?? 0, ok = h.services?.healthy;
    const pill = q('ovServPill');
    const countKnown = run >= 0 && tot >= 0;
    if (countKnown && ok && run === tot && tot > 0) { pill.textContent = `${run}/${tot} OK`; pill.className = 'ov-pill ov-pill--ok'; }
    else if (h.critical_count > 0) { pill.textContent = `${h.critical_count} critico`; pill.className = 'ov-pill ov-pill--crit'; }
    else if (ok) { pill.textContent = 'Healthy'; pill.className = 'ov-pill ov-pill--ok'; }
    else { pill.textContent = countKnown ? `${run}/${tot}` : '—'; pill.className = 'ov-pill ov-pill--warn'; }

    let html = '<div class="ov-svc-grid">';
    if (countKnown && tot > 0) {
      html += `<div class="ov-svc"><span class="ov-svc-dot ${run === tot ? 'dot-ok' : 'dot-warn'}"></span>
        <span class="ov-svc-name">In esecuzione</span>
        <span class="ov-svc-status ${run === tot ? 's-ok' : 's-warn'}">${run}/${tot}</span></div>`;
    }
    html += `<div class="ov-svc"><span class="ov-svc-dot ${ok ? 'dot-ok' : 'dot-crit'}"></span>
      <span class="ov-svc-name">Stato generale</span>
      <span class="ov-svc-status ${ok ? 's-ok' : 's-crit'}">${ok ? 'Healthy' : 'Unhealthy'}</span></div>`;
    html += `<div class="ov-svc"><span class="ov-svc-dot ${h.critical_count ? 'dot-crit' : 'dot-ok'}"></span>
        <span class="ov-svc-name">Critici</span>
        <span class="ov-svc-status ${h.critical_count ? 's-crit' : 's-ok'}">${h.critical_count || 0}</span></div>
      <div class="ov-svc"><span class="ov-svc-dot ${h.high_count ? 'dot-warn' : 'dot-ok'}"></span>
        <span class="ov-svc-name">Elevati</span>
        <span class="ov-svc-status ${h.high_count ? 's-warn' : 's-ok'}">${h.high_count || 0}</span></div>
    </div>`;

    if (h.issues?.length) {
      html += '<div class="mt-3"><div class="small fw-semibold mb-1" style="color:#64748b">Problemi rilevati</div>';
      h.issues.forEach(i => {
        const cls = /critical/i.test(i) ? 'text-danger bi-exclamation-octagon' : /high/i.test(i) ? 'text-warning bi-exclamation-triangle' : 'text-info bi-info-circle';
        html += `<div class="ov-issue"><i class="bi ${cls} ov-issue-icon"></i><span>${esc(i)}</span></div>`;
      });
      html += '</div>';
    } else {
      html += '<div class="mt-3 text-center"><i class="bi bi-check-circle text-success me-1"></i><span class="small text-muted">Nessun problema rilevato</span></div>';
    }
    el.innerHTML = html;
  };

  const ovRenderSecurityPanel = (sec) => {
    const el = q('ovSecPanel');
    if (!sec) { el.innerHTML = '<span class="text-muted small">Dati non disponibili</span>'; return; }
    const crit = sec.critical || 0, high = sec.high || 0, today = sec.total_today || 0;
    const total = crit + high;
    let level, lc, pct;
    if (total === 0)      { level = 'Basso';   lc = '#22c55e'; pct = 5;  }
    else if (total <= 2)  { level = 'Medio';   lc = '#f59e0b'; pct = 40; }
    else if (total <= 4)  { level = 'Alto';    lc = '#f97316'; pct = 70; }
    else                  { level = 'Critico'; lc = '#ef4444'; pct = 95; }

    el.innerHTML = `
      <div class="ov-threat-meter">
        <div class="ov-threat-label"><span>Livello di minaccia</span><span style="color:${lc};font-weight:700">${level}</span></div>
        <div class="ov-threat-track"><div class="ov-threat-fill" style="width:${pct}%;background:${lc}"></div></div>
      </div>
      <div class="ov-stat"><span class="ov-stat-label">Alert critici</span><span class="ov-stat-value" style="color:${crit?'#ef4444':'#22c55e'}">${crit}</span></div>
      <div class="ov-stat"><span class="ov-stat-label">Alert elevati</span><span class="ov-stat-value" style="color:${high?'#f59e0b':'#22c55e'}">${high}</span></div>
      <div class="ov-stat"><span class="ov-stat-label">Totale oggi</span><span class="ov-stat-value">${today}</span></div>`;
  };

  const ovRenderAiPanel = (ai) => {
    const el = q('ovAiPanel');
    if (!ai) { el.innerHTML = '<span class="text-muted small">Analisi AI non disponibile</span>'; return; }
    const sev = ai.severity || 'unknown';
    const anomalyCount = ai.anomalies?.total_logs || 0;
    const patterns = ai.patterns?.patterns || [];
    const rec = ai.recommendation || '—';
    const pill = q('ovAiPill');
    if (['low','normal'].includes(sev)) { pill.textContent = 'Normale'; pill.className = 'ov-pill ov-pill--ok'; }
    else if (sev === 'medium') { pill.textContent = 'Attenzione'; pill.className = 'ov-pill ov-pill--warn'; }
    else { pill.textContent = sev; pill.className = 'ov-pill ov-pill--crit'; }

    const sevCls = ['low','normal'].includes(sev) ? 'ii-success' : sev === 'medium' ? 'ii-warning' : 'ii-danger';
    const sevBi  = ['low','normal'].includes(sev) ? 'bi-check-circle' : sev === 'medium' ? 'bi-exclamation-triangle' : 'bi-exclamation-octagon';
    let html = `<div class="ov-insight">
      <div class="ov-insight-icon ${sevCls}"><i class="bi ${sevBi}"></i></div>
      <div><div class="ov-insight-title">Severità: ${esc(sev)}</div><div class="ov-insight-text">Log analizzati: ${anomalyCount}</div></div></div>`;
    html += `<div class="ov-insight">
      <div class="ov-insight-icon ii-info"><i class="bi bi-lightbulb"></i></div>
      <div><div class="ov-insight-title">Raccomandazione</div><div class="ov-insight-text">${esc(rec)}</div></div></div>`;
    if (patterns.length) {
      html += '<div class="mt-2"><div class="small fw-semibold mb-1" style="color:#64748b">Pattern rilevati</div>';
      patterns.slice(0, 5).forEach(p => {
        html += `<div class="ov-stat"><span class="ov-stat-label">${esc(p.name || p.pattern || '—')}</span><span class="ov-stat-value">${p.count || 0}</span></div>`;
      });
      html += '</div>';
    }
    el.innerHTML = html;
  };

  const ovRenderPredictions = (pred) => {
    const el = q('ovPredPanel');
    if (!pred) { el.innerHTML = '<span class="text-muted small">Predizioni non disponibili</span>'; return; }
    const preds = pred.predictions || [], actions = pred.recommended_actions || [];
    const overall = pred.overall_status || '—';
    const osCls = overall === 'stable' ? 'ii-success' : overall === 'warning' ? 'ii-warning' : 'ii-info';
    const osBi  = overall === 'stable' ? 'bi-check-circle' : overall === 'warning' ? 'bi-exclamation-triangle' : 'bi-bar-chart';
    let html = `<div class="ov-insight">
      <div class="ov-insight-icon ${osCls}"><i class="bi ${osBi}"></i></div>
      <div><div class="ov-insight-title">Stato complessivo</div><div class="ov-insight-text">${esc(overall)}</div></div></div>`;
    if (preds.length) {
      preds.slice(0, 4).forEach(p => {
        const rk = (p.risk || '').toLowerCase();
        const pCls = rk === 'low' ? 'ii-success' : rk === 'medium' ? 'ii-warning' : 'ii-danger';
        const pBi  = rk === 'low' ? 'bi-arrow-right' : 'bi-exclamation-diamond';
        html += `<div class="ov-insight">
          <div class="ov-insight-icon ${pCls}"><i class="bi ${pBi}"></i></div>
          <div><div class="ov-insight-title">${esc(p.component || p.metric || '—')}</div><div class="ov-insight-text">${esc(p.prediction || p.message || '—')}</div></div></div>`;
      });
    }
    if (actions.length) {
      html += '<div class="mt-2"><div class="small fw-semibold mb-1" style="color:#64748b">Azioni consigliate</div>';
      actions.slice(0, 4).forEach(a => {
        const txt = typeof a === 'string' ? a : a.action || a.message || JSON.stringify(a);
        html += `<div class="ov-issue"><i class="bi bi-arrow-right-circle text-primary ov-issue-icon"></i><span>${esc(txt)}</span></div>`;
      });
      html += '</div>';
    }
    if (!preds.length && !actions.length) {
      html += '<div class="text-center mt-2"><span class="text-muted small">Nessuna predizione al momento</span></div>';
    }
    el.innerHTML = html;
  };

  const ovRenderQuickActions = () => {
    const el = q('ovQuickActions');
    const acts = [
      { icon: 'bi-person-circle', label: 'Il mio Profilo',  fn: () => switchView('myprofile') },
      { icon: 'bi-collection',    label: 'Workspace',        fn: () => switchView('workspace') },
      { icon: 'bi-terminal',      label: 'Advanced',         fn: () => { location.href = '/advanced'; } },
    ];
    if (state.isAdmin) {
      acts.push(
        { icon: 'bi-people',         label: 'Gestione Utenti',  fn: () => switchView('users') },
        { icon: 'bi-shield-lock',    label: 'Security',         fn: () => switchView('security') },
        { icon: 'bi-puzzle',         label: 'Moduli',            fn: () => switchView('modules') },
        { icon: 'bi-journal-text',   label: 'Audit Log',        fn: () => switchView('audit') },
        { icon: 'bi-signpost-split', label: 'Route Control',    fn: () => switchView('routes') },
      );
    }
    let html = '<div class="ov-actions">';
    acts.forEach((a, i) => { html += `<a class="ov-action-btn" href="#" data-ov-act="${i}"><i class="bi ${a.icon}"></i>${esc(a.label)}</a>`; });
    html += '</div>';
    el.innerHTML = html;
    el.querySelectorAll('[data-ov-act]').forEach(btn => {
      btn.addEventListener('click', ev => { ev.preventDefault(); const i = +btn.dataset.ovAct; if (acts[i]?.fn) acts[i].fn(); });
    });
  };

  const ovRenderPlatformInfo = (data) => {
    const el = q('ovPlatformInfo');
    const rt = data?.rt, u = data?.u;
    let html = '';
    html += '<div class="ov-stat"><span class="ov-stat-label">Versione</span><span class="ov-stat-value">v3.0</span></div>';
    html += '<div class="ov-stat"><span class="ov-stat-label">API</span><span class="ov-stat-value" style="color:#22c55e">● Online</span></div>';
    if (rt) {
      html += `<div class="ov-stat"><span class="ov-stat-label">Route totali</span><span class="ov-stat-value">${rt.total_routes || 0}</span></div>`;
      html += `<div class="ov-stat"><span class="ov-stat-label">Route registrate</span><span class="ov-stat-value">${rt.registered_routes || 0}</span></div>`;
    }
    if (u) {
      html += `<div class="ov-stat"><span class="ov-stat-label">Utenti totali</span><span class="ov-stat-value">${u.total || 0}</span></div>`;
      if (u.roles_distribution) {
        const rd = Object.entries(u.roles_distribution).map(([r,n]) => `${r}: ${n}`).join(', ');
        html += `<div class="ov-stat"><span class="ov-stat-label">Ruoli</span><span class="ov-stat-value small">${esc(rd)}</span></div>`;
      }
    }
    html += `<div class="ov-stat"><span class="ov-stat-label">Ultimo aggiornamento</span><span class="ov-stat-value small">${new Date().toLocaleString('it-IT')}</span></div>`;
    el.innerHTML = html;
  };

  /* ── Main Overview loader ── */

  const loadOverview = async () => {
    const username = state.me?.sub || 'Utente';

    /* Welcome hero visibility (pref: show_welcome) */
    const heroEl = document.querySelector('#view-overview .ov-hero');
    if (heroEl) heroEl.classList.toggle('ov-hero--hidden', !tplPref('show_welcome'));

    q('ovGreeting').textContent = `${ovTimeGreet()}, ${username}`;
    q('ovRoleChip').innerHTML = `<i class="bi bi-person-badge"></i> ${(state.me?.roles || []).join(', ') || 'user'}`;
    q('ovClock').textContent = new Date().toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

    /* Auto-refresh badge */
    let arBadge = q('ovAutoRefreshBadge');
    if (!arBadge && heroEl) {
      const left = heroEl.querySelector('.ov-hero-left');
      if (left) {
        const b = document.createElement('div');
        b.id = 'ovAutoRefreshBadge';
        b.className = 'ov-autorefresh-badge' + (tplPref('auto_refresh') ? '' : ' d-none');
        b.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Auto-refresh ogni 30s';
        left.appendChild(b);
      }
    } else if (arBadge) {
      arBadge.classList.toggle('d-none', !tplPref('auto_refresh'));
    }

    /* Start auto-refresh timer if pref enabled */
    tplStartOverviewRefresh();

    ovRenderQuickActions();

    if (!state.isAdmin) {
      q('ovGreetingSub').textContent = 'Panoramica della piattaforma TPL';
      ovRenderPlatformInfo({});
      return;
    }

    q('ovGreetingSub').textContent = 'Pannello di controllo amministrativo';

    const [rH, rS, rU, rAi, rP, rR] = await Promise.allSettled([
      state.routeControl.call('health'),
      TPL.jsonFetch('/api/security/status'),
      TPL.jsonFetch('/api/users/stats/summary'),
      state.routeControl.call('ai'),
      TPL.jsonFetch('/api/monitoring/predictions'),
      TPL.jsonFetch('/api/router/status'),
    ]);
    const h    = rH.status  === 'fulfilled' ? rH.value  : null;
    const sec  = rS.status  === 'fulfilled' ? rS.value  : null;
    const u    = rU.status  === 'fulfilled' ? rU.value  : null;
    const ai   = rAi.status === 'fulfilled' ? rAi.value : null;
    const pred = rP.status  === 'fulfilled' ? rP.value  : null;
    const rt   = rR.status  === 'fulfilled' ? rR.value  : null;

    /* KPI: Health */
    const hSt = h?.status || 'unknown';
    const hLbl = hSt === 'healthy' ? 'Operativo' : hSt === 'degraded' ? 'Degradato' : hSt === 'critical' ? 'Critico' : '—';
    const hPct = hSt === 'healthy' ? 100 : hSt === 'degraded' ? 60 : hSt === 'critical' ? 20 : 0;
    q('ovKpiHealth').textContent = hLbl;
    q('ovKpiHealthBar').style.width = hPct + '%';
    if (hSt === 'critical') q('ovKpiHealth').closest('.ov-kpi').dataset.accent = 'danger';
    else if (hSt === 'degraded') q('ovKpiHealth').closest('.ov-kpi').dataset.accent = 'warning';

    /* KPI: Services */
    const sRun = h?.services?.running ?? 0, sTot = h?.services?.total ?? 0;
    const sHealthy = h?.services?.healthy;
    if (sRun < 0 || sTot < 0) {
      /* Engine returns -1 when count is unavailable */
      q('ovKpiServices').textContent = sHealthy ? '● OK' : '—';
      q('ovKpiServicesBar').style.width = sHealthy ? '100%' : '0%';
    } else {
      q('ovKpiServices').textContent = `${sRun} / ${sTot}`;
      q('ovKpiServicesBar').style.width = sTot ? Math.round(sRun / sTot * 100) + '%' : '0%';
    }

    /* KPI: Security */
    const cAll = (h?.critical_count || 0) + (sec?.critical || 0);
    const hAll = (h?.high_count || 0) + (sec?.high || 0);
    const threats = cAll + hAll;
    q('ovKpiThreats').textContent = threats;
    q('ovKpiThreatsBar').style.width = threats === 0 ? '100%' : Math.max(10, 100 - threats * 15) + '%';
    const tKpi = q('ovKpiThreats').closest('.ov-kpi');
    tKpi.dataset.accent = threats === 0 ? 'success' : cAll > 0 ? 'danger' : 'warning';

    /* KPI: Users */
    const uA = u?.active || 0, uT = u?.total || 0;
    q('ovKpiUsers').textContent = `${uA} / ${uT}`;
    q('ovKpiUsersBar').style.width = uT ? Math.round(uA / uT * 100) + '%' : '0%';

    /* Panels */
    ovRenderServicesPanel(h);
    ovRenderSecurityPanel(sec);
    ovRenderAiPanel(ai);
    ovRenderPredictions(pred);
    ovRenderPlatformInfo({ rt, u, h });
  };

  // -----------------------------------------------------------------------
  // WORKSPACE (quick-access hub with live system status)
  // -----------------------------------------------------------------------
  const loadWorkspace = async () => {
    const wsStatus = q('wsSystemStatus');
    if (!wsStatus) return;

    wsStatus.innerHTML = '<div class="ov-placeholder"><div class="ov-placeholder-pulse"></div></div>';

    try {
      const [health, ver] = await Promise.allSettled([
        TPL.jsonFetch('/api/health'),
        TPL.jsonFetch('/api/version/info'),
      ]);
      const h = health.status === 'fulfilled' ? health.value : null;
      const v = ver.status === 'fulfilled' ? ver.value : null;

      const hStatus = h?.status || 'unknown';
      const hColor = hStatus === 'ok' ? '#22c55e' : hStatus === 'degraded' ? '#f59e0b' : '#ef4444';
      const hLabel = hStatus === 'ok' ? 'Operativa' : hStatus === 'degraded' ? 'Degradata' : 'Critica';
      const authMode = h?.auth_mode || '—';
      const version = v?.version || v?.current_version || '—';
      const codename = v?.codename || '';
      const engLoaded = v?.engines_loaded ?? '—';

      wsStatus.innerHTML = `
        <div class="ws-status-grid">
          <div class="ws-status-card">
            <div class="ws-status-dot" style="background:${hColor}"></div>
            <div>
              <div class="ws-status-label">Piattaforma</div>
              <div class="ws-status-val">${esc(hLabel)}</div>
            </div>
          </div>
          <div class="ws-status-card">
            <i class="bi bi-tag"></i>
            <div>
              <div class="ws-status-label">Versione</div>
              <div class="ws-status-val">v${esc(String(version))}${codename ? ' · ' + esc(codename) : ''}</div>
            </div>
          </div>
          <div class="ws-status-card">
            <i class="bi bi-shield-lock"></i>
            <div>
              <div class="ws-status-label">Autenticazione</div>
              <div class="ws-status-val">${esc(authMode)}</div>
            </div>
          </div>
          <div class="ws-status-card">
            <i class="bi bi-gear-wide-connected"></i>
            <div>
              <div class="ws-status-label">Engine Caricati</div>
              <div class="ws-status-val">${esc(String(engLoaded))}</div>
            </div>
          </div>
        </div>
      `;
    } catch (_e) {
      wsStatus.innerHTML = '<p class="text-muted small">Impossibile caricare lo stato del sistema.</p>';
    }
  };

  // -----------------------------------------------------------------------
  // MY PROFILE (self-service)
  // -----------------------------------------------------------------------

  /* ── Profile tab switching ── */
  const mpTabMap = {
    personal: 'mpTabPersonal',
    contact:  'mpTabContact',
    address:  'mpTabAddress',
    notes:    'mpTabNotes',
    security: 'mpTabSecurity',
    prefs:    'mpTabPrefs',
  };
  let mpTabsBound = false;
  const mpBindTabs = () => {
    if (mpTabsBound) return;
    mpTabsBound = true;
    const tabBar = q('mpTabs');
    if (!tabBar) return;
    tabBar.addEventListener('click', (e) => {
      const btn = e.target.closest('.ov-tab');
      if (!btn) return;
      const tab = btn.dataset.ovTab;
      tabBar.querySelectorAll('.ov-tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      Object.entries(mpTabMap).forEach(([k, id]) => {
        const panel = q(id);
        if (panel) { panel.classList.toggle('d-none', k !== tab); }
      });
    });
  };

  /* ── Profile completion meter ── */
  const mpCompFields = [
    { key: 'first_name',  label: 'Nome',     icon: 'bi-person' },
    { key: 'last_name',   label: 'Cognome',   icon: 'bi-person' },
    { key: 'email',       label: 'Email',     icon: 'bi-envelope' },
    { key: 'phone',       label: 'Telefono',  icon: 'bi-telephone' },
    { key: 'fiscal_code', label: 'Cod. Fiscale', icon: 'bi-card-text' },
    { key: 'gender',      label: 'Genere',    icon: 'bi-gender-ambiguous' },
    { key: 'birth_date',  label: 'Nascita',   icon: 'bi-calendar' },
    { key: 'birth_place', label: 'Luogo nasc.', icon: 'bi-geo' },
    { key: 'address',     label: 'Indirizzo', icon: 'bi-house' },
    { key: 'city',        label: 'Città',     icon: 'bi-building' },
  ];

  const mpRenderCompletion = (profile) => {
    let filled = 0;
    let html = '';
    mpCompFields.forEach(f => {
      const ok = !!profile[f.key];
      if (ok) filled++;
      html += `<div class="ov-comp-item ${ok ? 'filled' : 'empty'}">`;
      html += `<i class="bi ${ok ? 'bi-check-circle-fill' : f.icon} ov-comp-icon"></i>`;
      html += `<span>${esc(f.label)}</span></div>`;
    });
    const pct = Math.round(filled / mpCompFields.length * 100);
    const grid = q('mpCompletionGrid');
    if (grid) grid.innerHTML = html;
    const pctEl = q('mpPct');
    if (pctEl) pctEl.textContent = pct + '%';
    const bar = q('mpProgressBar');
    if (bar) bar.style.width = pct + '%';
  };

  /* ── Profile activity panel ── */
  const mpRenderActivity = (user) => {
    const el = q('mpActivityPanel');
    if (!el) return;
    const updatedTs = user.updated ? fmtDate(user.updated) : '—';
    const items = [
      { icon: 'bi-person-badge', label: 'Username', value: user.username || '—' },
      { icon: 'bi-shield-check', label: 'Ruoli', value: (user.roles || []).map(r => `<span class="badge bg-primary bg-opacity-75 me-1" style="font-weight:500">${esc(r)}</span>`).join('') || '—', raw: true },
      { icon: 'bi-clock',        label: 'Ultimo accesso', value: fmtDate(user.last_login) },
      { icon: 'bi-arrow-repeat', label: 'Accessi totali', value: String(user.login_count || 0) },
      { icon: 'bi-calendar-plus',label: 'Creato il',       value: fmtDate(user.created) },
      { icon: 'bi-pencil-square',label: 'Ultimo aggiorn.', value: updatedTs },
    ];
    let html = '';
    items.forEach(i => {
      html += `<div class="ov-activity-row">`;
      html += `<span class="ov-activity-label"><i class="bi ${i.icon}"></i> ${esc(i.label)}</span>`;
      html += `<span class="ov-activity-value">${i.raw ? i.value : esc(i.value)}</span></div>`;
    });
    el.innerHTML = html;
  };

  /* ── Profile hero ── */
  const mpRenderHero = (user) => {
    const fn = user.profile?.first_name || '';
    const ln = user.profile?.last_name || '';
    const displayName = (fn || ln) ? `${fn} ${ln}`.trim() : (user.username || '—');
    q('mpHeroName').textContent = displayName;

    /* Avatar initials + active glow */
    const initials = (fn && ln) ? (fn[0] + ln[0]).toUpperCase() : (user.username || '?')[0].toUpperCase();
    const avatarEl = q('mpAvatar');
    avatarEl.textContent = initials;
    avatarEl.classList.toggle('ov-avatar--active', !!user.active);

    q('mpHeroRole').innerHTML = `<i class="bi bi-shield-check"></i> ${esc((user.roles || []).join(', ') || 'user')}`;
    const dot = q('mpHeroDot');
    dot.className = `ov-status-dot ${user.active ? 'dot-active' : 'dot-inactive'}`;
    q('mpHeroStatus').textContent = user.active ? 'Account attivo' : 'Account disattivato';

    /* Sub-line with member-since info */
    const sub = q('mpHeroSub');
    if (sub) {
      const since = user.created ? new Date(user.created * 1000).toLocaleDateString('it-IT', { month: 'long', year: 'numeric' }) : '';
      const logins = user.login_count || 0;
      sub.textContent = since ? `Membro da ${since} · ${logins} accessi totali` : '';
    }
  };

  /* ── Security tab ── */
  const mpRenderSecurity = (user) => {
    const panel = q('mpSecurityPanel');
    if (!panel) return;
    const mustChange = user.must_change_password;
    const lastLogin = user.last_login ? fmtDate(user.last_login) : 'Mai';
    const updatedAt = user.updated ? fmtDate(user.updated) : '—';
    const loginCount = user.login_count || 0;

    let html = '';
    /* Password status */
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon ${mustChange ? 'mp-sec-icon--warn' : 'mp-sec-icon--ok'}">
        <i class="bi ${mustChange ? 'bi-exclamation-triangle-fill' : 'bi-check-circle-fill'}"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Password</div>
        <div class="mp-sec-desc">${mustChange ? 'Cambio password richiesto.' : 'La password è impostata correttamente.'}</div>
        <button class="mp-sec-action" data-mp-action="change-password">Cambia password →</button>
      </div>
    </div>`;

    /* Login activity */
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon mp-sec-icon--info">
        <i class="bi bi-activity"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Attività di accesso</div>
        <div class="mp-sec-desc">Ultimo accesso: ${esc(lastLogin)}<br>${loginCount} accessi totali</div>
      </div>
    </div>`;

    /* Account status */
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon ${user.active ? 'mp-sec-icon--ok' : 'mp-sec-icon--warn'}">
        <i class="bi ${user.active ? 'bi-shield-check' : 'bi-shield-x'}"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Stato account</div>
        <div class="mp-sec-desc">${user.active ? 'Account attivo e operativo.' : 'Account disattivato.'}</div>
      </div>
    </div>`;

    /* Profile last updated */
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon mp-sec-icon--info">
        <i class="bi bi-clock-history"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Ultimo aggiornamento</div>
        <div class="mp-sec-desc">Profilo aggiornato il ${esc(updatedAt)}</div>
      </div>
    </div>`;

    /* Roles */
    const rolesHtml = (user.roles || []).map(r => `<span class="badge bg-primary bg-opacity-75 me-1">${esc(r)}</span>`).join('') || '—';
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon mp-sec-icon--info">
        <i class="bi bi-people-fill"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Ruoli assegnati</div>
        <div class="mp-sec-desc">${rolesHtml}</div>
      </div>
    </div>`;

    /* Session info */
    html += `<div class="mp-sec-card">
      <div class="mp-sec-icon mp-sec-icon--ok">
        <i class="bi bi-lock-fill"></i>
      </div>
      <div class="mp-sec-body">
        <div class="mp-sec-title">Sessione corrente</div>
        <div class="mp-sec-desc">Connesso tramite JWT token. La sessione scade automaticamente.</div>
      </div>
    </div>`;

    panel.innerHTML = html;

    /* Bind actions */
    panel.querySelectorAll('[data-mp-action="change-password"]').forEach(btn => {
      btn.addEventListener('click', () => openSelfPasswordModal());
    });
  };

  /* ── Preferences tab ── */
  const mpPrefsDef = [
    { key: 'notif_browser',  icon: 'bi-bell',           label: 'Notifiche browser',       desc: 'Ricevi notifiche push nel browser (richiede permesso)' },
    { key: 'notif_sound',    icon: 'bi-volume-up',      label: 'Suoni notifiche',         desc: 'Riproduci un suono per gli avvisi di sistema' },
    { key: 'compact_mode',   icon: 'bi-layout-sidebar', label: 'Modalità compatta',       desc: 'Riduci lo spazio tra gli elementi per più contenuto visibile' },
    { key: 'auto_refresh',   icon: 'bi-arrow-clockwise',label: 'Auto-refresh dashboard',  desc: 'Aggiorna automaticamente overview (30s), security e routes (15s)' },
    { key: 'show_welcome',   icon: 'bi-hand-wave',      label: 'Messaggio di benvenuto',  desc: 'Mostra il banner di saluto nella pagina overview' },
  ];

  const mpRenderPrefs = () => {
    const panel = q('mpPrefsPanel');
    if (!panel) return;

    const current = tplPref(); /* read all current values */

    let html = '';
    mpPrefsDef.forEach(p => {
      const checked = current[p.key];
      /* Status tag */
      const statusTag = checked
        ? '<span style="font-size:.65rem;color:#22c55e;font-weight:600;margin-left:.4rem">● ATTIVO</span>'
        : '<span style="font-size:.65rem;color:var(--ov-text-faint);margin-left:.4rem">○ OFF</span>';
      html += `<div class="mp-pref-row">
        <div class="mp-pref-left">
          <span class="mp-pref-icon"><i class="bi ${p.icon}"></i></span>
          <div class="mp-pref-info">
            <div class="mp-pref-label">${esc(p.label)}${statusTag}</div>
            <div class="mp-pref-desc">${esc(p.desc)}</div>
          </div>
        </div>
        <label class="mp-toggle">
          <input type="checkbox" data-pref-key="${p.key}" ${checked ? 'checked' : ''}>
          <span class="mp-toggle-slider"></span>
        </label>
      </div>`;
    });

    panel.innerHTML = html;

    /* Bind toggle changes → immediate apply */
    panel.querySelectorAll('[data-pref-key]').forEach(cb => {
      cb.addEventListener('change', () => {
        tplSetPref(cb.dataset.prefKey, cb.checked);
        /* Re-render to update status tags */
        mpRenderPrefs();
        /* Play sound feedback on any toggle */
        tplPlayNotifSound();
      });
    });
  };

  /* ── Dirty-form tracking ── */
  let _mpOriginalValues = {};
  let _mpDirty = false;

  const mpCaptureOriginal = () => {
    _mpOriginalValues = mpGetFormValues();
    _mpDirty = false;
    const badge = q('mpDirtyBadge');
    if (badge) badge.classList.add('d-none');
  };

  const mpGetFormValues = () => ({
    first_name:  q('mpFirstName')?.value.trim() || '',
    last_name:   q('mpLastName')?.value.trim() || '',
    email:       q('mpEmail')?.value.trim() || '',
    phone:       q('mpPhone')?.value.trim() || '',
    fiscal_code: q('mpFiscalCode')?.value.trim() || '',
    gender:      q('mpGender')?.value || '',
    birth_date:  q('mpBirthDate')?.value || '',
    birth_place: q('mpBirthPlace')?.value.trim() || '',
    address:     q('mpAddress')?.value.trim() || '',
    city:        q('mpCity')?.value.trim() || '',
    province:    q('mpProvince')?.value.trim() || '',
    zip_code:    q('mpZipCode')?.value.trim() || '',
    notes:       q('mpNotes')?.value.trim() || '',
  });

  const mpCheckDirty = () => {
    const current = mpGetFormValues();
    const dirty = Object.keys(current).some(k => current[k] !== (_mpOriginalValues[k] || ''));
    if (dirty !== _mpDirty) {
      _mpDirty = dirty;
      const badge = q('mpDirtyBadge');
      if (badge) badge.classList.toggle('d-none', !dirty);
    }
  };

  /* ── Client-side validation ── */
  const mpValidateField = (id, errId, validator) => {
    const el = q(id);
    const errEl = errId ? q(errId) : null;
    if (!el) return true;
    const val = el.value.trim();
    const result = validator(val);
    if (result === true || result === '') {
      el.classList.remove('is-invalid');
      if (val) el.classList.add('is-valid'); else el.classList.remove('is-valid');
      if (errEl) errEl.classList.add('d-none');
      return true;
    }
    el.classList.add('is-invalid');
    el.classList.remove('is-valid');
    if (errEl) { errEl.textContent = result; errEl.classList.remove('d-none'); }
    return false;
  };

  const mpValidateAll = () => {
    let ok = true;
    /* Email */
    if (!mpValidateField('mpEmail', 'mpEmailErr', v => {
      if (!v) return true;
      return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) ? true : 'Formato email non valido';
    })) ok = false;
    /* Fiscal code */
    if (!mpValidateField('mpFiscalCode', 'mpFiscalCodeErr', v => {
      if (!v) return true;
      return /^[A-Z0-9]{16}$/i.test(v) ? true : 'Deve essere 16 caratteri alfanumerici';
    })) ok = false;
    /* Phone */
    if (!mpValidateField('mpPhone', 'mpPhoneErr', v => {
      if (!v) return true;
      return /^[+\d\s()-]{6,20}$/.test(v) ? true : 'Formato telefono non valido';
    })) ok = false;
    /* ZIP */
    if (!mpValidateField('mpZipCode', 'mpZipCodeErr', v => {
      if (!v) return true;
      return /^\d{5}$/.test(v) ? true : 'Il CAP deve essere 5 cifre';
    })) ok = false;
    return ok;
  };

  /* ── Notes character counter ── */
  const mpBindNotesCounter = () => {
    const notes = q('mpNotes');
    const counter = q('mpNotesCount');
    if (!notes || !counter) return;
    const update = () => { counter.textContent = notes.value.length; };
    notes.addEventListener('input', update);
    update();
  };

  /* ── Export profile as JSON ── */
  const mpExportProfile = () => {
    const values = mpGetFormValues();
    const blob = new Blob([JSON.stringify(values, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `profilo_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  /* ── Bind dirty tracking to form fields ── */
  let _mpFormBound = false;
  const mpBindFormTracking = () => {
    if (_mpFormBound) return;
    _mpFormBound = true;
    const section = document.getElementById('view-myprofile');
    if (!section) return;
    section.addEventListener('input', mpCheckDirty);
    section.addEventListener('change', mpCheckDirty);

    /* Ctrl+S shortcut */
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's' && state.currentView === 'myprofile') {
        e.preventDefault();
        saveMyProfile();
      }
    });
  };

  /* ── Load profile ── */
  const loadMyProfile = async () => {
    mpBindTabs();
    mpBindFormTracking();
    mpBindNotesCounter();
    try {
      const data = await TPL.jsonFetch('/api/users/me/profile');
      const user = data?.user || {};
      const profile = user.profile || {};

      /* Hero */
      mpRenderHero(user);

      /* Form fields */
      q('mpFirstName').value  = profile.first_name || '';
      q('mpLastName').value   = profile.last_name || '';
      q('mpEmail').value      = profile.email || '';
      q('mpPhone').value      = profile.phone || '';
      q('mpFiscalCode').value = profile.fiscal_code || '';
      q('mpGender').value     = profile.gender || '';
      q('mpBirthDate').value  = profile.birth_date || '';
      q('mpBirthPlace').value = profile.birth_place || '';
      q('mpAddress').value    = profile.address || '';
      q('mpCity').value       = profile.city || '';
      q('mpProvince').value   = profile.province || '';
      q('mpZipCode').value    = profile.zip_code || '';
      q('mpNotes').value      = profile.notes || '';

      /* Capture original for dirty tracking */
      mpCaptureOriginal();

      /* Update notes counter */
      const counter = q('mpNotesCount');
      if (counter) counter.textContent = (profile.notes || '').length;

      /* Completion + activity + security + prefs */
      mpRenderCompletion(profile);
      mpRenderActivity(user);
      mpRenderSecurity(user);
      mpRenderPrefs();

      /* Clear validation states */
      document.querySelectorAll('#view-myprofile .is-valid, #view-myprofile .is-invalid').forEach(el => {
        el.classList.remove('is-valid', 'is-invalid');
      });
      document.querySelectorAll('#view-myprofile .ov-field-err').forEach(el => {
        el.classList.add('d-none');
      });

      /* Reset feedback */
      const fb = q('mpFeedback');
      fb.classList.add('d-none');
      q('mpSaveHint').textContent = '';

      /* Password change warning */
      if (user.must_change_password) {
        fb.className = 'ov-toast ov-toast--warning';
        fb.innerHTML = '<i class="bi bi-exclamation-triangle me-1"></i> È richiesto il cambio password. Usa il pulsante "Cambia Password".';
        fb.classList.remove('d-none');
      }
    } catch (error) {
      showMessage(`Profilo error: ${String(error)}`, 'warning');
    }
  };

  /* ── Save profile ── */
  const saveMyProfile = async () => {
    /* Validate first */
    if (!mpValidateAll()) {
      const fb = q('mpFeedback');
      fb.className = 'ov-toast ov-toast--danger';
      fb.innerHTML = '<i class="bi bi-x-circle me-1"></i> Correggi gli errori evidenziati prima di salvare.';
      fb.classList.remove('d-none');
      return;
    }
    const fb = q('mpFeedback');
    const hint = q('mpSaveHint');
    hint.textContent = 'Salvataggio in corso…';
    try {
      await TPL.jsonFetch('/api/users/me/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mpGetFormValues())
      });
      fb.className = 'ov-toast ov-toast--success';
      fb.innerHTML = '<i class="bi bi-check-circle me-1"></i> Profilo aggiornato con successo.';
      fb.classList.remove('d-none');
      hint.textContent = 'Salvato ✓';
      tplNotify('TPL — Profilo', 'Profilo aggiornato con successo.');
      setTimeout(() => { hint.textContent = ''; fb.classList.add('d-none'); }, 3000);
      /* Refresh completion meter & hero */
      await loadMyProfile();
    } catch (error) {
      fb.className = 'ov-toast ov-toast--danger';
      fb.innerHTML = `<i class="bi bi-x-circle me-1"></i> Errore: ${esc(String(error))}`;
      fb.classList.remove('d-none');
      hint.textContent = '';
    }
  };

  // -----------------------------------------------------------------------
  // USERS (Admin) — list, search, stats
  // -----------------------------------------------------------------------
  const loadUsersView = async () => {
    await Promise.all([loadUsers(), loadUserStats()]);
  };

  const loadUserStats = async () => {
    try {
      const data = await TPL.jsonFetch('/api/users/stats/summary');
      const total = data.total || 0;
      const active = data.active || 0;
      const inactive = data.inactive || 0;
      const mustPw = data.must_change_password || 0;

      q('statTotalUsers').textContent = total;
      q('statActiveUsers').textContent = active;
      q('statInactiveUsers').textContent = inactive;
      q('statMustChangePw').textContent = mustPw;

      /* Animate KPI bars */
      const pctActive = total ? Math.round((active / total) * 100) : 0;
      const pctInactive = total ? Math.round((inactive / total) * 100) : 0;
      const pctPw = total ? Math.round((mustPw / total) * 100) : 0;
      requestAnimationFrame(() => {
        const ab = q('umActiveBar');   if (ab) ab.style.width = pctActive + '%';
        const ib = q('umInactiveBar'); if (ib) ib.style.width = pctInactive + '%';
        const pb = q('umPwBar');       if (pb) pb.style.width = pctPw + '%';
      });
    } catch (e) { console.warn('loadUserStats failed:', e); }
  };

  const loadUsers = async () => {
    try {
      const params = new URLSearchParams();
      const search = q('userSearchInput')?.value?.trim();
      const role = q('userRoleFilter')?.value;
      const activeFilter = q('userActiveFilter')?.value;

      if (search) params.set('search', search);
      if (role) params.set('role', role);
      if (activeFilter === 'active') params.set('active_only', 'true');

      const qs = params.toString() ? `?${params}` : '';
      const data = await TPL.jsonFetch(`/api/users${qs}`);
      const users = data?.users || [];

      /* Update count pill */
      const pill = q('umCountPill');
      if (pill) {
        pill.textContent = `${users.length} utent${users.length === 1 ? 'e' : 'i'}`;
        pill.className = 'ov-pill' + (users.length ? ' ov-pill--ok' : '');
      }

      if (users.length === 0) {
        q('usersTbody').innerHTML = `<tr><td colspan="8"><div class="ov-empty"><i class="bi bi-people"></i><span class="ov-empty-text">Nessun utente trovato</span></div></td></tr>`;
        return;
      }

      const rows = users.map((u) => {
        const active = u.active;
        const statusBadge = active
          ? '<span class="ov-badge ov-badge--success">Attivo</span>'
          : '<span class="ov-badge ov-badge--danger">Disattivato</span>';
        const mustChange = u.must_change_password ? ' <span class="ov-badge ov-badge--warning" title="Cambio password richiesto">PW</span>' : '';
        const lastLogin = fmtDate(u.last_login);

        return `<tr>
          <td><span class="ov-cell-user">${esc(u.username)}</span>${mustChange}</td>
          <td>${esc(u.first_name || '')}</td>
          <td>${esc(u.last_name || '')}</td>
          <td>${esc(u.email || '')}</td>
          <td>${(u.roles || []).map(r => `<span class="ov-badge ov-badge--muted me-1">${esc(r)}</span>`).join('')}</td>
          <td>${statusBadge}</td>
          <td class="small" style="color:var(--ov-text-faint)">${lastLogin}</td>
          <td>
            <div class="ov-btn-group">
              <button class="ov-btn-icon btn--view" type="button" data-view-user="${esc(u.username)}" title="Dettaglio" aria-label="Dettaglio ${esc(u.username)}"><i class="bi bi-eye"></i></button>
              <button class="ov-btn-icon btn--edit" type="button" data-edit-user="${esc(u.username)}" title="Modifica" aria-label="Modifica ${esc(u.username)}"><i class="bi bi-pencil-square"></i></button>
              <button class="ov-btn-icon btn--key" type="button" data-reset-pw="${esc(u.username)}" title="Reset password" aria-label="Reset password ${esc(u.username)}"><i class="bi bi-key"></i></button>
              ${u.active
                ? `<button class="ov-btn-icon btn--stop" type="button" data-revoke-user="${esc(u.username)}" title="Disattiva" aria-label="Disattiva ${esc(u.username)}"><i class="bi bi-pause-circle"></i></button>`
                : `<button class="ov-btn-icon btn--play" type="button" data-activate-user="${esc(u.username)}" title="Riattiva" aria-label="Riattiva ${esc(u.username)}"><i class="bi bi-check-circle"></i></button>`}
              <button class="ov-btn-icon btn--del" type="button" data-delete-user="${esc(u.username)}" title="Elimina" aria-label="Elimina ${esc(u.username)}"><i class="bi bi-x-lg"></i></button>
            </div>
          </td>
        </tr>`;
      }).join('');
      q('usersTbody').innerHTML = rows;
    } catch (error) {
      showMessage(`Users error: ${String(error)}`, 'warning');
      q('usersTbody').innerHTML = `<tr><td colspan="8"><div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">Errore: ${esc(String(error))}</span></div></td></tr>`;
    }
  };

  // -----------------------------------------------------------------------
  // USER DETAIL modal (read-only)
  // -----------------------------------------------------------------------
  const viewUserDetail = async (username) => {
    try {
      const data = await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}`);
      const u = data?.user || {};
      const p = u.profile || {};
      const html = `
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem;padding-bottom:.75rem;border-bottom:1px solid var(--ov-border)">
          <div style="width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;font-size:1.2rem;font-weight:700;flex-shrink:0">${esc((p.first_name || u.username || '?')[0]).toUpperCase()}</div>
          <div>
            <div style="font-size:1.1rem;font-weight:700;color:var(--ov-text)">${esc(u.username)}</div>
            <div style="display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.2rem">
              ${u.active ? '<span class="ov-badge ov-badge--success">Attivo</span>' : '<span class="ov-badge ov-badge--danger">Disattivato</span>'}
              ${u.must_change_password ? '<span class="ov-badge ov-badge--warning">Cambio PW</span>' : ''}
              ${(u.roles||[]).map(r=>`<span class="ov-badge ov-badge--primary">${esc(r)}</span>`).join('')}
            </div>
          </div>
        </div>
        <h6 style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--ov-text-faint);margin-bottom:.5rem">Anagrafica</h6>
        <div class="row g-2 mb-3">
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">Nome</span><span class="ov-stat-value">${esc(p.first_name) || '—'}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">Cognome</span><span class="ov-stat-value">${esc(p.last_name) || '—'}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">CF</span><span class="ov-stat-value">${esc(p.fiscal_code) || '—'}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">Email</span><span class="ov-stat-value">${esc(p.email) || '—'}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">Telefono</span><span class="ov-stat-value">${esc(p.phone) || '—'}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label">Genere</span><span class="ov-stat-value">${esc(p.gender) || '—'}</span></div></div>
          <div class="col-md-6"><div class="ov-stat"><span class="ov-stat-label">Data nascita</span><span class="ov-stat-value">${esc(p.birth_date) || '—'}</span></div></div>
          <div class="col-md-6"><div class="ov-stat"><span class="ov-stat-label">Luogo nascita</span><span class="ov-stat-value">${esc(p.birth_place) || '—'}</span></div></div>
        </div>
        <h6 style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--ov-text-faint);margin-bottom:.5rem">Indirizzo</h6>
        <div class="row g-2 mb-3">
          <div class="col-md-5"><div class="ov-stat"><span class="ov-stat-label">Indirizzo</span><span class="ov-stat-value">${esc(p.address) || '—'}</span></div></div>
          <div class="col-md-3"><div class="ov-stat"><span class="ov-stat-label">Città</span><span class="ov-stat-value">${esc(p.city) || '—'}</span></div></div>
          <div class="col-md-2"><div class="ov-stat"><span class="ov-stat-label">Prov.</span><span class="ov-stat-value">${esc(p.province) || '—'}</span></div></div>
          <div class="col-md-2"><div class="ov-stat"><span class="ov-stat-label">CAP</span><span class="ov-stat-value">${esc(p.zip_code) || '—'}</span></div></div>
        </div>
        <div class="ov-stat mb-2"><span class="ov-stat-label">Note</span><span class="ov-stat-value">${esc(p.notes) || '—'}</span></div>
        <h6 style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--ov-text-faint);margin-bottom:.5rem;margin-top:.75rem">Account</h6>
        <div class="row g-2">
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label"><i class="bi bi-calendar-plus"></i> Creato</span><span class="ov-stat-value">${fmtDate(u.created)}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label"><i class="bi bi-pencil-square"></i> Aggiornato</span><span class="ov-stat-value">${fmtDate(u.updated)}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label"><i class="bi bi-box-arrow-in-right"></i> Ultimo accesso</span><span class="ov-stat-value">${fmtDate(u.last_login)}</span></div></div>
          <div class="col-md-4"><div class="ov-stat"><span class="ov-stat-label"><i class="bi bi-arrow-repeat"></i> Accessi totali</span><span class="ov-stat-value">${u.login_count || 0}</span></div></div>
        </div>`;
      q('userDetailBody').innerHTML = html;
      getModal('userDetailModal')?.show();
    } catch (error) {
      showMessage(`Errore dettaglio: ${String(error)}`, 'danger');
    }
  };

  // -----------------------------------------------------------------------
  // CREATE / EDIT user modal
  // -----------------------------------------------------------------------
  const openCreateUserModal = () => {
    q('umEditMode').value = 'create';
    q('userModalTitle').textContent = 'Nuovo utente';
    q('umUsername').value = '';
    q('umUsername').disabled = false;
    q('umPassword').value = '';
    q('umPassword').closest('.col-md-6').classList.remove('d-none');
    q('umFirstName').value = '';
    q('umLastName').value = '';
    q('umFiscalCode').value = '';
    q('umEmail').value = '';
    q('umPhone').value = '';
    q('umGender').value = '';
    q('umBirthDate').value = '';
    q('umBirthPlace').value = '';
    q('umAddress').value = '';
    q('umCity').value = '';
    q('umProvince').value = '';
    q('umZipCode').value = '';
    q('umNotes').value = '';
    q('umActive').value = 'true';
    // Reset roles
    document.querySelectorAll('#umRolesCheckboxes input').forEach(cb => {
      cb.checked = cb.value === 'user';
    });
    q('umError').classList.add('d-none');
    getModal('userModal')?.show();
  };

  const openEditUserModal = async (username) => {
    try {
      const data = await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}`);
      const u = data?.user || {};
      const p = u.profile || {};

      q('umEditMode').value = 'edit';
      q('userModalTitle').textContent = `Modifica: ${username}`;
      q('umUsername').value = username;
      q('umUsername').disabled = true;
      q('umPassword').value = '';
      q('umPassword').closest('.col-md-6').classList.add('d-none');
      q('umFirstName').value = p.first_name || '';
      q('umLastName').value = p.last_name || '';
      q('umFiscalCode').value = p.fiscal_code || '';
      q('umEmail').value = p.email || '';
      q('umPhone').value = p.phone || '';
      q('umGender').value = p.gender || '';
      q('umBirthDate').value = p.birth_date || '';
      q('umBirthPlace').value = p.birth_place || '';
      q('umAddress').value = p.address || '';
      q('umCity').value = p.city || '';
      q('umProvince').value = p.province || '';
      q('umZipCode').value = p.zip_code || '';
      q('umNotes').value = p.notes || '';
      q('umActive').value = u.active ? 'true' : 'false';

      document.querySelectorAll('#umRolesCheckboxes input').forEach(cb => {
        cb.checked = (u.roles || []).includes(cb.value);
      });

      q('umError').classList.add('d-none');
      getModal('userModal')?.show();
    } catch (error) {
      showMessage(`Errore caricamento utente: ${String(error)}`, 'danger');
    }
  };

  const saveUser = async () => {
    const mode = q('umEditMode').value;
    const username = q('umUsername').value.trim();
    const errEl = q('umError');
    errEl.classList.add('d-none');

    const selectedRoles = [];
    document.querySelectorAll('#umRolesCheckboxes input:checked').forEach(cb => {
      selectedRoles.push(cb.value);
    });

    if (!selectedRoles.length) {
      errEl.textContent = 'Seleziona almeno un ruolo.';
      errEl.classList.remove('d-none');
      return;
    }

    const profile = {
      first_name: q('umFirstName').value.trim(),
      last_name: q('umLastName').value.trim(),
      fiscal_code: q('umFiscalCode').value.trim(),
      email: q('umEmail').value.trim(),
      phone: q('umPhone').value.trim(),
      gender: q('umGender').value,
      birth_date: q('umBirthDate').value,
      birth_place: q('umBirthPlace').value.trim(),
      address: q('umAddress').value.trim(),
      city: q('umCity').value.trim(),
      province: q('umProvince').value.trim(),
      zip_code: q('umZipCode').value.trim(),
      notes: q('umNotes').value.trim(),
    };

    try {
      if (mode === 'create') {
        const password = q('umPassword').value;
        if (!username) { errEl.textContent = 'Username obbligatorio.'; errEl.classList.remove('d-none'); return; }
        if (!password || password.length < 8) { errEl.textContent = 'Password minimo 8 caratteri.'; errEl.classList.remove('d-none'); return; }

        await TPL.jsonFetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, roles: selectedRoles, profile })
        });
        showMessage(`Utente creato: ${username}`, 'success');
      } else {
        await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            roles: selectedRoles,
            active: q('umActive').value === 'true',
            profile
          })
        });
        showMessage(`Utente aggiornato: ${username}`, 'success');
      }
      getModal('userModal')?.hide();
      await loadUsersView();
    } catch (error) {
      errEl.textContent = String(error);
      errEl.classList.remove('d-none');
    }
  };

  // -----------------------------------------------------------------------
  // PASSWORD modals
  // -----------------------------------------------------------------------
  const openSelfPasswordModal = () => {
    q('pwMode').value = 'self';
    q('pwUsername').value = state.me?.sub || '';
    q('pwModalTitle').textContent = 'Cambia la tua password';
    q('pwCurrentGroup').classList.remove('d-none');
    q('pwForceChangeGroup').classList.add('d-none');
    q('pwCurrent').value = '';
    q('pwNew').value = '';
    q('pwConfirm').value = '';
    q('pwError').classList.add('d-none');
    getModal('passwordModal')?.show();
  };

  const openAdminResetPasswordModal = (username) => {
    q('pwMode').value = 'admin';
    q('pwUsername').value = username;
    q('pwModalTitle').textContent = `Reset password: ${username}`;
    q('pwCurrentGroup').classList.add('d-none');
    q('pwForceChangeGroup').classList.remove('d-none');
    q('pwForceChange').checked = true;
    q('pwCurrent').value = '';
    q('pwNew').value = '';
    q('pwConfirm').value = '';
    q('pwError').classList.add('d-none');
    getModal('passwordModal')?.show();
  };

  const savePassword = async () => {
    const mode = q('pwMode').value;
    const username = q('pwUsername').value;
    const newPw = q('pwNew').value;
    const confirmPw = q('pwConfirm').value;
    const errEl = q('pwError');
    errEl.classList.add('d-none');

    if (newPw !== confirmPw) {
      errEl.textContent = 'Le password non corrispondono.';
      errEl.classList.remove('d-none');
      return;
    }
    if (newPw.length < 8) {
      errEl.textContent = 'La nuova password deve avere almeno 8 caratteri.';
      errEl.classList.remove('d-none');
      return;
    }

    try {
      if (mode === 'self') {
        const currentPw = q('pwCurrent').value;
        if (!currentPw) {
          errEl.textContent = 'Inserisci la password attuale.';
          errEl.classList.remove('d-none');
          return;
        }
        await TPL.jsonFetch('/api/users/me/password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_password: currentPw, new_password: newPw })
        });
        showMessage('Password cambiata con successo. Effettua nuovamente il login.', 'success');
        getModal('passwordModal')?.hide();
        setTimeout(() => { TPL.logout(); }, 2000);
      } else {
        const forceChange = q('pwForceChange').checked;
        await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}/reset-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ new_password: newPw, force_change: forceChange })
        });
        showMessage(`Password di ${username} reimpostata.`, 'success');
        getModal('passwordModal')?.hide();
        await loadUsersView();
      }
    } catch (error) {
      errEl.textContent = String(error);
      errEl.classList.remove('d-none');
    }
  };

  // -----------------------------------------------------------------------
  // USER ACTIONS: delete, revoke, activate
  // -----------------------------------------------------------------------
  const deleteUser = async (username) => {
    if (!username) return;
    if (username === 'admin') { showMessage('Impossibile eliminare l\'utente admin.', 'warning'); return; }
    if (!confirm(`Conferma eliminazione utente: ${username}?`)) return;

    try {
      await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
      showMessage(`Utente eliminato: ${username}`, 'success');
      await loadUsersView();
    } catch (error) {
      showMessage(`Errore: ${String(error)}`, 'danger');
    }
  };

  const revokeUser = async (username) => {
    if (!username) return;
    if (!confirm(`Disattivare l'utente ${username}?`)) return;
    try {
      await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}/revoke`, { method: 'POST' });
      showMessage(`Utente disattivato: ${username}`, 'success');
      await loadUsersView();
    } catch (error) {
      showMessage(`Errore: ${String(error)}`, 'danger');
    }
  };

  const activateUser = async (username) => {
    if (!username) return;
    try {
      await TPL.jsonFetch(`/api/users/${encodeURIComponent(username)}/activate`, { method: 'POST' });
      showMessage(`Utente riattivato: ${username}`, 'success');
      await loadUsersView();
    } catch (error) {
      showMessage(`Errore: ${String(error)}`, 'danger');
    }
  };

  // -----------------------------------------------------------------------
  // MODULES — graphical card grid
  // -----------------------------------------------------------------------
  const moduleIcon = (id) => {
    const map = {
      traefik: 'bi-hdd-network', web_gui: 'bi-window', ux_linear: 'bi-palette',
      api_base: 'bi-code-slash', api_engine_host: 'bi-cpu', auth_local: 'bi-key',
      auth_keycloak: 'bi-shield-lock', gui_template_engine: 'bi-layout-text-sidebar',
      language_engine: 'bi-translate', log_engine: 'bi-file-text',
      communication_engine: 'bi-chat-dots', security_hardening: 'bi-shield-check',
      ai_log_analysis: 'bi-robot', system_monitoring_ai: 'bi-activity',
      user_management: 'bi-people', router_manager: 'bi-signpost-split',
      template_manager: 'bi-file-earmark-richtext',
      encryption: 'bi-lock', version_manager: 'bi-git',
      resilience: 'bi-heart-pulse', self_diagnosis: 'bi-activity',
    };
    const key = (id || '').replace(/^\d+_/, '');
    return map[key] || 'bi-puzzle';
  };

  const moduleName = (id) => {
    return (id || '').replace(/^\d+_/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  };

  // -----------------------------------------------------------------------
  // MODULE CONTROL CENTER — Advanced Module Management
  // -----------------------------------------------------------------------

  let _mcModules = [];           // cached module data (enriched)
  let _mcCurrentTab = 'modules'; // active tab
  let _mcSelected = new Set();   // selected module IDs for batch ops

  /* ── Module category classification ────────────────────────── */
  const MC_CATEGORIES = {
    infra:    { label: 'Infrastruttura',  icon: 'bi-hdd-rack',      color: '#6366f1', keys: ['traefik'] },
    ui:       { label: 'Interfaccia',     icon: 'bi-window',        color: '#06b6d4', keys: ['web_gui', 'ux_linear'] },
    api:      { label: 'API & Core',      icon: 'bi-code-slash',    color: '#8b5cf6', keys: ['api_base', 'api_engine_host', 'router_manager', 'template_manager'] },
    auth:     { label: 'Autenticazione',  icon: 'bi-shield-lock',   color: '#f43f5e', keys: ['auth_local', 'auth_keycloak', 'user_management'] },
    engine:   { label: 'Engine',          icon: 'bi-gear',          color: '#0ea5e9', keys: ['language_engine', 'log_engine', 'communication_engine'] },
    security: { label: 'Sicurezza',       icon: 'bi-shield-check',  color: '#dc2626', keys: ['security_hardening', 'encryption'] },
    ai:       { label: 'Intelligenza IA', icon: 'bi-robot',         color: '#a855f7', keys: ['ai_log_analysis', 'system_monitoring_ai'] },
    ops:      { label: 'Operazioni',      icon: 'bi-tools',         color: '#059669', keys: ['version_manager', 'resilience', 'self_diagnosis'] },
  };

  const mcGetCategory = (id) => {
    const key = (id || '').replace(/^\d+_/, '');
    for (const [cat, info] of Object.entries(MC_CATEGORIES)) {
      if (info.keys.includes(key)) return { id: cat, ...info };
    }
    return { id: 'other', label: 'Altro', icon: 'bi-puzzle', color: '#94a3b8', keys: [] };
  };

  const mcGetPriority = (id) => {
    const num = parseInt((id || '').match(/^(\d+)/)?.[1] || '999', 10);
    return num;
  };

  /* ── Score Ring SVG (reused for diagnosis + resilience + version) ─── */
  const mcRenderScoreRing = (score, grade, color) => {
    const r = 54, c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(100, score));
    const offset = c - (pct / 100) * c;
    if (!color) color = score >= 90 ? '#198754' : score >= 70 ? '#0dcaf0' : score >= 50 ? '#ffc107' : '#dc3545';
    return `<div class="mc-score-ring"><svg viewBox="0 0 130 130">
      <circle cx="65" cy="65" r="${r}" fill="none" stroke="var(--ov-border)" stroke-width="10"/>
      <circle cx="65" cy="65" r="${r}" fill="none" stroke="${color}" stroke-width="10"
        stroke-dasharray="${c}" stroke-dashoffset="${offset}"
        stroke-linecap="round" transform="rotate(-90 65 65)"
        style="transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)"/>
      <text x="65" y="58" text-anchor="middle" style="fill:var(--ov-text)" font-size="28" font-weight="700">${Math.round(score)}</text>
      <text x="65" y="78" text-anchor="middle" fill="${color}" font-size="14" font-weight="600">${esc(grade)}</text>
    </svg></div>`;
  };

  /* ── Tab switching ─────────────────────────────────────────── */
  const mcSwitchTab = (tab) => {
    _mcCurrentTab = tab;
    const panelMap = {
      modules: 'mcPanelModules',
      version: 'mcPanelVersion',
      deps: 'mcPanelDeps',
      diagnosis: 'mcPanelDiagnosis',
      resilience: 'mcPanelResilience',
    };
    document.querySelectorAll('#mcTabs .ov-tab').forEach(b => b.classList.toggle('active', b.dataset.mcTab === tab));
    Object.values(panelMap).forEach(id => q(id)?.classList.add('d-none'));
    q(panelMap[tab])?.classList.remove('d-none');

    // Lazy load tab data
    if (tab === 'version') mcLoadVersion();
    if (tab === 'deps') mcLoadDeps();
    if (tab === 'diagnosis') mcLoadDiagnosis();
    if (tab === 'resilience') mcLoadResilience();
  };

  /* ── Format uptime ─────────────────────────────────────────── */
  const mcFmtUptime = (secs) => {
    if (secs == null || secs === '') return '—';
    secs = Number(secs);
    if (isNaN(secs) || secs < 0) return '—';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  const mcFmtBytes = (b) => {
    if (!b) return '0B';
    if (b < 1024) return b + 'B';
    if (b < 1048576) return (b / 1024).toFixed(1) + 'KB';
    return (b / 1048576).toFixed(1) + 'MB';
  };

  const mcFmtTimeAgo = (ts) => {
    if (!ts) return '—';
    const diff = Math.floor(Date.now() / 1000) - ts;
    if (diff < 60) return 'adesso';
    if (diff < 3600) return `${Math.floor(diff / 60)}m fa`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h fa`;
    return `${Math.floor(diff / 86400)}g fa`;
  };

  /* ── Load main modules tab ─────────────────────────────────── */
  const loadModules = async () => {
    try {
      // Parallel fetch: enriched modules + version info + bundle info + security checklist
      const [modData, verModData, verData, bundleData, secCheck] = await Promise.all([
        state.routeControl.call('modules'),
        TPL.jsonFetch('/api/version/modules').catch(e => { console.warn('version/modules:', e.message); return null; }),
        TPL.jsonFetch('/api/version/info').catch(e => { console.warn('version/info:', e.message); return null; }),
        TPL.jsonFetch('/api/modules/bundle').catch(e => { console.warn('modules/bundle:', e.message); return null; }),
        TPL.jsonFetch('/api/modules/security-checklist').catch(e => { console.warn('modules/security-checklist:', e.message); return null; }),
      ]);

      // Merge data: start from /modules/state (has desc, ver, deps now), enrich with /version/modules
      let modules = modData?.modules || [];
      const verModMap = {};
      if (verModData?.modules) {
        verModData.modules.forEach(vm => { verModMap[vm.id] = vm; });
      }

      // Enrich each module with version/modules data (engine info, hashes)
      modules = modules.map(m => {
        const vm = verModMap[m.id] || {};
        return {
          ...m,
          has_engine: vm.has_engine || false,
          engine_file: vm.engine_file || null,
          engine_hash: vm.engine_hash || null,
          installed_version: m.installed_version || vm.installed_version || '',
          available_version: m.available_version || vm.available_version || m.ver || '',
          needs_update: m.needs_update || vm.needs_update || false,
          deps: m.deps || vm.deps || [],
          desc: m.desc || vm.desc || '',
          // Computed fields
          _cat: mcGetCategory(m.id),
          _priority: mcGetPriority(m.id),
          _name: moduleName(m.id),
        };
      });

      _mcModules = modules;
      const installed = modules.filter(m => m.installed);
      const available = modules.filter(m => !m.installed);
      const needsUpdate = modules.filter(m => m.needs_update);
      const withEngine = modules.filter(m => m.has_engine);

      /* KPI stats */
      q('modTotal').textContent = modules.length;
      q('modInstalled').textContent = installed.length;
      q('modAvailable').textContent = needsUpdate.length
        ? `${available.length} + ${needsUpdate.length} upd`
        : available.length;
      const upd = modData?.updated;
      q('modUpdated').textContent = upd ? fmtDate(upd) : '—';
      q('modStatusChip').innerHTML = `<i class="bi bi-boxes"></i> ${installed.length}/${modules.length} attivi` +
        (withEngine.length ? ` · ${withEngine.length} engine` : '');

      /* KPI bars */
      const pctI = modules.length ? Math.round((installed.length / modules.length) * 100) : 0;
      const pctA = modules.length ? Math.round((available.length / modules.length) * 100) : 0;
      requestAnimationFrame(() => {
        const ib = q('modInstalledBar'); if (ib) ib.style.width = pctI + '%';
        const ab = q('modAvailableBar'); if (ab) ab.style.width = pctA + '%';
      });

      /* Platform info bar */
      if (verData) {
        const p = verData.platform || {};
        q('mcCoreVer').textContent = `v${p.version || '?'}`;
        q('mcCodename').textContent = p.codename || '—';
        q('mcEngineCount').textContent = `${verData.engines_loaded || 0} caricati`;
        q('mcUptime').textContent = mcFmtUptime(verData.uptime_seconds);
      }

      /* Bundle info enrichment */
      if (bundleData) {
        const bMode = bundleData.mode || 'legacy';
        const bSig = bundleData.signature || {};
        const bInt = bundleData.integrity || {};
        const bMeta = q('mcBundleMeta');
        if (bMeta) {
          if (bMode === 'bundle') {
            const mf = bundleData.manifest || {};
            bMeta.innerHTML = `<span class="mc-bundle-chip mc-bundle-active"><i class="bi bi-box-seam"></i> v${esc(mf.version || '?')}</span>` +
              (bSig.signed ? '<span class="mc-bundle-chip mc-bundle-signed"><i class="bi bi-shield-check"></i> Firmato</span>' : '<span class="mc-bundle-chip mc-bundle-unsigned"><i class="bi bi-shield-x"></i></span>') +
              `<span class="mc-bundle-chip mc-bundle-int-${bInt.status === 'ok' ? 'ok' : 'err'}"><i class="bi bi-fingerprint"></i> ${bInt.verified || 0}/${bInt.total || 0}</span>`;
          } else {
            bMeta.innerHTML = '<span class="mc-bundle-chip mc-bundle-legacy"><i class="bi bi-info-circle"></i> Legacy</span>';
          }
        }
      }

      /* Security checklist enrichment */
      if (secCheck) {
        const secEl = q('mcSecCheckScore');
        if (secEl) {
          secEl.textContent = `${secCheck.grade} (${secCheck.score})`;
          secEl.style.color = secCheck.score >= 80 ? '#16a34a' : secCheck.score >= 50 ? '#f59e0b' : '#dc3545';
        }
      }

      // Async platform bar enrichment (diag + security scores)
      TPL.jsonFetch('/api/diagnosis/report').then(diag => {
        q('mcHealthGrade').textContent = `${diag.grade || '?'} (${diag.score || 0})`;
        q('mcHealthGrade').style.color = (diag.score || 0) >= 70 ? '#16a34a' : (diag.score || 0) >= 40 ? '#f59e0b' : '#dc3545';
      }).catch(() => { q('mcHealthGrade').textContent = '—'; });

      TPL.jsonFetch('/api/security/score').then(sec => {
        q('mcSecScore').textContent = `${sec.grade || '?'} (${sec.score || 0})`;
        q('mcSecScore').style.color = (sec.score || 0) >= 70 ? '#16a34a' : (sec.score || 0) >= 40 ? '#f59e0b' : '#dc3545';
      }).catch(() => { q('mcSecScore').textContent = '—'; });

      /* Render module cards */
      mcRenderModuleGrid();

    } catch (error) {
      showMessage(`Modules error: ${String(error)}`, 'warning');
      q('modulesGrid').innerHTML = `<div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">Errore: ${esc(String(error))}</span></div>`;
    }
  };

  /* ── Sort modules ──────────────────────────────────────────── */
  const mcSortModules = (modules) => {
    const sortBy = q('mcModSort')?.value || 'priority';
    const sorted = [...modules];
    switch (sortBy) {
      case 'name':      sorted.sort((a, b) => a._name.localeCompare(b._name)); break;
      case 'name-desc': sorted.sort((a, b) => b._name.localeCompare(a._name)); break;
      case 'version':   sorted.sort((a, b) => (b.available_version || '').localeCompare(a.available_version || '')); break;
      case 'date':      sorted.sort((a, b) => (b.installed_at || 0) - (a.installed_at || 0)); break;
      case 'category':  sorted.sort((a, b) => a._cat.label.localeCompare(b._cat.label) || a._priority - b._priority); break;
      default:          sorted.sort((a, b) => a._priority - b._priority); break;
    }
    return sorted;
  };

  /* ── Filter modules ────────────────────────────────────────── */
  const mcFilterModules = (modules) => {
    const search = (q('mcModSearch')?.value || '').toLowerCase();
    const filter = q('mcModFilter')?.value || 'all';

    let filtered = modules;
    if (search) {
      filtered = filtered.filter(m =>
        m._name.toLowerCase().includes(search) ||
        (m.id || '').toLowerCase().includes(search) ||
        (m.desc || '').toLowerCase().includes(search) ||
        m._cat.label.toLowerCase().includes(search)
      );
    }
    if (filter === 'installed') filtered = filtered.filter(m => m.installed);
    if (filter === 'available') filtered = filtered.filter(m => !m.installed);
    if (filter === 'update')    filtered = filtered.filter(m => m.needs_update);
    if (filter === 'engine')    filtered = filtered.filter(m => m.has_engine);
    return filtered;
  };

  /* ── Render a single module card ───────────────────────────── */
  const mcRenderCard = (m) => {
    const inst = !!m.installed;
    const icon = moduleIcon(m.id);
    const update = m.needs_update;
    const deps = m.deps || [];
    const cat = m._cat;
    const selected = _mcSelected.has(m.id);

    // Version pill
    let verPill = '';
    if (update && m.installed_version && m.available_version) {
      verPill = `<span class="mc-mod-ver mc-mod-ver--upd" title="Aggiornamento disponibile">v${esc(m.installed_version)} → v${esc(m.available_version)}</span>`;
    } else if (inst && m.installed_version) {
      verPill = `<span class="mc-mod-ver mc-mod-ver--inst">v${esc(m.installed_version)}</span>`;
    } else if (m.available_version) {
      verPill = `<span class="mc-mod-ver mc-mod-ver--avail">v${esc(m.available_version)}</span>`;
    }

    // Badges
    let badges = '';
    if (inst)   badges += '<span class="mc-mod-badge mc-mod-badge--ok"><i class="bi bi-check-circle-fill"></i> Installato</span>';
    else        badges += '<span class="mc-mod-badge mc-mod-badge--cat"><i class="bi bi-circle"></i> Disponibile</span>';
    if (update) badges += '<span class="mc-mod-badge mc-mod-badge--warn"><i class="bi bi-arrow-up-circle-fill"></i> Aggiornamento</span>';
    if (m.has_engine) badges += '<span class="mc-mod-badge mc-mod-badge--dep"><i class="bi bi-gear-fill"></i> Engine</span>';
    if (deps.length) badges += `<span class="mc-mod-badge mc-mod-badge--dep"><i class="bi bi-diagram-3"></i> ${deps.length} dep</span>`;
    if (m.installed_at) badges += `<span class="mc-mod-badge mc-mod-badge--cat"><i class="bi bi-clock"></i> ${mcFmtTimeAgo(m.installed_at)}</span>`;

    // Actions
    let actions = `<input type="checkbox" class="mc-mod-check" data-mc-select="${m.id}" ${selected ? 'checked' : ''} title="Seleziona">`;
    if (inst && update) {
      actions += `<button class="btn btn-outline-warning btn-sm" type="button" data-apply-module="${m.id}" title="Aggiorna" aria-label="Aggiorna modulo ${esc(m._name)}"><i class="bi bi-arrow-up-circle"></i></button>`;
    } else if (!inst) {
      actions += `<button class="btn btn-outline-primary btn-sm" type="button" data-apply-module="${m.id}" title="Installa" aria-label="Installa modulo ${esc(m._name)}"><i class="bi bi-download"></i></button>`;
    }
    actions += `<button class="mc-mod-expand" type="button" data-mc-detail="${m.id}" title="Dettagli" aria-label="Dettagli modulo ${esc(m._name)}"><i class="bi bi-info-circle"></i></button>`;

    return `<div class="mc-mod-card${update ? ' mc-mod--update' : ''}${selected ? ' mc-mod--selected' : ''}" data-mod-id="${esc(m.id)}">
      <div class="mc-mod-left">
        <div class="ov-mod-icon ${inst ? 'mod-installed' : 'mod-available'}"><i class="bi ${icon}"></i></div>
        <span class="mc-mod-cat" style="border-color:${cat.color};color:${cat.color}">${esc(cat.label)}</span>
      </div>
      <div class="mc-mod-body">
        <div class="mc-mod-head">
          <span class="mc-mod-title" title="${esc(m.id)}">${esc(m._name)}</span>
          ${verPill}
        </div>
        <div class="mc-mod-desc mc-mod-desc--clamp" title="${esc(m.desc || '')}">${esc(m.desc || '—')}</div>
        <div class="mc-mod-badges">${badges}</div>
        ${m.engine_file ? `<div class="mc-mod-meta"><span><i class="bi bi-file-earmark-code"></i> ${esc(m.engine_file)}</span>${m.engine_hash ? `<span title="${esc(m.engine_hash)}"><i class="bi bi-fingerprint"></i> ${esc((m.engine_hash || '').substring(0,10))}…</span>` : ''}</div>` : ''}
      </div>
      <div class="mc-mod-actions">${actions}</div>
    </div>`;
  };

  /* ── Render full module grid (with optional grouping) ──────── */
  const mcRenderModuleGrid = () => {
    const filtered = mcFilterModules(_mcModules);
    const sorted = mcSortModules(filtered);
    const grouped = q('mcModGroup')?.checked;

    // Update count pill
    const pill = q('modCountPill');
    if (pill) {
      pill.textContent = `${sorted.length}/${_mcModules.length} moduli`;
      pill.className = 'ov-pill ' + (sorted.length === _mcModules.length ? 'ov-pill--info' : 'ov-pill--warning');
    }

    if (!sorted.length) {
      q('modulesGrid').innerHTML = '<div class="ov-empty"><i class="bi bi-puzzle"></i><span class="ov-empty-text">Nessun modulo corrisponde al filtro</span></div>';
      return;
    }

    let html = '';

    if (grouped) {
      // Group by category
      const groups = {};
      sorted.forEach(m => {
        const cat = m._cat.id;
        if (!groups[cat]) groups[cat] = { info: m._cat, modules: [] };
        groups[cat].modules.push(m);
      });

      Object.values(groups).forEach(g => {
        html += `<div class="mc-group-head"><i class="bi ${g.info.icon}" style="color:${g.info.color}"></i> ${esc(g.info.label)}<span class="mc-group-count">${g.modules.length} moduli</span></div>`;
        html += `<div class="ov-mod-grid">${g.modules.map(mcRenderCard).join('')}</div>`;
      });
    } else {
      html = `<div class="ov-mod-grid">${sorted.map(mcRenderCard).join('')}</div>`;
    }

    q('modulesGrid').innerHTML = html;

    // Update batch bar
    mcUpdateBatchBar();
  };

  /* ── Module selection & batch actions ──────────────────────── */
  const mcToggleSelect = (id) => {
    if (_mcSelected.has(id)) _mcSelected.delete(id);
    else _mcSelected.add(id);
    // Update card visual
    const card = document.querySelector(`[data-mod-id="${id}"]`);
    if (card) card.classList.toggle('mc-mod--selected', _mcSelected.has(id));
    const cb = document.querySelector(`[data-mc-select="${id}"]`);
    if (cb) cb.checked = _mcSelected.has(id);
    mcUpdateBatchBar();
  };

  const mcUpdateBatchBar = () => {
    const bar = q('mcBatchBar');
    if (!bar) return;
    if (_mcSelected.size > 0) {
      bar.classList.remove('d-none');
      q('mcBatchCount').textContent = _mcSelected.size;
    } else {
      bar.classList.add('d-none');
    }
  };

  const mcBatchApply = async () => {
    const ids = [..._mcSelected].filter(id => {
      const m = _mcModules.find(x => x.id === id);
      return m && (!m.installed || m.needs_update);
    });
    if (!ids.length) { showMessage('Nessun modulo da installare/aggiornare nella selezione', 'info'); return; }
    if (!confirm(`Installare/aggiornare ${ids.length} moduli?\n${ids.join(', ')}`)) return;

    try {
      for (const id of ids) {
        await applyModule(id);
      }
      _mcSelected.clear();
      showMessage(`${ids.length} moduli applicati`, 'success');
      await loadModules();
    } catch (error) {
      showMessage(`Errore batch: ${error}`, 'danger');
    }
  };

  const mcBatchClear = () => {
    _mcSelected.clear();
    document.querySelectorAll('.mc-mod--selected').forEach(el => el.classList.remove('mc-mod--selected'));
    document.querySelectorAll('.mc-mod-check').forEach(cb => cb.checked = false);
    mcUpdateBatchBar();
  };

  /* ── Module detail modal ───────────────────────────────────── */
  const mcShowDetail = (id) => {
    const m = _mcModules.find(x => x.id === id);
    if (!m) return;

    const cat = m._cat;
    const inst = !!m.installed;
    const deps = m.deps || [];

    // Build dependency list with status
    const depsHtml = deps.length ? deps.map(d => {
      const dm = _mcModules.find(x => x.id === d);
      const dInst = dm?.installed;
      return `<span class="mc-detail-dep ${dInst ? '' : 'mc-detail-dep--missing'}">
        <i class="bi ${dInst ? 'bi-check-circle' : 'bi-exclamation-triangle'}"></i> ${esc(moduleName(d))}
      </span>`;
    }).join('') : '<span class="text-muted" style="font-size:.72rem">Nessuna dipendenza</span>';

    // Reverse deps (who depends on this module)
    const reverseDeps = _mcModules.filter(x => (x.deps || []).includes(m.id));
    const rDepsHtml = reverseDeps.length ? reverseDeps.map(r =>
      `<span class="mc-detail-dep"><i class="bi bi-arrow-return-left"></i> ${esc(moduleName(r.id))}</span>`
    ).join('') : '<span class="text-muted" style="font-size:.72rem">Nessuno dipende da questo modulo</span>';

    q('mcModDetailBody').innerHTML = `
      <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
        <div class="ov-mod-icon ${inst ? 'mod-installed' : 'mod-available'}" style="width:48px;height:48px;font-size:1.4rem"><i class="bi ${moduleIcon(m.id)}"></i></div>
        <div>
          <div style="font-size:1rem;font-weight:700">${esc(m._name)}</div>
          <div style="font-size:.7rem;color:var(--ov-text-faint);font-family:monospace">${esc(m.id)}</div>
        </div>
        <span class="mc-mod-cat" style="border-color:${cat.color};color:${cat.color};margin-left:auto">${esc(cat.label)}</span>
      </div>

      <div style="font-size:.8rem;color:var(--ov-text);line-height:1.5;margin-bottom:.75rem;background:var(--ov-bg);padding:.6rem .75rem;border-radius:.4rem;border-left:3px solid ${cat.color}">
        ${esc(m.desc || 'Nessuna descrizione disponibile.')}
      </div>

      <div class="mc-detail-section">Informazioni versione</div>
      <div class="mc-detail-grid">
        <span class="mc-detail-label">Versione disponibile</span>
        <span class="mc-detail-val"><span class="mc-mod-ver mc-mod-ver--avail">v${esc(m.available_version || '?')}</span></span>
        <span class="mc-detail-label">Versione installata</span>
        <span class="mc-detail-val">${inst ? `<span class="mc-mod-ver mc-mod-ver--inst">v${esc(m.installed_version || '?')}</span>` : '<span class="text-muted" style="font-size:.72rem">Non installato</span>'}</span>
        <span class="mc-detail-label">Stato</span>
        <span class="mc-detail-val">${inst ? '<span style="color:#16a34a">● Installato</span>' : '<span style="color:#94a3b8">○ Disponibile</span>'}${m.needs_update ? ' <span style="color:#d97706">· Aggiornamento disponibile</span>' : ''}</span>
        <span class="mc-detail-label">Installato il</span>
        <span class="mc-detail-val">${m.installed_at ? fmtDate(m.installed_at) : '—'}</span>
        <span class="mc-detail-label">Priorità</span>
        <span class="mc-detail-val">${m._priority}</span>
      </div>

      ${m.has_engine ? `
      <div class="mc-detail-section">Engine</div>
      <div class="mc-detail-grid">
        <span class="mc-detail-label">File engine</span>
        <span class="mc-detail-val" style="font-family:monospace;font-size:.72rem">${esc(m.engine_file || '—')}</span>
        <span class="mc-detail-label">Hash (SHA-256)</span>
        <span class="mc-detail-val" style="font-family:monospace;font-size:.65rem;word-break:break-all">${esc(m.engine_hash || '—')}</span>
      </div>` : ''}

      <div class="mc-detail-section">Dipendenze</div>
      <div><strong style="font-size:.68rem;color:var(--ov-text-faint)">Richiede:</strong></div>
      <div class="mc-detail-deps">${depsHtml}</div>
      <div style="margin-top:.5rem"><strong style="font-size:.68rem;color:var(--ov-text-faint)">Dipendenti (reverse):</strong></div>
      <div class="mc-detail-deps">${rDepsHtml}</div>

      <div style="display:flex;gap:.5rem;margin-top:1.2rem;justify-content:flex-end">
        ${!inst ? `<button class="btn btn-primary btn-sm" type="button" data-apply-module="${esc(m.id)}"><i class="bi bi-download me-1"></i>Installa</button>` : ''}
        ${inst && m.needs_update ? `<button class="btn btn-warning btn-sm" type="button" data-apply-module="${esc(m.id)}"><i class="bi bi-arrow-up-circle me-1"></i>Aggiorna</button>` : ''}
        ${inst ? `<button class="btn btn-outline-secondary btn-sm" type="button" data-reset-module="${esc(m.id)}"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset</button>` : ''}
      </div>
    `;

    q('mcModDetailOverlay').classList.remove('d-none');
  };

  const mcCloseDetail = () => {
    q('mcModDetailOverlay')?.classList.add('d-none');
  };

  /* ── Tab: Version & Updates ────────────────────────────────── */
  const mcLoadVersion = async () => {
    try {
      const [vInfo, engines, changelog, rollbacks] = await Promise.all([
        TPL.jsonFetch('/api/version/info'),
        TPL.jsonFetch('/api/version/engines'),
        TPL.jsonFetch('/api/version/changelog').catch(() => ({ changelog: [] })),
        TPL.jsonFetch('/api/version/rollback-points').catch(() => ({ points: [] })),
      ]);

      // Version ring
      const p = vInfo.platform || {};
      q('mcVersionRing').innerHTML = `
        ${mcRenderScoreRing(100, `v${p.version || '?'}`, '#0d6efd')}
        <div style="margin-top:.5rem;font-size:.82rem;font-weight:600">${esc(p.codename || '')}</div>
        <div style="font-size:.7rem;color:var(--ov-text-faint)">Build: ${esc(p.build || '?')} • ${vInfo.engines_loaded || 0} engine</div>
        <div style="font-size:.7rem;color:var(--ov-text-faint);margin-top:.2rem">Uptime: ${mcFmtUptime(vInfo.uptime_seconds)}</div>
      `;

      // Engines list
      const engList = engines.engines || [];
      q('mcEngPill').textContent = `${engList.length} engine`;
      q('mcEnginesList').innerHTML = engList.map(e => `
        <div class="mc-eng-row">
          <div class="mc-eng-icon ${e.status === 'ok' ? 'eng-ok' : 'eng-err'}"></div>
          <span class="mc-eng-name">${esc(e.engine)}</span>
          <span class="mc-eng-lines">${e.lines || 0} righe</span>
          <span class="mc-eng-hash" title="${esc(e.hash || '')}">${esc((e.hash || '').substring(0, 12))}…</span>
        </div>
      `).join('') || '<span class="text-muted small">Nessun engine</span>';

      // Changelog
      const entries = changelog.changelog || [];
      q('mcChangelog').innerHTML = entries.length ? entries.slice(-20).reverse().map(e => `
        <div class="mc-changelog-item">
          <span class="mc-cl-time">${fmtDate(e.ts)}</span>
          <span class="mc-cl-action">${esc(e.action || e.type || '?')}</span>
          ${e.detail ? ` — <span style="color:var(--ov-text-faint)">${esc(typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail))}</span>` : ''}
        </div>
      `).join('') : '<span class="text-muted small">Nessuna voce</span>';

      // Rollbacks
      const rbs = rollbacks.points || [];
      q('mcRbPill').textContent = `${rbs.length}`;
      q('mcRollbackList').innerHTML = rbs.length ? rbs.map(rb => `
        <div class="mc-rb-item">
          <i class="bi bi-arrow-counterclockwise text-primary"></i>
          <span style="flex:1">${fmtDate(rb.created) || esc(rb.name || rb.id)}</span>
          <span style="color:var(--ov-text-faint);font-size:.7rem">${rb.state_files || 0} file</span>
          <button class="btn btn-outline-warning btn-sm" type="button" data-mc-rollback="${esc(rb.name || rb.id)}" title="Ripristina" aria-label="Ripristina punto ${esc(rb.name || rb.id)}"><i class="bi bi-arrow-counterclockwise"></i></button>
        </div>
      `).join('') : '<span class="text-muted small">Nessun punto di ripristino</span>';

    } catch (error) {
      q('mcVersionRing').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Tab: Dependencies ─────────────────────────────────────── */
  const mcLoadDeps = async () => {
    try {
      const data = await TPL.jsonFetch('/api/version/dependencies');
      const graph = data.graph || {};
      const issues = data.issues || [];
      const missing = issues.filter(i => i.type === 'missing_dependency').map(i => i.module || i.missing || i.dependency || '?');
      const orphans = issues.filter(i => i.type === 'orphan_engine').map(i => i.engine || '?');

      const keys = Object.keys(graph).sort();
      q('mcDepPill').textContent = `${keys.length} moduli`;

      // Render dependency chains
      let chainsHtml = '';
      keys.forEach(modId => {
        const info = graph[modId];
        const deps = info.deps || [];
        const inst = info.installed;
        chainsHtml += `<div class="mc-dep-chain">
          <span class="mc-dep-node ${inst ? 'dep-installed' : ''}" title="${esc(modId)}">
            <i class="bi ${moduleIcon(modId)}"></i> ${esc(moduleName(modId))}
            <span style="font-size:.58rem;color:var(--ov-text-faint)">v${esc(info.version || '?')}</span>
          </span>`;
        if (deps.length) {
          chainsHtml += '<span class="mc-dep-arrow"><i class="bi bi-arrow-left"></i></span>';
          deps.forEach(d => {
            const depInfo = graph[d] || {};
            const depInst = depInfo.installed;
            chainsHtml += `<span class="mc-dep-node ${depInst ? 'dep-installed' : 'dep-missing'}" title="${esc(d)}">${esc(moduleName(d))}</span>`;
          });
        }
        chainsHtml += '</div>';
      });
      q('mcDepsGraph').innerHTML = chainsHtml || '<span class="text-muted small">Nessuna dipendenza</span>';

      // Missing
      q('mcMissingDeps').innerHTML = missing.length ?
        missing.map(d => `<div class="mc-drift-item"><i class="bi bi-exclamation-triangle text-warning"></i><span>${esc(d)}</span></div>`).join('')
        : '<span class="text-muted small">Nessuna dipendenza mancante</span>';

      // Orphans
      q('mcOrphanEngines').innerHTML = orphans.length ?
        orphans.map(o => `<div class="mc-drift-item"><i class="bi bi-puzzle text-info"></i><span>${esc(o)}</span></div>`).join('')
        : '<span class="text-muted small">Nessun engine orfano</span>';

    } catch (error) {
      q('mcDepsGraph').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Tab: Diagnosis ────────────────────────────────────────── */
  const mcLoadDiagnosis = async () => {
    try {
      const [report, engines, drift] = await Promise.all([
        TPL.jsonFetch('/api/diagnosis/report'),
        TPL.jsonFetch('/api/diagnosis/engines'),
        TPL.jsonFetch('/api/diagnosis/config-drift'),
      ]);

      // Score ring
      q('mcDiagRing').innerHTML = mcRenderScoreRing(report.score || 0, report.grade || '?')
        + `<div style="margin-top:.5rem;font-size:.78rem;color:var(--ov-text-faint)">
          ${esc((report.status || '').replace(/_/g, ' '))}
          </div>`;

      // Recommendations
      const recs = report.recommendations || [];
      q('mcRecsPill').textContent = `${recs.length}`;
      q('mcRecommendations').innerHTML = recs.length ? recs.map(r => `
        <div class="mc-rec-item">
          <div class="mc-rec-prio prio-${esc(r.priority)}"></div>
          <div class="mc-rec-body">
            <div class="mc-rec-title">${esc(r.title)}</div>
            <div class="mc-rec-desc">${esc(r.description)}</div>
            ${r.action ? `<button class="btn btn-outline-primary btn-sm mt-1" type="button" data-mc-remed="${esc(r.action)}" style="font-size:.65rem"><i class="bi bi-wrench"></i> Fix</button>` : ''}
          </div>
        </div>
      `).join('') : '<span class="text-muted small">Nessuna raccomandazione</span>';

      // Root causes
      const causes = report.root_causes || [];
      q('mcRootCausePill').textContent = `${causes.length}`;
      q('mcRootCauses').innerHTML = causes.length ? causes.map(c => `
        <div class="mc-cause-item cause-${esc(c.severity)}">
          <div class="mc-cause-title"><i class="bi bi-exclamation-circle me-1"></i>${esc(c.description)}</div>
          <div class="mc-cause-desc">${esc(c.detail || '')} — ${esc(c.recommendation || '')}</div>
        </div>
      `).join('') : '<span class="text-muted small">Nessuna causa trovata — sistema stabile</span>';

      // Engine health
      const engList = engines.engines || [];
      q('mcEngHealthPill').textContent = `${engines.healthy || 0}/${engines.total || 0}`;
      q('mcEngineHealth').innerHTML = engList.map(e => `
        <div class="mc-health-item">
          <div class="mc-health-dot ${e.status === 'ok' ? 'h-ok' : 'h-err'}"></div>
          <span style="flex:1;font-weight:500">${esc(e.engine)}</span>
          <span style="color:var(--ov-text-faint);font-size:.7rem">${e.lines || 0} righe</span>
          <span style="font-size:.68rem;${e.status === 'ok' ? 'color:#16a34a' : 'color:#dc3545'}">${esc(e.status)}</span>
        </div>
      `).join('');

      // Config drift
      const drifts = drift.drifts || [];
      q('mcConfigDrift').innerHTML = drifts.length ? drifts.map(d => `
        <div class="mc-drift-item">
          <span class="mc-drift-type" style="color:${d.type.includes('removed') ? '#dc3545' : d.type.includes('added') ? '#16a34a' : '#f59e0b'}">
            <i class="bi bi-${d.type.includes('removed') ? 'dash-circle' : d.type.includes('added') ? 'plus-circle' : 'pencil-square'}"></i>
            ${esc(d.type.replace(/_/g, ' '))}
          </span>
          <span>${esc(d.file || d.var || '?')}</span>
          ${d.from ? `<span style="color:var(--ov-text-faint);font-size:.65rem">${esc(d.from)} → ${esc(d.to)}</span>` : ''}
        </div>
      `).join('') : `<span class="text-muted small">${drift.status === 'baseline_created' ? 'Baseline creata — nessun drift rilevato' : 'Nessun drift rilevato'}</span>`;

    } catch (error) {
      q('mcDiagRing').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Tab: Resilience ───────────────────────────────────────── */
  const mcLoadResilience = async () => {
    try {
      const [status, resources, health, backups] = await Promise.all([
        TPL.jsonFetch('/api/resilience/status'),
        TPL.jsonFetch('/api/resilience/resources'),
        TPL.jsonFetch('/api/resilience/health'),
        TPL.jsonFetch('/api/resilience/backups').catch(() => ({ backups: [] })),
      ]);

      // Resilience ring
      q('mcResRing').innerHTML = mcRenderScoreRing(status.score || 0, status.grade || '?')
        + `<div style="margin-top:.5rem;font-size:.72rem;color:var(--ov-text-faint)">
          ${(status.issues || []).map(i => `<div>${esc(i)}</div>`).join('') || 'Nessun problema'}
          </div>`;

      // Resources
      const res = resources;
      q('mcResPill').textContent = `${Object.keys(res).filter(k => k !== 'collected_at').length} metriche`;
      const resItems = [
        { label: 'CPU', val: `${(res.cpu?.usage_pct ?? 0).toFixed(1)}%`, pct: res.cpu?.usage_pct ?? 0, color: (res.cpu?.usage_pct ?? 0) > 80 ? '#dc3545' : '#0d6efd' },
        { label: 'Memoria', val: `${(res.memory?.usage_pct ?? 0).toFixed(1)}%`, pct: res.memory?.usage_pct ?? 0, color: (res.memory?.usage_pct ?? 0) > 85 ? '#dc3545' : '#198754' },
        { label: 'Disco', val: `${(res.disk?.usage_pct ?? 0).toFixed(1)}%`, pct: res.disk?.usage_pct ?? 0, color: (res.disk?.usage_pct ?? 0) > 90 ? '#dc3545' : '#0dcaf0' },
        { label: 'Load (1m)', val: `${(res.load_avg?.["1min"] ?? 0).toFixed(2)}`, pct: Math.min(100, ((res.load_avg?.["1min"] ?? 0) / (res.cpu?.cores ?? 1)) * 100), color: '#6f42c1' },
      ];
      q('mcResources').innerHTML = `<div class="mc-res-grid">${resItems.map(r => `
        <div class="mc-res-item">
          <div class="mc-res-label">${r.label}</div>
          <div class="mc-res-val" style="color:${r.color}">${r.val}</div>
          <div class="mc-res-track"><div class="mc-res-fill" style="width:${Math.min(100, r.pct)}%;background:${r.color}"></div></div>
        </div>
      `).join('')}</div>`;

      // Backups
      const bks = backups.backups || [];
      q('mcBackupsList').innerHTML = bks.length ? bks.map(b => `
        <div class="mc-bk-item">
          <i class="bi bi-archive text-primary"></i>
          <span class="mc-bk-time">${fmtDate(b.created || b.timestamp)}</span>
          <span class="mc-bk-size">${mcFmtBytes(b.total_size || b.size || 0)}</span>
          <button class="btn btn-outline-warning btn-sm" type="button" data-mc-restore="${esc(b.name || b.id || b.file)}" title="Ripristina" aria-label="Ripristina backup"><i class="bi bi-arrow-counterclockwise"></i></button>
        </div>
      `).join('') : '<span class="text-muted small">Nessun backup</span>';

      // Health detail
      const engines = health.engines || [];
      const fileHealth = health.state_files || [];
      q('mcHealthPill').textContent = `${engines.length + fileHealth.length}`;
      let healthHtml = '';
      engines.forEach(e => {
        healthHtml += `<div class="mc-health-item">
          <div class="mc-health-dot ${e.healthy ? 'h-ok' : 'h-err'}"></div>
          <span style="flex:1">${esc(e.engine)}</span>
          <span style="font-size:.68rem;color:var(--ov-text-faint)">${esc(e.marker)}</span>
        </div>`;
      });
      if (fileHealth.length) {
        healthHtml += '<div style="font-weight:600;font-size:.72rem;margin-top:.5rem;padding:.3rem .5rem">State Files</div>';
        fileHealth.forEach(f => {
          healthHtml += `<div class="mc-health-item">
            <div class="mc-health-dot ${(f.exists && !f.corrupted) ? 'h-ok' : f.exists ? 'h-warn' : 'h-err'}"></div>
            <span style="flex:1">${esc(f.file || f.name || '?')}</span>
            <span style="font-size:.68rem;color:var(--ov-text-faint)">${mcFmtBytes(f.size_bytes || f.size || 0)}</span>
          </div>`;
        });
      }
      q('mcHealthDetail').innerHTML = healthHtml || '<span class="text-muted small">Nessun dato</span>';

    } catch (error) {
      q('mcResRing').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── OTA check ─────────────────────────────────────────────── */
  const mcOtaCheck = async () => {
    q('mcOtaResult').innerHTML = '<span class="text-muted small"><i class="bi bi-hourglass-split"></i> Controllo in corso…</span>';
    try {
      const data = await TPL.jsonFetch('/api/version/check-updates', { method: 'POST' });
      const tags = data.remote_tags || data.tags || [];
      if (tags.length) {
        q('mcOtaResult').innerHTML = `<div class="alert alert-warning py-1 px-2 mb-0" style="font-size:.78rem">
          <i class="bi bi-arrow-up-circle"></i> ${tags.length} aggiornamenti disponibili: ${tags.map(t => `<strong>${esc(t)}</strong>`).join(', ')}
          <button class="btn btn-warning btn-sm ms-2" id="mcOtaApplyBtn" type="button"><i class="bi bi-cloud-download"></i> Applica OTA</button>
        </div>`;
        q('mcOtaApplyBtn')?.addEventListener('click', mcOtaApply);
      } else {
        q('mcOtaResult').innerHTML = '<span class="text-success small"><i class="bi bi-check-circle"></i> Piattaforma aggiornata</span>';
      }
    } catch (error) {
      q('mcOtaResult').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  const mcOtaApply = async () => {
    if (!confirm('Confermi aggiornamento OTA? Verrà creato un rollback point automatico.')) return;
    try {
      const data = await TPL.jsonFetch('/api/version/update/ota', { method: 'POST' });
      showMessage('Aggiornamento OTA completato. Riavviare il container per applicare.', 'success');
      q('mcOtaResult').innerHTML = `<span class="text-success small"><i class="bi bi-check-circle"></i> OTA completato</span>`;
    } catch (error) {
      showMessage(`OTA fallito: ${error}`, 'danger');
    }
  };

  /* ── Local upload ──────────────────────────────────────────── */
  const mcLocalUpload = async () => {
    const fileInput = q('mcLocalFile');
    if (!fileInput?.files?.length) { showMessage('Seleziona un file .sh', 'warning'); return; }
    const file = fileInput.files[0];
    if (!file.name.endsWith('.sh')) { showMessage('Solo file .sh', 'warning'); return; }

    const formData = new FormData();
    formData.append('file', file);

    try {
      const resp = await fetch('/api/version/update/local', {
        method: 'POST',
        headers: { ...TPL.authHeader() },
        body: formData,
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Upload failed');
      q('mcLocalResult').innerHTML = `<span class="text-success small"><i class="bi bi-check-circle"></i> ${esc(data.message || 'Modulo caricato')}</span>`;
      showMessage(`Modulo ${file.name} caricato`, 'success');
    } catch (error) {
      q('mcLocalResult').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Remediation action ────────────────────────────────────── */
  const mcRemediate = async (action) => {
    if (!confirm(`Eseguire remediation: ${action}?`)) return;
    try {
      const data = await TPL.jsonFetch(`/api/diagnosis/remediate?action=${encodeURIComponent(action)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      q('mcRemedResult').innerHTML = `<span class="text-success small"><i class="bi bi-check-circle"></i> ${esc(action)}: completato</span>`;
      showMessage(`Remediation "${action}" completata`, 'success');
      // Reload diagnosis tab
      if (_mcCurrentTab === 'diagnosis') setTimeout(mcLoadDiagnosis, 500);
    } catch (error) {
      q('mcRemedResult').innerHTML = `<span class="text-danger small">${esc(String(error))}</span>`;
    }
  };

  /* ── Backup create ─────────────────────────────────────────── */
  const mcCreateBackup = async () => {
    try {
      showMessage('Creazione backup in corso…', 'info');
      await TPL.jsonFetch('/api/resilience/backup', { method: 'POST' });
      showMessage('Backup creato con successo', 'success');
      if (_mcCurrentTab === 'resilience') setTimeout(mcLoadResilience, 500);
    } catch (error) {
      showMessage(`Backup fallito: ${error}`, 'danger');
    }
  };

  /* ── Restore from backup ───────────────────────────────────── */
  const mcRestore = async (name) => {
    if (!confirm(`Ripristinare dal backup "${name}"? Verrà creato un backup pre-ripristino.`)) return;
    try {
      await TPL.jsonFetch('/api/resilience/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backup_name: name }),
      });
      showMessage('Ripristino completato', 'success');
      if (_mcCurrentTab === 'resilience') setTimeout(mcLoadResilience, 500);
    } catch (error) {
      showMessage(`Ripristino fallito: ${error}`, 'danger');
    }
  };

  /* ── Rollback ──────────────────────────────────────────────── */
  const mcRollback = async (pointId) => {
    if (!confirm(`Ripristinare al punto "${pointId}"?`)) return;
    try {
      await TPL.jsonFetch('/api/version/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ point: pointId, confirm: true }),
      });
      showMessage('Rollback completato', 'success');
      if (_mcCurrentTab === 'version') setTimeout(mcLoadVersion, 500);
    } catch (error) {
      showMessage(`Rollback fallito: ${error}`, 'danger');
    }
  };

  // -----------------------------------------------------------------------
  // SECURITY — Full Security Center
  // -----------------------------------------------------------------------
  const secSeverityMeta = (sev) => {
    const map = {
      critical: { icon: 'bi-exclamation-triangle-fill', cls: 'tl-danger', badge: 'danger', label: 'Critico', color: '#dc3545' },
      high:     { icon: 'bi-shield-exclamation', cls: 'tl-warning', badge: 'warning', label: 'Alto', color: '#fd7e14' },
      medium:   { icon: 'bi-exclamation-circle', cls: 'tl-info', badge: 'info', label: 'Medio', color: '#0dcaf0' },
      low:      { icon: 'bi-info-circle', cls: 'tl-muted', badge: 'muted', label: 'Basso', color: '#6c757d' },
    };
    return map[(sev || '').toLowerCase()] || map.low;
  };

  const secThreatLevelMeta = (level) => {
    const m = {
      critical: { label: 'CRITICO', color: '#dc3545', pct: 95 },
      high:     { label: 'ALTO', color: '#fd7e14', pct: 75 },
      elevated: { label: 'ELEVATO', color: '#ffc107', pct: 55 },
      guarded:  { label: 'MODERATO', color: '#0dcaf0', pct: 35 },
      low:      { label: 'BASSO', color: '#198754', pct: 10 },
    };
    return m[(level || '').toLowerCase()] || m.low;
  };

  /* ── SVG: Score Ring ─────────────────────────────────────────────────── */
  const secRenderScoreRing = (score, grade) => {
    const r = 54, c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(100, score));
    const offset = c - (pct / 100) * c;
    const color = score >= 90 ? '#198754' : score >= 70 ? '#0dcaf0' : score >= 50 ? '#ffc107' : '#dc3545';
    return `<svg viewBox="0 0 130 130" class="sec-score-svg">
      <circle cx="65" cy="65" r="${r}" fill="none" stroke="var(--ov-border)" stroke-width="10"/>
      <circle cx="65" cy="65" r="${r}" fill="none" stroke="${color}" stroke-width="10"
        stroke-dasharray="${c}" stroke-dashoffset="${offset}"
        stroke-linecap="round" transform="rotate(-90 65 65)"
        style="transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)"/>
      <text x="65" y="58" text-anchor="middle" style="fill:var(--ov-text)" font-size="28" font-weight="700">${Math.round(score)}</text>
      <text x="65" y="78" text-anchor="middle" fill="${color}" font-size="14" font-weight="600">${esc(grade)}</text>
    </svg>`;
  };

  /* ── SVG: Threat Gauge ───────────────────────────────────────────────── */
  const secRenderThreatGauge = (level) => {
    const m = secThreatLevelMeta(level);
    const angle = -90 + (m.pct / 100) * 180; // -90 to 90 degrees
    return `<svg viewBox="0 0 200 110" class="sec-gauge-svg">
      <defs>
        <linearGradient id="secGaugeGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#198754"/>
          <stop offset="30%" stop-color="#0dcaf0"/>
          <stop offset="55%" stop-color="#ffc107"/>
          <stop offset="75%" stop-color="#fd7e14"/>
          <stop offset="100%" stop-color="#dc3545"/>
        </linearGradient>
      </defs>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--ov-border)" stroke-width="14" stroke-linecap="round"/>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#secGaugeGrad)" stroke-width="14" stroke-linecap="round"
        stroke-dasharray="${Math.PI * 80}" stroke-dashoffset="${Math.PI * 80 * (1 - m.pct / 100)}"
        style="transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)"/>
      <line x1="100" y1="100" x2="${100 + 55 * Math.cos(angle * Math.PI / 180)}" y2="${100 + 55 * Math.sin(angle * Math.PI / 180)}"
        stroke="${m.color}" stroke-width="3" stroke-linecap="round"
        style="transition:all .6s cubic-bezier(.4,0,.2,1)"/>
      <circle cx="100" cy="100" r="5" fill="${m.color}"/>
    </svg>`;
  };

  /* ── SVG: Threat Timeline Bar Chart ──────────────────────────────────── */
  const secRenderTimelineChart = (timeline) => {
    if (!timeline || !timeline.length) return '<div class="ov-empty"><i class="bi bi-graph-up"></i><span class="ov-empty-text">Nessun dato timeline</span></div>';
    const maxVal = Math.max(1, ...timeline.map(t => t.total));
    const barW = Math.max(6, Math.min(20, 600 / timeline.length - 2));
    const h = 140, pad = 25;
    const totalW = timeline.length * (barW + 2) + pad * 2;

    let bars = '';
    timeline.forEach((t, i) => {
      const x = pad + i * (barW + 2);
      const bh = (t.total / maxVal) * (h - 30);
      const y = h - 10 - bh;
      const crit = (t.critical / maxVal) * (h - 30);
      const high = (t.high / maxVal) * (h - 30);
      const hour = new Date(t.ts * 1000).getHours();

      // Stack: low(grey), medium(blue), high(orange), critical(red)
      bars += `<rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="2" fill="rgba(108,117,125,.3)"/>`;
      if (t.critical > 0) bars += `<rect x="${x}" y="${y}" width="${barW}" height="${crit}" rx="2" fill="#dc3545" opacity=".85"/>`;
      else if (t.high > 0) bars += `<rect x="${x}" y="${y}" width="${barW}" height="${high}" rx="2" fill="#fd7e14" opacity=".85"/>`;

      if (i % 4 === 0) {
        bars += `<text x="${x + barW/2}" y="${h}" text-anchor="middle" fill="var(--ov-text-muted)" font-size="8">${hour}h</text>`;
      }
    });

    return `<svg viewBox="0 0 ${totalW} ${h}" class="sec-timeline-svg" preserveAspectRatio="xMidYEnd meet">${bars}</svg>`;
  };

  /* ── WAF Rules Panel ─────────────────────────────────────────────────── */
  const secRenderWafRules = (waf) => {
    const rules = waf?.rules || [];
    if (!rules.length) return '<div class="ov-empty"><i class="bi bi-shield"></i><span class="ov-empty-text">Nessuna regola attiva</span></div>';

    return `<div class="sec-rules-grid">${rules.map(r => {
      const iconMap = { xss: 'bi-code-slash', sqli: 'bi-database-exclamation', traversal: 'bi-folder-minus',
                        cmdi: 'bi-terminal', ssrf: 'bi-globe2', xxe: 'bi-filetype-xml',
                        suspicious_ua: 'bi-robot', honeypot: 'bi-flower1' };
      const icon = iconMap[r.type] || 'bi-shield';
      const statusCls = r.status === 'active' ? 'sec-rule--active' : 'sec-rule--inactive';
      return `<div class="sec-rule ${statusCls}">
        <div class="sec-rule-icon"><i class="bi ${icon}"></i></div>
        <div class="sec-rule-info">
          <div class="sec-rule-type">${esc(r.type.toUpperCase().replace(/_/g, ' '))}</div>
          <div class="sec-rule-count">${r.count} pattern${r.count !== 1 ? 's' : ''}</div>
        </div>
        <div class="sec-rule-status"><i class="bi bi-circle-fill"></i> ${esc(r.status)}</div>
      </div>`;
    }).join('')}</div>`;
  };

  /* ── WAF Stats Panel ─────────────────────────────────────────────────── */
  const secRenderWafStats = (waf, status) => {
    const stats = [
      { label: 'XSS Bloccati', value: waf?.xss_blocked ?? 0, icon: 'bi-code-slash', color: '#dc3545' },
      { label: 'SQLi Bloccati', value: waf?.sqli_blocked ?? 0, icon: 'bi-database-exclamation', color: '#fd7e14' },
      { label: 'Path Traversal', value: waf?.traversal_blocked ?? 0, icon: 'bi-folder-minus', color: '#ffc107' },
      { label: 'Honeypot Hit', value: waf?.honeypot_hits ?? 0, icon: 'bi-flower1', color: '#0dcaf0' },
      { label: 'Totale Bloccati', value: waf?.total_blocked ?? 0, icon: 'bi-bricks', color: '#6c757d' },
    ];
    const maxVal = Math.max(1, ...stats.map(s => s.value));

    return `<div class="sec-waf-stats">${stats.map(s => {
      const pct = Math.min(100, (s.value / maxVal) * 100);
      return `<div class="sec-waf-stat">
        <div class="sec-waf-stat-head">
          <span class="sec-waf-stat-icon" style="color:${s.color}"><i class="bi ${s.icon}"></i></span>
          <span class="sec-waf-stat-label">${s.label}</span>
          <span class="sec-waf-stat-val">${s.value}</span>
        </div>
        <div class="sec-waf-stat-track"><div class="sec-waf-stat-fill" style="width:${pct}%;background:${s.color}"></div></div>
      </div>`;
    }).join('')}</div>`;
  };

  /* ── Categories Donut ────────────────────────────────────────────────── */
  const secRenderCategories = (categories) => {
    if (!categories || !Object.keys(categories).length) {
      return '<div class="ov-empty"><i class="bi bi-pie-chart"></i><span class="ov-empty-text">Nessuna categoria</span></div>';
    }
    const entries = Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const total = entries.reduce((s, e) => s + e[1], 0);
    const colors = ['#dc3545', '#fd7e14', '#ffc107', '#0dcaf0', '#198754', '#6f42c1', '#d63384', '#6c757d'];
    const r = 50, cx = 65, cy = 65, c = 2 * Math.PI * r;

    let offset = 0;
    let arcs = '';
    let legend = '';
    entries.forEach(([cat, count], i) => {
      const pct = count / total;
      const dashLen = pct * c;
      const color = colors[i % colors.length];
      arcs += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="16"
        stroke-dasharray="${dashLen} ${c - dashLen}" stroke-dashoffset="${-offset}"
        transform="rotate(-90 ${cx} ${cy})" opacity=".85"/>`;
      offset += dashLen;

      const catLabel = cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      legend += `<div class="sec-cat-item">
        <span class="sec-cat-dot" style="background:${color}"></span>
        <span class="sec-cat-name">${esc(catLabel)}</span>
        <span class="sec-cat-count">${count}</span>
      </div>`;
    });

    return `<div class="sec-cat-wrap">
      <svg viewBox="0 0 130 130" class="sec-cat-donut">${arcs}
        <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="var(--ov-text)" font-size="18" font-weight="700">${total}</text>
        <text x="${cx}" y="${cy + 12}" text-anchor="middle" fill="var(--ov-text-sec)" font-size="9">totale</text>
      </svg>
      <div class="sec-cat-legend">${legend}</div>
    </div>`;
  };

  /* ── Blocked IPs Panel ───────────────────────────────────────────────── */
  /* ── Rate Limiting Panel ─────────────────────────────────────────────── */
  const secRenderRateLimit = (fw) => {
    const rl = fw?.rate_limit || {};
    const bf = fw?.brute_force || {};

    return `<div class="sec-rate-grid">
      <div class="sec-rate-card">
        <div class="sec-rate-title"><i class="bi bi-speedometer me-1"></i> Rate Limit</div>
        <div class="sec-rate-row"><span>Finestra</span><span class="sec-rate-val">${rl.window || 60}s</span></div>
        <div class="sec-rate-row"><span>Max Richieste</span><span class="sec-rate-val">${rl.max || 200}/win</span></div>
        <div class="sec-rate-row"><span>Stato</span><span class="ov-badge ov-badge--success">Attivo</span></div>
      </div>
      <div class="sec-rate-card">
        <div class="sec-rate-title"><i class="bi bi-person-slash me-1"></i> Brute-Force</div>
        <div class="sec-rate-row"><span>Finestra</span><span class="sec-rate-val">${bf.window || 300}s</span></div>
        <div class="sec-rate-row"><span>Max Tentativi</span><span class="sec-rate-val">${bf.max || 15}/win</span></div>
        <div class="sec-rate-row"><span>Escalation</span><span class="ov-badge ov-badge--info">5m → 15m → 1h</span></div>
      </div>
    </div>`;
  };

  /* ── File Integrity Panel ────────────────────────────────────────────── */
  const secRenderIntegrity = (intg) => {
    if (!intg) return '<div class="ov-empty"><i class="bi bi-question-circle"></i><span class="ov-empty-text">Dati integrità non disponibili</span></div>';

    const statusMap = {
      ok: { icon: 'bi-check-circle-fill', color: '#198754', label: 'Integrità confermata' },
      baseline_set: { icon: 'bi-check-circle-fill', color: '#0dcaf0', label: 'Baseline impostata' },
      changed: { icon: 'bi-exclamation-circle-fill', color: '#ffc107', label: 'File aggiunti rilevati' },
      tampered: { icon: 'bi-x-circle-fill', color: '#dc3545', label: 'MANOMISSIONE RILEVATA' },
    };
    const s = statusMap[intg.status] || statusMap.ok;
    const ts = intg.timestamp ? new Date(intg.timestamp * 1000).toLocaleString('it-IT') : '—';

    let html = `<div class="sec-intg-status" style="--intg-color:${s.color}">
      <div class="sec-intg-icon"><i class="bi ${s.icon}"></i></div>
      <div class="sec-intg-info">
        <div class="sec-intg-label">${s.label}</div>
        <div class="sec-intg-meta">${intg.files_checked} file monitorati · Ultimo check: ${ts}</div>
      </div>
    </div>`;

    if (intg.modified?.length) {
      html += `<div class="sec-intg-list sec-intg-list--danger"><div class="sec-intg-list-title"><i class="bi bi-exclamation-triangle me-1"></i> File Modificati (${intg.modified.length})</div>`;
      intg.modified.forEach(f => { html += `<div class="sec-intg-file"><i class="bi bi-file-earmark-x me-1"></i>${esc(f.split('/').pop())}</div>`; });
      html += '</div>';
    }
    if (intg.added?.length) {
      html += `<div class="sec-intg-list sec-intg-list--warn"><div class="sec-intg-list-title"><i class="bi bi-plus-circle me-1"></i> File Aggiunti (${intg.added.length})</div>`;
      intg.added.forEach(f => { html += `<div class="sec-intg-file"><i class="bi bi-file-earmark-plus me-1"></i>${esc(f.split('/').pop())}</div>`; });
      html += '</div>';
    }
    if (intg.removed?.length) {
      html += `<div class="sec-intg-list sec-intg-list--danger"><div class="sec-intg-list-title"><i class="bi bi-trash me-1"></i> File Rimossi (${intg.removed.length})</div>`;
      intg.removed.forEach(f => { html += `<div class="sec-intg-file"><i class="bi bi-file-earmark-minus me-1"></i>${esc(f.split('/').pop())}</div>`; });
      html += '</div>';
    }

    html += `<div class="sec-intg-actions"><button class="sec-action-btn sec-action-btn--sm" id="secResetBaseline"><i class="bi bi-arrow-clockwise me-1"></i>Reset Baseline</button></div>`;
    return html;
  };

  /* ── Crypto Status Panel ─────────────────────────────────────────────── */
  const secRenderCryptoStatus = (crypto, bench) => {
    if (!crypto) return '<div class="ov-empty"><i class="bi bi-key"></i><span class="ov-empty-text">Engine crittografia non disponibile</span></div>';

    const st = crypto.stats || {};
    const algs = crypto.algorithms || {};
    const keys = crypto.keys || {};

    const opsGrid = [
      { label: 'Cifrature', val: st.encryptions || 0, icon: 'bi-lock-fill', color: '#198754' },
      { label: 'Decifrature', val: st.decryptions || 0, icon: 'bi-unlock-fill', color: '#0dcaf0' },
      { label: 'Firme', val: st.signatures || 0, icon: 'bi-pen-fill', color: '#6f42c1' },
      { label: 'Verifiche', val: st.verifications || 0, icon: 'bi-check2-circle', color: '#fd7e14' },
      { label: 'Hash', val: st.checksums || 0, icon: 'bi-hash', color: '#d63384' },
      { label: 'Token Gen', val: st.tokens_generated || 0, icon: 'bi-key', color: '#ffc107' },
      { label: 'Sigilli', val: st.seals_created || 0, icon: 'bi-shield-lock', color: '#20c997' },
      { label: 'Errori', val: st.errors || 0, icon: 'bi-x-circle', color: '#dc3545' },
    ];

    let html = `<div class="sec-crypto-summary">
      <div class="sec-crypto-total"><span class="sec-crypto-big">${st.total_ops || 0}</span><span class="sec-crypto-lbl">Operazioni Totali</span></div>
      <div class="sec-crypto-keys"><span class="sec-crypto-big">${keys.active || 1}</span><span class="sec-crypto-lbl">Chiavi Attive</span></div>
      <div class="sec-crypto-rot"><span class="sec-crypto-big">${keys.rotated || 0}</span><span class="sec-crypto-lbl">Rotazioni</span></div>
    </div>`;

    html += `<div class="sec-crypto-ops-grid">${opsGrid.map(o =>
      `<div class="sec-crypto-op"><i class="bi ${o.icon}" style="color:${o.color}"></i><span class="sec-crypto-op-val">${o.val}</span><span class="sec-crypto-op-lbl">${o.label}</span></div>`
    ).join('')}</div>`;

    if (bench) {
      html += `<div class="sec-crypto-bench">
        <div class="sec-crypto-bench-title"><i class="bi bi-lightning-fill me-1"></i> Benchmark</div>
        <div class="sec-crypto-bench-row"><span>Encrypt 1KB</span><span>${bench.encrypt_1kb_ms ?? '—'} ms</span></div>
        <div class="sec-crypto-bench-row"><span>Decrypt 1KB</span><span>${bench.decrypt_1kb_ms ?? '—'} ms</span></div>
        <div class="sec-crypto-bench-row"><span>SHA-256 1KB</span><span>${bench.sha256_1kb_us ?? '—'} µs</span></div>
        <div class="sec-crypto-bench-row"><span>Throughput</span><span>${bench.encrypt_throughput_mbps ?? '—'} MB/s</span></div>
      </div>`;
    }

    return html;
  };

  /* ── Crypto Tools Panel ──────────────────────────────────────────────── */
  const secRenderCryptoTools = () => {
    return `<div class="sec-crypto-tools">
      <div class="sec-crypto-alg-list">
        <div class="sec-crypto-alg"><i class="bi bi-lock-fill me-1" style="color:#198754"></i> AES-256-GCM <span class="ov-badge ov-badge--success">Attivo</span></div>
        <div class="sec-crypto-alg"><i class="bi bi-pen-fill me-1" style="color:#6f42c1"></i> HMAC-SHA256/512 <span class="ov-badge ov-badge--success">Attivo</span></div>
        <div class="sec-crypto-alg"><i class="bi bi-hash me-1" style="color:#d63384"></i> SHA-256 / SHA-512 / BLAKE2b <span class="ov-badge ov-badge--success">Attivo</span></div>
        <div class="sec-crypto-alg"><i class="bi bi-key me-1" style="color:#ffc107"></i> PBKDF2 / scrypt <span class="ov-badge ov-badge--success">Attivo</span></div>
        <div class="sec-crypto-alg"><i class="bi bi-shield-lock me-1" style="color:#20c997"></i> Data Sealing (Anti-Replay) <span class="ov-badge ov-badge--success">Attivo</span></div>
        <div class="sec-crypto-alg"><i class="bi bi-shuffle me-1" style="color:#0dcaf0"></i> Secure Token Gen <span class="ov-badge ov-badge--success">Attivo</span></div>
      </div>
      <div class="sec-crypto-actions">
        <button class="sec-action-btn" id="secRunBenchmark"><i class="bi bi-lightning-fill me-1"></i>Benchmark</button>
        <button class="sec-action-btn" id="secRotateKey"><i class="bi bi-arrow-repeat me-1"></i>Ruota Chiave</button>
        <button class="sec-action-btn" id="secGenToken"><i class="bi bi-key me-1"></i>Genera Token</button>
      </div>
    </div>`;
  };

  /* ── Alert Filters State ─────────────────────────────────────────────── */
  let _secFilterSev = 'all';
  let _secFilterSearch = '';
  let _secCachedAlerts = [];
  let _secCachedBf = null;
  const _secPag = { alerts: { page: 1, size: 20 }, blocked: { page: 1, size: 10 } };
  let secAutoRefreshTimer = null;

  /* ── Generic Pager Renderer ──────────────────────────────────────────── */
  const secRenderPager = (containerId, total, pag, onPageChange) => {
    const el = q(containerId);
    if (!el) return;
    const pages = Math.ceil(total / pag.size);
    if (pages <= 1) { el.innerHTML = ''; return; }
    const p = pag.page;
    let btns = '';
    btns += `<button class="sec-pg-btn" ${p <= 1 ? 'disabled' : ''} data-pg="${p - 1}" aria-label="Pagina precedente"><i class="bi bi-chevron-left"></i></button>`;
    const show = new Set();
    for (let i = 1; i <= pages; i++) {
      if (i <= 2 || i >= pages - 0 || Math.abs(i - p) <= 1) show.add(i);
    }
    let prev = 0;
    for (const i of [...show].sort((a, b) => a - b)) {
      if (prev && i - prev > 1) btns += '<span class="sec-pg-dots">…</span>';
      btns += i === p
        ? `<button class="sec-pg-btn sec-pg-btn--cur">${i}</button>`
        : `<button class="sec-pg-btn" data-pg="${i}">${i}</button>`;
      prev = i;
    }
    btns += `<button class="sec-pg-btn" ${p >= pages ? 'disabled' : ''} data-pg="${p + 1}" aria-label="Pagina successiva"><i class="bi bi-chevron-right"></i></button>`;
    el.innerHTML = `<div class="sec-pg">${btns}<span class="sec-pg-info">${total} totali · pag. ${p}/${pages}</span></div>`;
    el.querySelectorAll('[data-pg]').forEach(b => b.addEventListener('click', () => { pag.page = +b.dataset.pg; onPageChange(); }));
  };

  const secRenderFilteredAlerts = () => {
    let filtered = _secFilterSev === 'all' ? [..._secCachedAlerts] : _secCachedAlerts.filter(a => a.severity === _secFilterSev);
    if (_secFilterSearch) {
      const s = _secFilterSearch.toLowerCase();
      filtered = filtered.filter(a => ((a.message || '') + (a.category || '') + (a.source || '')).toLowerCase().includes(s));
    }
    const panel = q('secAlertsPanel');
    if (!panel) return;

    const total = filtered.length;
    const pag = _secPag.alerts;
    const pages = Math.ceil(total / pag.size) || 1;
    if (pag.page > pages) pag.page = Math.max(1, pages);
    const start = (pag.page - 1) * pag.size;
    const pageItems = filtered.slice(start, start + pag.size);

    const pill = q('secAlertsPill');
    if (pill) {
      pill.textContent = `${total} alert`;
      const crit = _secCachedAlerts.filter(a => a.severity === 'critical').length;
      const high = _secCachedAlerts.filter(a => a.severity === 'high').length;
      pill.className = 'ov-pill' + (crit > 0 ? ' ov-pill--crit' : high > 0 ? ' ov-pill--warn' : ' ov-pill--ok');
    }

    if (!pageItems.length) {
      panel.innerHTML = '<div class="ov-empty"><i class="bi bi-shield-check"></i><span class="ov-empty-text">Nessun alert di sicurezza</span></div>';
      secRenderPager('secAlertsPager', total, pag, secRenderFilteredAlerts);
      return;
    }

    panel.innerHTML = `<div class="ov-timeline">${pageItems.map(a => {
      const meta = secSeverityMeta(a.severity);
      const ts = a.ts ? new Date(a.ts * 1000).toLocaleString('it-IT') : '';
      const source = a.source ? `<span class="ov-badge ov-badge--muted">${esc(a.source)}</span>` : '';
      return `<div class="ov-tl-item">
        <div class="ov-tl-icon ${meta.cls}"><i class="bi ${meta.icon}"></i></div>
        <div class="ov-tl-body">
          <div class="ov-tl-head">
            <span class="ov-tl-action">${esc(a.category || 'alert')}</span>
            <span class="ov-badge ov-badge--${meta.badge}">${esc(meta.label)}</span>
            ${source}
            <span class="ov-tl-time">${ts}</span>
          </div>
          <div class="ov-tl-meta">${esc(a.message || '')}</div>
        </div>
      </div>`;
    }).join('')}</div>`;

    secRenderPager('secAlertsPager', total, pag, secRenderFilteredAlerts);
  };

  /* ── Blocked IPs Paginated Renderer ──────────────────────────────────── */
  const secRenderBlockedPaged = () => {
    const panel = q('secBlockedPanel');
    if (!panel || !_secCachedBf) return;
    const bf = _secCachedBf;
    const blocks = bf?.active_blocks || {};
    let ips = Object.entries(blocks);

    const searchVal = (q('secBlockedSearch')?.value || '').toLowerCase();
    if (searchVal) ips = ips.filter(([ip]) => ip.toLowerCase().includes(searchVal));

    let html = `<div class="sec-bf-summary">
      <div class="sec-bf-stat"><span class="sec-bf-num">${bf?.total_failed ?? 0}</span><span class="sec-bf-lbl">Login Falliti</span></div>
      <div class="sec-bf-stat"><span class="sec-bf-num">${bf?.tracked_ips ?? 0}</span><span class="sec-bf-lbl">IP Tracciati</span></div>
      <div class="sec-bf-stat"><span class="sec-bf-num">${ips.length}</span><span class="sec-bf-lbl">IP Bloccati</span></div>
    </div>`;

    const total = ips.length;
    if (total > 0) {
      const pag = _secPag.blocked;
      const pages = Math.ceil(total / pag.size) || 1;
      if (pag.page > pages) pag.page = Math.max(1, pages);
      const start = (pag.page - 1) * pag.size;
      const pageItems = ips.slice(start, start + pag.size);

      html += '<div class="sec-ip-table"><table class="sec-table"><thead><tr><th>Indirizzo IP</th><th>Scade tra</th><th>Azione</th></tr></thead><tbody>';
      pageItems.forEach(([ip, info]) => {
        const mins = Math.max(0, Math.ceil(info.expires_in / 60));
        html += `<tr><td class="sec-cell-ip"><i class="bi bi-pc-display me-1"></i>${esc(ip)}</td>
          <td><span class="ov-badge ov-badge--warning">${mins} min</span></td>
          <td><button class="sec-action-btn" data-unblock-ip="${esc(ip)}" title="Sblocca" aria-label="Sblocca IP ${esc(ip)}"><i class="bi bi-unlock"></i></button></td></tr>`;
      });
      html += '</tbody></table></div>';
      panel.innerHTML = html;
      secRenderPager('secBlockedPager', total, pag, secRenderBlockedPaged);
    } else {
      html += '<div class="sec-bf-empty"><i class="bi bi-shield-check"></i> Nessun IP bloccato</div>';
      panel.innerHTML = html;
      const pagerEl = q('secBlockedPager');
      if (pagerEl) pagerEl.innerHTML = '';
    }
  };

  /* ── Auto-refresh toggle ─────────────────────────────────────────────── */
  const secToggleAutoRefresh = (enabled) => {
    if (secAutoRefreshTimer) { clearInterval(secAutoRefreshTimer); secAutoRefreshTimer = null; }
    if (enabled) {
      secAutoRefreshTimer = setInterval(() => {
        if (state.currentView === 'security') loadSecurity();
      }, 15000);
    }
  };

  /* ══ MAIN LOADER ═════════════════════════════════════════════════════ */
  const loadSecurity = async () => {
    try {
      // Parallel fetch all data
      const [rStatus, rAlerts, rWaf, rBf, rFw, rIntg, rScore, rTl, rCrypto, rBench] = await Promise.allSettled([
        TPL.jsonFetch('/api/security/status'),
        TPL.jsonFetch('/api/security/alerts?limit=200&exclude_info=true'),
        TPL.jsonFetch('/api/security/waf'),
        TPL.jsonFetch('/api/security/bruteforce'),
        TPL.jsonFetch('/api/security/firewall'),
        TPL.jsonFetch('/api/security/integrity'),
        TPL.jsonFetch('/api/security/score'),
        TPL.jsonFetch('/api/security/threats/timeline?hours=24'),
        TPL.jsonFetch('/api/encryption/status'),
        TPL.jsonFetch('/api/encryption/benchmark'),
      ]);

      const status = rStatus.status === 'fulfilled' ? rStatus.value : null;
      const alerts = rAlerts.status === 'fulfilled' ? rAlerts.value : { items: [], count: 0 };
      const waf = rWaf.status === 'fulfilled' ? rWaf.value : null;
      const bf = rBf.status === 'fulfilled' ? rBf.value : null;
      const fw = rFw.status === 'fulfilled' ? rFw.value : null;
      const intg = rIntg.status === 'fulfilled' ? rIntg.value : null;
      const score = rScore.status === 'fulfilled' ? rScore.value : null;
      const tl = rTl.status === 'fulfilled' ? rTl.value : null;
      const crypto = rCrypto.status === 'fulfilled' ? rCrypto.value : null;
      const bench = rBench.status === 'fulfilled' ? rBench.value : null;

      const critical = status?.critical ?? 0;
      const high = status?.high ?? 0;
      const today = status?.real_threats_today ?? status?.total_today ?? 0;
      const threatLevel = status?.threat_level ?? 'low';
      const velocity = status?.threat_velocity ?? 0;
      const globalOk = critical === 0 && high === 0 && velocity === 0;

      // ── Score Ring ──
      const scoreRing = q('secScoreRing');
      if (scoreRing) scoreRing.innerHTML = secRenderScoreRing(score?.score ?? 100, score?.grade ?? 'A+');

      // ── Threat Gauge ──
      const gaugeEl = q('secThreatGauge');
      if (gaugeEl) gaugeEl.innerHTML = secRenderThreatGauge(threatLevel);
      const levelEl = q('secThreatLevel');
      if (levelEl) {
        const tm = secThreatLevelMeta(threatLevel);
        levelEl.innerHTML = `<span style="color:${tm.color};font-weight:700">${tm.label}</span>`;
      }

      // ── Hero Badges ──
      const badges = q('secHeroBadges');
      if (badges) {
        const badgeData = [
          { label: 'WAF', ok: waf?.enabled !== false },
          { label: 'IDS', ok: true },
          { label: 'Anti-BF', ok: true },
          { label: 'Integrità', ok: intg?.status !== 'tampered' },
          { label: 'Crypto', ok: crypto?.engine === 'active' },
        ];
        badges.innerHTML = badgeData.map(b =>
          `<span class="sec-badge sec-badge--${b.ok ? 'ok' : 'err'}"><i class="bi bi-${b.ok ? 'check-circle-fill' : 'x-circle-fill'}"></i> ${b.label}</span>`
        ).join('');
      }

      // ── KPIs ──
      q('secCritical').textContent = critical;
      q('secHigh').textContent = high;
      q('secToday').textContent = today;
      q('secGlobalStatus').textContent = globalOk ? 'OK' : 'Alert';
      q('secWafBlocked').textContent = waf?.total_blocked ?? 0;
      q('secBfBlocks').textContent = status?.blocked_ips ?? 0;
      q('secIntegrity').textContent = (intg?.status || 'ok').toUpperCase();
      q('secCryptoOps').textContent = crypto?.stats?.total_ops ?? 0;

      requestAnimationFrame(() => {
        const set = (id, v) => { const e = q(id); if (e) e.style.width = Math.min(v, 100) + '%'; };
        set('secCriticalBar', critical * 20);
        set('secHighBar', high * 10);
        set('secTodayBar', today * 5);
        set('secGlobalBar', globalOk ? 100 : 30);
        set('secWafBar', Math.min((waf?.total_blocked ?? 0) * 5, 100));
        set('secBfBar', Math.min((status?.blocked_ips ?? 0) * 15, 100));
        set('secIntBar', intg?.status === 'ok' || intg?.status === 'baseline_set' ? 100 : intg?.status === 'changed' ? 60 : 20);
        set('secCryptoBar', Math.min((crypto?.stats?.total_ops ?? 0) * 2, 100));
      });

      // ── Section Pills ──
      const wafPill = q('secWafPill');
      if (wafPill) { wafPill.textContent = `${waf?.total_blocked ?? 0} blocked`; wafPill.className = 'ov-pill' + ((waf?.total_blocked ?? 0) > 0 ? ' ov-pill--warn' : ' ov-pill--ok'); }
      const threatsPill = q('secThreatsPill');
      if (threatsPill) { threatsPill.textContent = `${tl?.total_events ?? 0} eventi`; threatsPill.className = 'ov-pill' + (critical > 0 ? ' ov-pill--crit' : ' ov-pill--ok'); }
      const bfPill = q('secBfPill');
      if (bfPill) { bfPill.textContent = `${bf?.total_failed ?? 0} falliti`; bfPill.className = 'ov-pill' + ((bf?.total_failed ?? 0) > 0 ? ' ov-pill--warn' : ' ov-pill--ok'); }
      const intPill = q('secIntegrityPill');
      if (intPill) { intPill.textContent = (intg?.status || 'ok').toUpperCase(); intPill.className = 'ov-pill' + (intg?.status === 'tampered' ? ' ov-pill--crit' : intg?.status === 'changed' ? ' ov-pill--warn' : ' ov-pill--ok'); }
      const cryptoPill = q('secCryptoPill');
      if (cryptoPill) { cryptoPill.textContent = `${crypto?.stats?.total_ops ?? 0} ops`; cryptoPill.className = 'ov-pill ov-pill--ok'; }

      // ── Render Panels ──
      const wp = q('secWafRulesPanel'); if (wp) wp.innerHTML = secRenderWafRules(waf);
      const ws = q('secWafStatsPanel'); if (ws) ws.innerHTML = secRenderWafStats(waf, status);
      const tp = q('secTimelinePanel'); if (tp) tp.innerHTML = secRenderTimelineChart(tl?.timeline || []);
      const cp = q('secCategoriesPanel'); if (cp) cp.innerHTML = secRenderCategories(status?.categories || {});
      _secCachedBf = bf; secRenderBlockedPaged();
      const rp = q('secRatePanel'); if (rp) rp.innerHTML = secRenderRateLimit(fw);
      const ip = q('secIntegrityPanel'); if (ip) ip.innerHTML = secRenderIntegrity(intg);
      const csp = q('secCryptoStatusPanel'); if (csp) csp.innerHTML = secRenderCryptoStatus(crypto, bench?.benchmark || null);
      const ctp = q('secCryptoToolsPanel'); if (ctp) ctp.innerHTML = secRenderCryptoTools();

      // ── Cache alerts for filtering ──
      _secCachedAlerts = (alerts?.items || []).slice().reverse();
      secRenderFilteredAlerts();

    } catch (error) {
      showMessage(`Security error: ${String(error)}`, 'warning');
      const ap = q('secAlertsPanel');
      if (ap) ap.innerHTML = `<div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">Errore: ${esc(String(error))}</span></div>`;
    }
  };


  // -----------------------------------------------------------------------
  // AUDIT — timeline view
  // -----------------------------------------------------------------------
  const auditActionMeta = (action, outcome) => {
    const icons = {
      'auth.login': 'bi-box-arrow-in-right',
      'modules.apply': 'bi-puzzle',
      'modules.reset': 'bi-arrow-counterclockwise',
    };
    const icon = icons[action] || 'bi-journal-text';
    const cls = outcome === 'success' ? 'tl-success' : outcome === 'failed' ? 'tl-danger' : 'tl-warning';
    return { icon, cls };
  };

  const loadAudit = async () => {
    try {
      const data = await state.routeControl.call('audit', { query: { limit: 40 } });
      const items = data?.items || [];
      const total = data?.count || items.length;
      const success = items.filter(i => i.outcome === 'success').length;
      const failed = items.filter(i => i.outcome !== 'success').length;

      /* KPIs */
      q('auditTotal').textContent = total;
      q('auditSuccess').textContent = success;
      q('auditFailed').textContent = failed;
      q('auditStatusChip').innerHTML = `<i class="bi bi-clock-history"></i> ${total} eventi`;

      /* Count pill */
      const pill = q('auditCountPill');
      if (pill) { pill.textContent = `${total} eventi`; pill.className = 'ov-pill ov-pill--info'; }

      if (!items.length) {
        q('auditTimeline').innerHTML = '<div class="ov-empty"><i class="bi bi-journal-text"></i><span class="ov-empty-text">Nessuna attività registrata</span></div>';
        return;
      }

      q('auditTimeline').innerHTML = `<div class="ov-timeline">${items.map(item => {
        const meta = auditActionMeta(item.action, item.outcome);
        const ts = item.ts ? new Date(item.ts * 1000).toLocaleString('it-IT') : '';
        const outBadge = item.outcome === 'success'
          ? '<span class="ov-badge ov-badge--success">Riuscito</span>'
          : item.outcome === 'failed'
          ? '<span class="ov-badge ov-badge--danger">Fallito</span>'
          : `<span class="ov-badge ov-badge--warning">${esc(item.outcome)}</span>`;
        return `<div class="ov-tl-item">
          <div class="ov-tl-icon ${meta.cls}"><i class="bi ${meta.icon}"></i></div>
          <div class="ov-tl-body">
            <div class="ov-tl-head">
              <span class="ov-tl-action">${esc(item.action || '—')}</span>
              ${outBadge}
              <span class="ov-tl-time">${ts}</span>
            </div>
            <div class="ov-tl-meta">
              <span class="ov-tl-meta-item"><i class="bi bi-person"></i> ${esc(item.actor || 'anonymous')}</span>
              <span class="ov-tl-meta-item"><i class="bi bi-globe"></i> ${esc(item.ip || '—')}</span>
              ${item.request_id ? `<span class="ov-tl-meta-item"><i class="bi bi-hash"></i> ${esc(item.request_id)}</span>` : ''}
            </div>
          </div>
        </div>`;
      }).join('')}</div>`;
    } catch (error) {
      showMessage(`Audit error: ${String(error)}`, 'warning');
      q('auditTimeline').innerHTML = `<div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">Errore: ${esc(String(error))}</span></div>`;
    }
  };

  // -----------------------------------------------------------------------
  // ROUTES — Advanced Route Control System
  // -----------------------------------------------------------------------
  let rtAutoRefreshTimer = null;
  let rtCachedRoutes = [];   // cached for client-side filtering
  let rtCachedCBs = {};      // cached for CB filtering

  const rtStatusMeta = (status) => {
    const map = {
      healthy:  { label: 'Operativo',  cls: 'ov-badge--success', icon: 'bi-check-circle-fill' },
      warning:  { label: 'Attenzione', cls: 'ov-badge--warning', icon: 'bi-exclamation-triangle' },
      degraded: { label: 'Degradato',  cls: 'ov-badge--warning', icon: 'bi-exclamation-triangle-fill' },
      critical: { label: 'Critico',    cls: 'ov-badge--danger',  icon: 'bi-x-octagon-fill' },
    };
    return map[status] || { label: status || '—', cls: 'ov-badge--muted', icon: 'bi-question-circle' };
  };

  const rtCBStateMeta = (st) => {
    const map = {
      closed:      { label: 'Chiuso',    cls: 'rt-cb--closed',    icon: 'bi-circle-fill',               badge: 'ov-badge--success' },
      open:        { label: 'APERTO',    cls: 'rt-cb--open',      icon: 'bi-exclamation-circle-fill',   badge: 'ov-badge--danger' },
      'half-open': { label: 'Recovery',  cls: 'rt-cb--halfopen',  icon: 'bi-arrow-repeat',              badge: 'ov-badge--warning' },
    };
    return map[st] || map.closed;
  };

  /* ── Collapsible Sections ── */
  const rtInitSections = () => {
    document.querySelectorAll('#view-routes .rt-section-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const sec = btn.closest('.rt-section');
        const wasOpen = sec.classList.contains('rt-section--open');
        sec.classList.toggle('rt-section--open', !wasOpen);
        btn.setAttribute('aria-expanded', String(!wasOpen));
      });
    });
  };

  const secInitSections = () => {
    document.querySelectorAll('#view-security .sec-section-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const sec = btn.closest('.sec-section');
        const wasOpen = sec.classList.contains('sec-section--open');
        sec.classList.toggle('sec-section--open', !wasOpen);
        btn.setAttribute('aria-expanded', String(!wasOpen));
      });
    });
  };

  const rtAlertSeverityMeta = (sev) => {
    const map = {
      critical: { label: 'Critico', icon: 'bi-x-octagon-fill',           cls: 'tl-danger',  badge: 'ov-badge--danger' },
      high:     { label: 'Alto',    icon: 'bi-exclamation-triangle-fill', cls: 'tl-warning', badge: 'ov-badge--warning' },
      medium:   { label: 'Medio',   icon: 'bi-exclamation-circle',       cls: 'tl-info',    badge: 'ov-badge--info' },
      low:      { label: 'Basso',   icon: 'bi-info-circle',              cls: 'tl-muted',   badge: 'ov-badge--muted' },
    };
    return map[sev] || map.low;
  };

  const rtFormatUptime = (seconds) => {
    if (!seconds || seconds < 0) return '—';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}g ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  const rtFormatLatency = (ms) => {
    if (ms === null || ms === undefined || ms < 0) return '—';
    if (ms < 1) return '<1ms';
    if (ms >= 1000) return `${(ms/1000).toFixed(1)}s`;
    return `${Math.round(ms)}ms`;
  };

  /* ═══════════════════════════════════════════════════════════════
     CONTROLLO GENERALE — Professional Chart & Visualization System
     ═══════════════════════════════════════════════════════════════ */

  /* ── SVG Donut (hero size) ── */
  const rtDonut = (segments, size = 180, stroke = 24) => {
    const r = (size - stroke) / 2;
    const circ = 2 * Math.PI * r;
    const cx = size / 2, cy = size / 2;
    const total = segments.reduce((s, sg) => s + sg.val, 0) || 1;
    let offset = 0;
    const arcs = segments.map((sg, i) => {
      const pct = sg.val / total;
      const dash = pct * circ;
      const gap = segments.length > 1 ? 3 : 0;
      const o = offset;
      offset += dash;
      return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${sg.color}" stroke-width="${stroke}"
        stroke-dasharray="${Math.max(0, dash - gap)} ${circ - Math.max(0, dash - gap)}" stroke-dashoffset="${-o}"
        stroke-linecap="round" transform="rotate(-90 ${cx} ${cy})"
        style="transition:stroke-dasharray .8s cubic-bezier(.4,0,.2,1),stroke-dashoffset .8s cubic-bezier(.4,0,.2,1);filter:drop-shadow(0 1px 2px ${sg.color}40)"/>`;
    });
    return `<svg viewBox="0 0 ${size} ${size}" class="rtcg-donut">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#f1f5f9" stroke-width="${stroke - 4}"/>
      ${arcs.join('')}
      <text x="${cx}" y="${cy - 8}" class="rtcg-donut-score" text-anchor="middle" dominant-baseline="central"></text>
      <text x="${cx}" y="${cy + 14}" class="rtcg-donut-sub" text-anchor="middle" dominant-baseline="central">Health Score</text>
    </svg>`;
  };

  /* ── Radial Gauge (error rate) ── */
  const rtGauge = (pct, label, color) => {
    const r = 52, stroke = 10, size = 130;
    const circ = 1.5 * Math.PI * r;
    const fill = (Math.min(pct, 100) / 100) * circ;
    const startAngle = 135;
    const cx = size / 2, cy = size / 2 + 8;
    return `<svg viewBox="0 0 ${size} ${size}" class="rtcg-gauge">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#f1f5f9" stroke-width="${stroke}"
        stroke-dasharray="${circ} ${2*Math.PI*r}" stroke-linecap="round"
        transform="rotate(${startAngle} ${cx} ${cy})"/>
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke + 2}"
        stroke-dasharray="${fill} ${2*Math.PI*r}" stroke-linecap="round"
        transform="rotate(${startAngle} ${cx} ${cy})"
        style="transition:stroke-dasharray .8s cubic-bezier(.4,0,.2,1);filter:drop-shadow(0 0 6px ${color}50)"/>
      <text x="${cx}" y="${cy - 4}" class="rtcg-gauge-val" text-anchor="middle">${pct.toFixed(1)}%</text>
      <text x="${cx}" y="${cy + 14}" class="rtcg-gauge-lbl" text-anchor="middle">${label}</text>
    </svg>`;
  };

  /* ── Horizontal Bar Chart ── */
  const rtHBarChart = (items, opts = {}) => {
    if (!items.length) return '<div class="ov-empty"><i class="bi bi-bar-chart"></i><span class="ov-empty-text">Nessun dato disponibile</span></div>';
    const maxVal = Math.max(...items.map(i => i.val), 1);
    const showValues = opts.showValues !== false;
    let html = '<div class="rtcg-hbars">';
    items.forEach((it, i) => {
      const pct = Math.max(2, (it.val / maxVal) * 100);
      const delay = i * 60;
      html += `<div class="rtcg-hbar-row" title="${esc(it.label)}: ${it.display || it.val}">
        <span class="rtcg-hbar-name">${esc(it.label)}</span>
        <div class="rtcg-hbar-track">
          <div class="rtcg-hbar-fill" style="width:${pct}%;background:${it.color || '#3b82f6'};transition-delay:${delay}ms"></div>
        </div>
        ${showValues ? `<span class="rtcg-hbar-val">${it.display || it.val}</span>` : ''}
      </div>`;
    });
    html += '</div>';
    return html;
  };

  /* ── Health Hero Renderer (left side) ── */
  const rtRenderChartHealth = (routesData) => {
    const el = q('rtChartHealth');
    const routes = routesData?.routes || [];
    const api = routes.filter(r => r.methods?.length > 0);
    const total = api.length || 1;
    const h = api.filter(r => r.health === 'healthy').length;
    const w = api.filter(r => r.health === 'warning').length;
    const d = api.filter(r => r.health === 'degraded').length;
    const c = api.filter(r => r.health === 'critical').length;
    const scorePct = total > 0 ? Math.round((h / total) * 100) : 0;

    const segments = [
      { val: h, color: '#22c55e', label: 'Healthy', icon: 'bi-check-circle-fill' },
      { val: w, color: '#f59e0b', label: 'Warning', icon: 'bi-exclamation-circle-fill' },
      { val: d, color: '#f97316', label: 'Degraded', icon: 'bi-exclamation-triangle-fill' },
      { val: c, color: '#ef4444', label: 'Critical', icon: 'bi-x-octagon-fill' },
    ].filter(s => s.val > 0);
    if (!segments.length) segments.push({ val: 1, color: '#e2e8f0', label: '—', icon: 'bi-dash' });

    el.innerHTML = `
      <div class="rtcg-health-wrap">
        <div class="rtcg-health-ring">
          ${rtDonut(segments)}
        </div>
        <div class="rtcg-health-breakdown">
          <div class="rtcg-health-title"><i class="bi bi-shield-check me-1"></i>Distribuzione Salute</div>
          ${[
            { val: h, color: '#22c55e', label: 'Healthy', icon: 'bi-check-circle-fill' },
            { val: w, color: '#f59e0b', label: 'Warning', icon: 'bi-exclamation-circle-fill' },
            { val: d, color: '#f97316', label: 'Degraded', icon: 'bi-exclamation-triangle-fill' },
            { val: c, color: '#ef4444', label: 'Critical', icon: 'bi-x-octagon-fill' },
          ].map(s => {
            const pct = total > 0 ? ((s.val / total) * 100).toFixed(0) : 0;
            return `<div class="rtcg-bd-row">
              <i class="bi ${s.icon}" style="color:${s.color}"></i>
              <span class="rtcg-bd-label">${s.label}</span>
              <div class="rtcg-bd-track"><div class="rtcg-bd-fill" style="width:${pct}%;background:${s.color}"></div></div>
              <span class="rtcg-bd-count" style="color:${s.color}">${s.val}</span>
            </div>`;
          }).join('')}
          <div class="rtcg-bd-total">Totale rotte API: <strong>${total}</strong></div>
        </div>
      </div>`;

    const scoreTxt = el.querySelector('.rtcg-donut-score');
    if (scoreTxt) scoreTxt.textContent = `${scorePct}%`;
  };

  /* ── Error Rate Hero Renderer (right side) ── */
  const rtRenderChartErrors = (statusData) => {
    const el = q('rtChartErrors');
    const gs = statusData?.global_stats || {};
    const st = statusData || {};
    const cb = st.circuit_breakers || {};
    const errRate = (gs.error_rate || 0) * 100;
    const color = errRate > 40 ? '#ef4444' : errRate > 15 ? '#f59e0b' : '#22c55e';
    const reqs = gs.total_requests || 0;
    const errs = gs.total_errors || 0;

    el.innerHTML = `
      <div class="rtcg-errors-wrap">
        <div class="rtcg-errors-gauge">
          ${rtGauge(errRate, 'Error Rate', color)}
        </div>
        <div class="rtcg-errors-grid">
          <div class="rtcg-stat-tile">
            <div class="rtcg-stat-icon"><i class="bi bi-send-fill" style="color:#6366f1"></i></div>
            <div class="rtcg-stat-data"><span class="rtcg-stat-num">${reqs.toLocaleString()}</span><span class="rtcg-stat-lbl">Richieste</span></div>
          </div>
          <div class="rtcg-stat-tile">
            <div class="rtcg-stat-icon"><i class="bi bi-x-circle-fill" style="color:${errs > 0 ? '#ef4444' : '#94a3b8'}"></i></div>
            <div class="rtcg-stat-data"><span class="rtcg-stat-num ${errs > 0 ? 'rt-text-danger' : ''}">${errs.toLocaleString()}</span><span class="rtcg-stat-lbl">Errori</span></div>
          </div>
          <div class="rtcg-stat-tile">
            <div class="rtcg-stat-icon"><i class="bi bi-lightning-fill" style="color:${(cb.open||0) > 0 ? '#ef4444' : '#94a3b8'}"></i></div>
            <div class="rtcg-stat-data"><span class="rtcg-stat-num ${(cb.open||0) > 0 ? 'rt-text-danger' : ''}">${cb.open ?? 0}</span><span class="rtcg-stat-lbl">CB Aperti</span></div>
          </div>
          <div class="rtcg-stat-tile">
            <div class="rtcg-stat-icon"><i class="bi bi-speedometer2" style="color:#3b82f6"></i></div>
            <div class="rtcg-stat-data"><span class="rtcg-stat-num">${rtFormatLatency(st.global_avg_latency_ms)}</span><span class="rtcg-stat-lbl">Latenza Media</span></div>
          </div>
        </div>
      </div>`;
  };

  /* ── Route Control Restart with live tracking ── */
  let _rtRestartPolling = null;

  const rtPhaseLabels = {
    stop_watchdog:  'Arresto Watchdog',
    clear_metrics:  'Reset Metriche',
    clear_cbs:      'Reset Circuit Breakers',
    clear_alerts:   'Pulizia Alert e Heal Log',
    reset_globals:  'Reset Contatori Globali',
    start_watchdog: 'Avvio Watchdog',
    verify:         'Verifica Sistema',
    complete:       'Completato',
    error:          'Errore',
  };

  const rtPhaseIcons = {
    stop_watchdog:  'bi-stop-circle',
    clear_metrics:  'bi-eraser',
    clear_cbs:      'bi-lightning',
    clear_alerts:   'bi-trash3',
    reset_globals:  'bi-arrow-counterclockwise',
    start_watchdog: 'bi-play-circle',
    verify:         'bi-check2-circle',
    complete:       'bi-check-circle-fill',
    error:          'bi-x-octagon-fill',
  };

  const rtShowRestartOverlay = () => {
    const ov = q('rtRestartOverlay');
    if (ov) { ov.style.display = 'flex'; ov.offsetHeight; ov.classList.add('rtcg-restart-overlay--active'); }
    const btn = q('rtRestartBtn');
    if (btn) btn.disabled = true;
  };

  const rtHideRestartOverlay = () => {
    const ov = q('rtRestartOverlay');
    if (ov) { ov.classList.remove('rtcg-restart-overlay--active'); setTimeout(() => { ov.style.display = 'none'; }, 400); }
    const btn = q('rtRestartBtn');
    if (btn) btn.disabled = false;
  };

  const rtUpdateRestartUI = (data) => {
    const phase = data.phase || 'unknown';
    const progress = Math.min(data.progress || 0, 100);
    const isDone = phase === 'complete';
    const isError = phase === 'error';

    // Update progress bar
    const barFill = q('rtRestartBarFill');
    if (barFill) {
      barFill.style.width = progress + '%';
      barFill.style.background = isError ? '#ef4444' : isDone ? '#22c55e' : '';
    }
    const pctEl = q('rtRestartPct');
    if (pctEl) pctEl.textContent = progress + '%';

    // Update phase label
    const phaseEl = q('rtRestartPhase');
    if (phaseEl) phaseEl.textContent = rtPhaseLabels[phase] || phase;

    // Update title
    const titleEl = q('rtRestartTitle');
    if (titleEl) {
      if (isDone) titleEl.textContent = 'Riavvio Completato!';
      else if (isError) titleEl.textContent = 'Errore nel Riavvio';
      else titleEl.textContent = 'Riavvio Route Control';
    }

    // Update icon
    const iconEl = q('rtRestartIcon');
    if (iconEl) {
      if (isDone) iconEl.innerHTML = '<i class="bi bi-check-circle-fill rtcg-restart-done"></i>';
      else if (isError) iconEl.innerHTML = '<i class="bi bi-x-octagon-fill rtcg-restart-error"></i>';
      else iconEl.innerHTML = '<i class="bi bi-arrow-clockwise rtcg-restart-spin"></i>';
    }

    // Render phase checklist
    const allPhases = data.phases || [];
    const done = new Set(data.phases_done || []);
    const phasesEl = q('rtRestartPhases');
    if (phasesEl) {
      phasesEl.innerHTML = allPhases.map(p => {
        const isCurrent = p.id === phase;
        const isPhDone = done.has(p.id);
        const icon = isPhDone ? 'bi-check-circle-fill' : isCurrent ? 'bi-arrow-right-circle-fill' : 'bi-circle';
        const cls = isPhDone ? 'rtcg-rp--done' : isCurrent ? 'rtcg-rp--active' : 'rtcg-rp--pending';
        return `<div class="rtcg-rp ${cls}">
          <i class="bi ${icon} rtcg-rp-icon"></i>
          <span class="rtcg-rp-label">${esc(p.label)}</span>
          <span class="rtcg-rp-weight">${p.weight}%</span>
        </div>`;
      }).join('');
    }
  };

  const rtPollRestart = () => {
    if (_rtRestartPolling) return;
    _rtRestartPolling = setInterval(async () => {
      try {
        const data = await TPL.jsonFetch('/api/router/restart/status');
        rtUpdateRestartUI(data);

        if (!data.active && (data.phase === 'complete' || data.phase === 'error')) {
          clearInterval(_rtRestartPolling);
          _rtRestartPolling = null;

          // Wait a moment then hide overlay and refresh
          setTimeout(async () => {
            rtHideRestartOverlay();
            if (data.phase === 'complete') {
              showMessage('Route Control riavviato con successo', 'success');
              await loadRoutesPanel();
            } else {
              showMessage(`Errore nel riavvio: ${data.error || 'sconosciuto'}`, 'danger');
            }
          }, 1500);
        }
      } catch (e) {
        clearInterval(_rtRestartPolling);
        _rtRestartPolling = null;
        rtHideRestartOverlay();
        showMessage('Errore nella verifica del riavvio', 'danger');
      }
    }, 350);
  };

  const rtDoRestart = async () => {
    if (!confirm('Vuoi riavviare il Route Control?\n\nTutte le metriche, circuit breakers, alert e log verranno resettati.\nIl watchdog verrà riavviato.')) return;

    rtShowRestartOverlay();
    // Reset UI
    rtUpdateRestartUI({ phase: null, progress: 0, phases_done: [], phases: [] });

    try {
      const res = await TPL.jsonFetch('/api/router/restart', { method: 'POST' });
      // Start polling from the returned phases
      rtUpdateRestartUI({ phase: 'stop_watchdog', progress: 0, phases_done: [], phases: res.phases || [] });
      rtPollRestart();
    } catch (e) {
      rtHideRestartOverlay();
      showMessage(`Errore avvio riavvio: ${String(e)}`, 'danger');
    }
  };

  /* ── Latency Chart Renderer (horizontal bars) ── */
  const rtRenderChartLatency = (topoData) => {
    const el = q('rtChartLatency');
    const groups = topoData?.api_groups || {};
    const items = Object.entries(groups).map(([name, routes]) => {
      const totalReq = routes.reduce((s, r) => s + (r.requests || 0), 0);
      const avgLat = totalReq > 0
        ? routes.reduce((s, r) => s + (r.requests || 0) * (r.avg_latency_ms || 0), 0) / totalReq
        : 0;
      return {
        label: '/' + name,
        val: avgLat,
        display: rtFormatLatency(avgLat),
        color: avgLat > 100 ? '#ef4444' : avgLat > 30 ? '#f59e0b' : '#3b82f6'
      };
    }).filter(i => i.val > 0).sort((a, b) => b.val - a.val).slice(0, 8);
    el.innerHTML = rtHBarChart(items);
  };

  /* ── Traffic Chart Renderer (horizontal bars) ── */
  const rtRenderChartTraffic = (topoData) => {
    const el = q('rtChartTraffic');
    const groups = topoData?.api_groups || {};
    const items = Object.entries(groups).map(([name, routes]) => {
      const totalReq = routes.reduce((s, r) => s + (r.requests || 0), 0);
      return {
        label: '/' + name,
        val: totalReq,
        display: `${totalReq} req`,
        color: '#6366f1'
      };
    }).filter(i => i.val > 0).sort((a, b) => b.val - a.val).slice(0, 8);
    el.innerHTML = rtHBarChart(items);
  };

  /* ── System Summary Renderer ── */
  const rtRenderSysSummary = (statusData, topoData) => {
    const el = q('rtSysSummary');
    const st = statusData || {};
    const gs = st.global_stats || {};
    const cb = st.circuit_breakers || {};
    const issues = st.health_issues || [];
    const ic = st.issue_counts || {};
    const meta = rtStatusMeta(st.status);
    const groups = topoData?.api_groups || {};
    const groupCount = Object.keys(groups).length;
    const totalIssues = (ic.critical || 0) + (ic.high || 0) + (ic.medium || 0) + (ic.low || 0);

    const statCards = [
      { icon: 'bi-signpost-2-fill', color: '#3b82f6', val: st.active_routes ?? 0, lbl: 'Rotte Attive' },
      { icon: 'bi-diagram-3-fill',  color: '#8b5cf6', val: groupCount,            lbl: 'Gruppi API' },
      { icon: 'bi-layers-fill',     color: '#06b6d4', val: st.middleware_count ?? 0, lbl: 'Middleware' },
      { icon: 'bi-shield-fill-check', color: meta.label === 'Healthy' ? '#22c55e' : meta.label === 'Critical' ? '#ef4444' : '#f59e0b', val: '', lbl: 'Stato', badge: `<span class="ov-badge ${meta.cls}"><i class="bi ${meta.icon}"></i> ${esc(meta.label)}</span>` },
    ];

    const sevBar = [
      { color: '#ef4444', count: ic.critical || 0, label: 'Critici' },
      { color: '#f59e0b', count: ic.high || 0,     label: 'Alti' },
      { color: '#3b82f6', count: ic.medium || 0,   label: 'Medi' },
      { color: '#94a3b8', count: ic.low || 0,      label: 'Bassi' },
    ];

    let issuesHtml = '';
    if (issues.length > 0) {
      issuesHtml = `<div class="rtcg-issues">
        <div class="rtcg-issues-head"><i class="bi bi-exclamation-triangle-fill text-warning me-1"></i>Problemi rilevati (${issues.length})</div>
        <div class="rtcg-issues-list">
        ${issues.slice(0, 6).map(i => {
          const m = rtStatusMeta(i.severity || 'warning');
          return `<div class="rtcg-issue-row">
            <i class="bi ${m.icon} rt-health-${i.severity}"></i>
            <strong>${esc(i.route || '')}</strong>
            <span>${esc(i.description || i.issue || '')}</span>
          </div>`;
        }).join('')}
        </div>
      </div>`;
    }

    el.innerHTML = `
      <div class="rtcg-summary-grid">
        ${statCards.map(s => `
          <div class="rtcg-sum-card">
            <div class="rtcg-sum-icon" style="color:${s.color}"><i class="bi ${s.icon}"></i></div>
            <div class="rtcg-sum-val">${s.badge || s.val}</div>
            <div class="rtcg-sum-lbl">${s.lbl}</div>
          </div>`).join('')}
      </div>
      <div class="rtcg-severity-bar mt-2">
        <div class="rtcg-sev-header">
          <span class="rtcg-sev-title"><i class="bi bi-bar-chart-steps me-1"></i>Severità Problemi</span>
          <span class="rtcg-sev-total">${totalIssues} totali</span>
        </div>
        <div class="rtcg-sev-track">
          ${sevBar.map(s => {
            const w = totalIssues > 0 ? Math.max(0, (s.count / totalIssues) * 100) : 0;
            return s.count > 0 ? `<div class="rtcg-sev-fill" style="width:${w}%;background:${s.color}" title="${s.label}: ${s.count}"></div>` : '';
          }).join('')}
          ${totalIssues === 0 ? '<div class="rtcg-sev-fill" style="width:100%;background:#22c55e"></div>' : ''}
        </div>
        <div class="rtcg-sev-legend">
          ${sevBar.map(s => `<span class="rtcg-sev-item"><span class="rtcg-sev-dot" style="background:${s.color}"></span>${s.label}: ${s.count}</span>`).join('')}
        </div>
      </div>
      ${issuesHtml}
    `;

    // Update general pill
    const gPill = q('rtGeneralPill');
    if (gPill) {
      gPill.textContent = meta.label;
      gPill.className = 'ov-pill ms-auto ' + (st.status === 'healthy' ? 'ov-pill--ok' : st.status === 'critical' ? 'ov-pill--crit' : 'ov-pill--warn');
    }
  };

  /* ── Topology Renderer ── */
  const rtRenderTopology = (topo) => {
    const el = q('rtTopologyPanel');
    if (!topo) { el.innerHTML = '<div class="ov-empty"><i class="bi bi-diagram-3"></i><span class="ov-empty-text">Topologia non disponibile</span></div>'; return; }

    const pill = q('rtTopologyPill');
    if (pill) { pill.textContent = `${topo.total_endpoints || 0} endpoint`; pill.className = 'ov-pill ov-pill--info'; }

    let html = '<div class="rt-topology">';
    // Proxy layer
    html += '<div class="rt-topo-layer"><div class="rt-topo-layer-head"><i class="bi bi-hdd-rack"></i> Traefik Reverse Proxy</div>';
    html += '<div class="rt-topo-proxies">';
    (topo.proxy?.routes || []).forEach(r => {
      html += `<div class="rt-topo-proxy">
        <span class="rt-topo-rule">${esc(r.rule)}</span>
        <i class="bi bi-arrow-right rt-topo-arrow"></i>
        <span class="rt-topo-svc"><i class="bi bi-server"></i> ${esc(r.service)}</span>
        <span class="rt-topo-target">${esc(r.target)}</span>
      </div>`;
    });
    html += '</div></div>';

    // API groups layer
    html += '<div class="rt-topo-layer"><div class="rt-topo-layer-head"><i class="bi bi-code-slash"></i> API Endpoints</div>';
    html += '<div class="rt-topo-groups">';

    const groups = topo.api_groups || {};
    Object.entries(groups).forEach(([group, routes]) => {
      const healthCounts = { healthy: 0, degraded: 0, critical: 0 };
      routes.forEach(r => { healthCounts[r.health] = (healthCounts[r.health] || 0) + 1; });
      const groupHealth = healthCounts.critical > 0 ? 'critical' : healthCounts.degraded > 0 ? 'degraded' : 'healthy';
      const gMeta = rtStatusMeta(groupHealth);
      const totalReq = routes.reduce((s, r) => s + (r.requests || 0), 0);

      html += `<div class="rt-topo-group">
        <div class="rt-topo-group-head">
          <span class="rt-topo-group-name"><i class="bi ${gMeta.icon} rt-health-${groupHealth}"></i> /${esc(group)}</span>
          <span class="rt-topo-group-info">${routes.length} rotte · ${totalReq} req</span>
        </div>
        <div class="rt-topo-routes">`;
      routes.forEach(r => {
        const rMeta = rtStatusMeta(r.health);
        const methods = (r.methods || []).map(m => `<span class="ov-method-tag m-${m.toLowerCase()}">${m}</span>`).join('');
        html += `<div class="rt-topo-route rt-health-bg-${r.health}">
          <span class="rt-topo-route-path">${esc(r.path)}</span>
          <span class="ov-route-methods">${methods}</span>
          <span class="rt-topo-route-stats">${r.requests || 0} req${r.errors > 0 ? ` · <span class="text-danger">${r.errors} err</span>` : ''}</span>
          <span class="rt-topo-route-cb"><i class="bi ${rtCBStateMeta(r.cb_state).icon} ${rtCBStateMeta(r.cb_state).cls}"></i></span>
        </div>`;
      });
      html += '</div></div>';
    });
    html += '</div></div></div>';
    el.innerHTML = html;
  };

  /* ── Watchdog Renderer (Professional) ── */
  const rtRenderWatchdog = (status) => {
    const el = q('rtWatchdogPanel');
    const wd = status?.watchdog || {};
    const gs = status?.global_stats || {};
    const sh = status?.self_healing || {};
    const cb = status?.circuit_breakers || {};
    const meta = rtStatusMeta(status?.status);

    const wdPill = q('rtWatchdogPill');
    if (wdPill) {
      wdPill.textContent = wd.running ? 'Attivo' : 'Fermo';
      wdPill.className = 'ov-pill ' + (wd.running ? 'ov-pill--ok' : 'ov-pill--crit');
    }

    const stats = [
      { icon: 'bi-activity',           label: 'Stato',           value: `<span class="ov-badge ${meta.cls}"><i class="bi ${meta.icon}"></i> ${esc(meta.label)}</span>` },
      { icon: 'bi-heart-pulse',        label: 'Watchdog',        value: `<span class="ov-badge ${wd.running ? 'ov-badge--success' : 'ov-badge--danger'}"><i class="bi bi-circle-fill"></i> ${wd.running ? 'Attivo' : 'Fermo'}</span>` },
      { icon: 'bi-arrow-repeat',       label: 'Cicli',           value: wd.cycle_count ?? 0 },
      { icon: 'bi-check2-all',         label: 'Sani consec.',    value: wd.consecutive_healthy ?? 0 },
      { icon: 'bi-clock-history',      label: 'Uptime',          value: rtFormatUptime(status?.uptime_seconds) },
      { icon: 'bi-send',              label: 'Richieste',       value: (gs.total_requests ?? 0).toLocaleString() },
      { icon: 'bi-x-circle',          label: 'Errori',          value: `<span class="${(gs.total_errors||0) > 0 ? 'rt-text-danger' : ''}">${gs.total_errors ?? 0}${gs.error_rate > 0 ? ` (${(gs.error_rate*100).toFixed(1)}%)` : ''}</span>` },
      { icon: 'bi-lightning',         label: 'CB Aperti',       value: `<span class="${(cb.open||0) > 0 ? 'rt-text-danger' : ''}">${cb.open ?? 0}${cb.half_open > 0 ? ` +${cb.half_open}` : ''}</span>` },
      { icon: 'bi-bandaid',           label: 'Self-healing',    value: sh.events ?? 0 },
    ];

    if (wd.consecutive_degraded > 0) {
      stats.splice(4, 0, { icon: 'bi-exclamation-triangle', label: 'Degradati', value: `<span class="rt-text-danger">${wd.consecutive_degraded}</span>` });
    }

    el.innerHTML = `<div class="rtcg-wd-grid">
      ${stats.map(s => `<div class="rtcg-wd-row">
        <span class="rtcg-wd-icon"><i class="bi ${s.icon}"></i></span>
        <span class="rtcg-wd-label">${s.label}</span>
        <span class="rtcg-wd-val">${s.value}</span>
      </div>`).join('')}
    </div>`;
  };

  /* ── Alerts Renderer ── */
  const rtRenderAlerts = (alertsData) => {
    const el = q('rtAlertsPanel');
    const items = alertsData?.alerts || [];
    const active = alertsData?.active || 0;
    const pill = q('rtAlertsPill');

    if (pill) {
      pill.textContent = `${active} attivi`;
      pill.className = 'ov-pill ' + (active === 0 ? 'ov-pill--ok' : items.some(a => a.severity === 'critical' && !a.resolved) ? 'ov-pill--crit' : 'ov-pill--warn');
    }

    if (!items.length) {
      el.innerHTML = '<div class="ov-empty"><i class="bi bi-shield-check"></i><span class="ov-empty-text">Nessun alert — Sistema operativo</span></div>';
      return;
    }

    el.innerHTML = `<div class="ov-timeline">${items.slice(0, 30).map(a => {
      const meta = rtAlertSeverityMeta(a.severity);
      const ts = a.ts ? new Date(a.ts * 1000).toLocaleString('it-IT') : '';
      const resolved = a.resolved ? ' rt-alert-resolved' : '';
      return `<div class="ov-tl-item${resolved}">
        <div class="ov-tl-icon ${meta.cls}"><i class="bi ${meta.icon}"></i></div>
        <div class="ov-tl-body">
          <div class="ov-tl-head">
            <span class="ov-tl-action">${esc(a.category || 'alert')}</span>
            <span class="ov-badge ${meta.badge}">${esc(meta.label)}</span>
            ${a.resolved ? '<span class="ov-badge ov-badge--muted">Risolto</span>' : ''}
            <span class="ov-tl-time">${ts}</span>
          </div>
          <div class="ov-tl-meta">${esc(a.message || '')}</div>
          ${a.route ? `<div class="ov-tl-meta"><i class="bi bi-signpost-split"></i> ${esc(a.route)}</div>` : ''}
        </div>
      </div>`;
    }).join('')}</div>`;
  };

  /* ── Routes Table Renderer (with filter support) ── */
  const rtBuildTableHTML = (apiRoutes) => {
    let html = '<div class="rt-table-wrap"><table class="rt-table"><thead><tr>';
    html += '<th></th><th>Rotta</th><th>Metodi</th><th>Req</th><th>Errori</th><th>Latenza</th><th>CB</th>';
    html += '</tr></thead><tbody>';

    apiRoutes.forEach(r => {
      const m = r.metrics || {};
      const cb = r.circuit_breaker || {};
      const hMeta = rtStatusMeta(r.health);
      const cbMeta = rtCBStateMeta(cb.state || 'closed');
      const methods = (r.methods || []).map(mt => `<span class="ov-method-tag m-${mt.toLowerCase()}">${mt}</span>`).join('');
      const errRate = m.error_rate > 0 ? ` (${(m.error_rate*100).toFixed(1)}%)` : '';

      html += `<tr class="rt-row-${r.health}" data-path="${esc(r.path)}" data-health="${r.health}" data-methods="${(r.methods||[]).join(',')}" data-cb="${cb.state || 'closed'}">
        <td><i class="bi ${hMeta.icon} rt-health-${r.health}" title="${esc(hMeta.label)}"></i></td>
        <td class="rt-cell-path">${esc(r.path)}</td>
        <td><div class="ov-route-methods">${methods}</div></td>
        <td class="rt-cell-num">${m.requests || 0}</td>
        <td class="rt-cell-num ${(m.errors || 0) > 0 ? 'rt-text-danger' : ''}">${m.errors || 0}${errRate}</td>
        <td class="rt-cell-num">${rtFormatLatency(m.avg_latency_ms)}${m.p95_latency_ms > 0 ? `<small class="rt-p95"> P95:${rtFormatLatency(m.p95_latency_ms)}</small>` : ''}</td>
        <td><span class="ov-badge ${cbMeta.badge}" title="Failures: ${cb.failures || 0}"><i class="bi ${cbMeta.icon}"></i></span></td>
      </tr>`;
    });

    html += '</tbody></table></div>';
    return html;
  };

  const rtApplyRouteFilters = () => {
    const pathVal  = (q('rtFilterPath')?.value || '').toLowerCase();
    const methodVal = q('rtFilterMethod')?.value || '';
    const healthVal = q('rtFilterHealth')?.value || '';
    const cbVal     = q('rtFilterCB')?.value || '';

    const el = q('rtRoutesTablePanel');
    const rows = el?.querySelectorAll('tbody tr') || [];
    let shown = 0, total = rows.length;

    rows.forEach(tr => {
      const path = (tr.dataset.path || '').toLowerCase();
      const health = tr.dataset.health || '';
      const methods = tr.dataset.methods || '';
      const cb = tr.dataset.cb || '';

      const ok = (!pathVal || path.includes(pathVal))
             && (!methodVal || methods.includes(methodVal))
             && (!healthVal || health === healthVal)
             && (!cbVal || cb === cbVal);

      tr.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });

    const countEl = q('rtFilterCount');
    if (countEl) {
      countEl.textContent = (pathVal || methodVal || healthVal || cbVal) ? `${shown} di ${total} rotte visibili` : '';
    }
  };

  const rtRenderRoutesTable = (routesData) => {
    const el = q('rtRoutesTablePanel');
    const routes = routesData?.routes || [];
    const pill = q('rtRoutesCountPill');

    if (pill) { pill.textContent = `${routes.length} rotte`; pill.className = 'ov-pill ov-pill--info'; }

    if (!routes.length) {
      el.innerHTML = '<div class="ov-empty"><i class="bi bi-signpost-split"></i><span class="ov-empty-text">Nessuna rotta registrata</span></div>';
      return;
    }

    const apiRoutes = routes.filter(r => r.methods && r.methods.length > 0);
    rtCachedRoutes = apiRoutes;
    el.innerHTML = rtBuildTableHTML(apiRoutes);
    rtApplyRouteFilters();
  };

  /* ── Self-Healing Log Renderer ── */
  const rtRenderHealLog = (healData) => {
    const el = q('rtHealPanel');
    const events = healData?.events || [];
    const pill = q('rtHealPill');
    if (pill) { pill.textContent = `${healData?.total || 0}`; pill.className = 'ov-pill ov-pill--info'; }

    if (!events.length) {
      el.innerHTML = '<div class="ov-empty"><i class="bi bi-bandaid"></i><span class="ov-empty-text">Nessun evento self-healing</span></div>';
      return;
    }

    el.innerHTML = events.slice(0, 20).map(e => {
      const ts = e.ts ? new Date(e.ts * 1000).toLocaleString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
      const icon = e.success ? 'bi-check-circle-fill' : 'bi-x-circle-fill';
      const cls = e.success ? 'rt-heal-ok' : 'rt-heal-fail';
      return `<div class="rt-heal-item ${cls}">
        <i class="bi ${icon}"></i>
        <div class="rt-heal-body">
          <div class="rt-heal-action">${esc(e.action || '—')}</div>
          <div class="rt-heal-detail">${esc(e.detail || '')} <span class="rt-heal-time">${ts}</span></div>
        </div>
      </div>`;
    }).join('');
  };

  /* ── Circuit Breakers Renderer (with filter support) ── */
  const rtRenderCircuitBreakers = (cbData) => {
    const el = q('rtCircuitPanel');
    const cbs = cbData?.circuit_breakers || {};
    const summary = cbData?.summary || {};
    const pill = q('rtCBPill');
    rtCachedCBs = cbs;

    if (pill) {
      const openCount = (summary.open || 0) + (summary.half_open || 0);
      pill.textContent = openCount > 0 ? `${openCount} attivi` : 'OK';
      pill.className = 'ov-pill ' + (summary.open > 0 ? 'ov-pill--crit' : summary.half_open > 0 ? 'ov-pill--warn' : 'ov-pill--ok');
    }

    const entries = Object.entries(cbs);
    if (!entries.length) {
      el.innerHTML = '<div class="ov-empty"><i class="bi bi-lightning"></i><span class="ov-empty-text">Nessun circuit breaker attivato — sistema stabile</span></div>';
      return;
    }

    const stateOrder = { open: 0, 'half-open': 1, closed: 2 };
    entries.sort((a, b) => (stateOrder[a[1].state] || 2) - (stateOrder[b[1].state] || 2));

    el.innerHTML = entries.map(([path, cb]) => {
      const meta = rtCBStateMeta(cb.state);
      const age = cb.age ? `aperto da ${cb.age}s` : '';
      const canReset = cb.state !== 'closed';
      return `<div class="rt-cb-item ${meta.cls}" data-cb-path="${esc(path)}" data-cb-state="${cb.state || 'closed'}">
        <div class="rt-cb-head">
          <i class="bi ${meta.icon}"></i>
          <span class="rt-cb-path">${esc(path)}</span>
          <span class="ov-badge ${meta.badge}">${esc(meta.label)}</span>
        </div>
        <div class="rt-cb-stats">
          <span>Fallimenti: ${cb.failures || 0}</span>
          <span>Scatti: ${cb.trips || 0}</span>
          ${age ? `<span>${age}</span>` : ''}
          <span>Err: ${((cb.error_rate || 0)*100).toFixed(1)}%</span>
          <span>Lat: ${rtFormatLatency(cb.avg_latency_ms)}</span>
        </div>
        ${canReset ? `<button class="rt-cb-reset" data-cb-reset="${esc(path)}"><i class="bi bi-arrow-counterclockwise"></i> Reset</button>` : ''}
      </div>`;
    }).join('');

    rtApplyCBFilters();

    el.querySelectorAll('[data-cb-reset]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const p = btn.dataset.cbReset;
        try {
          await TPL.jsonFetch(`/api/router/circuit-breakers/reset?path=${encodeURIComponent(p)}`, { method: 'POST' });
          showMessage(`Circuit breaker resettato: ${p}`, 'success');
          await loadRoutesPanel();
        } catch (e) { showMessage(`Errore reset CB: ${e}`, 'danger'); }
      });
    });
  };

  const rtApplyCBFilters = () => {
    const pathVal = (q('rtCBFilterPath')?.value || '').toLowerCase();
    const stateVal = q('rtCBFilterState')?.value || '';
    const el = q('rtCircuitPanel');
    (el?.querySelectorAll('.rt-cb-item') || []).forEach(item => {
      const path = (item.dataset.cbPath || '').toLowerCase();
      const state = item.dataset.cbState || '';
      const ok = (!pathVal || path.includes(pathVal)) && (!stateVal || state === stateVal);
      item.style.display = ok ? '' : 'none';
    });
  };

  /* ── Shorthand Map Renderer ── */
  const rtRenderShorthand = (mapData) => {
    const el = q('rtShorthandPanel');
    const shortcuts = mapData?.shorthand_routes || {};
    const count = Object.keys(shortcuts).length;

    if (count === 0) {
      el.innerHTML = '<div class="ov-empty"><i class="bi bi-link-45deg"></i><span class="ov-empty-text">Nessuna scorciatoia configurata</span></div>';
      return;
    }

    el.innerHTML = Object.entries(shortcuts).map(([key, val]) =>
      `<div class="ov-route-item">
        <span class="ov-route-label">/api/r/${esc(key)}</span>
        <span class="ov-route-arrow"><i class="bi bi-arrow-right"></i></span>
        <span class="ov-route-path">/api${esc(val.full_path || '')}</span>
      </div>`
    ).join('');
  };

  /* ── Main Route Control Loader ── */
  const loadRoutesPanel = async () => {
    try {
      const [status, routesData, alertsData, healData, cbData, topoData, mapData] = await Promise.allSettled([
        TPL.jsonFetch('/api/router/status'),
        TPL.jsonFetch('/api/router/routes'),
        TPL.jsonFetch('/api/router/alerts?limit=30'),
        TPL.jsonFetch('/api/router/heal-log?limit=20'),
        TPL.jsonFetch('/api/router/circuit-breakers'),
        TPL.jsonFetch('/api/router/topology'),
        TPL.jsonFetch('/api/r/map'),
      ]);

      const st  = status.status === 'fulfilled' ? status.value : null;
      const rt  = routesData.status === 'fulfilled' ? routesData.value : null;
      const al  = alertsData.status === 'fulfilled' ? alertsData.value : null;
      const hl  = healData.status === 'fulfilled' ? healData.value : null;
      const cb  = cbData.status === 'fulfilled' ? cbData.value : null;
      const tp  = topoData.status === 'fulfilled' ? topoData.value : null;
      const mp  = mapData.status === 'fulfilled' ? mapData.value : null;

      /* ── KPIs ── */
      q('rtTotal').textContent = st?.total_routes ?? '—';

      const allRoutes = rt?.routes || [];
      const healthyCount = allRoutes.filter(r => r.health === 'healthy').length;
      const totalWithMethods = allRoutes.filter(r => r.methods?.length > 0).length;
      q('rtHealthy').textContent = `${healthyCount}/${totalWithMethods}`;
      const healthyKpi = q('rtHealthy')?.closest('.ov-kpi');
      if (healthyKpi) {
        if (healthyCount < totalWithMethods * 0.5) healthyKpi.dataset.accent = 'danger';
        else if (healthyCount < totalWithMethods) healthyKpi.dataset.accent = 'warning';
        else healthyKpi.dataset.accent = 'success';
      }

      q('rtLatency').textContent = rtFormatLatency(st?.global_avg_latency_ms);

      const upPct = st?.uptime_healthy_pct ?? 0;
      q('rtUptime').textContent = `${upPct}%`;
      requestAnimationFrame(() => { const ub = q('rtUptimeBar'); if (ub) ub.style.width = upPct + '%'; });
      const uptimeKpi = q('rtUptime')?.closest('.ov-kpi');
      if (uptimeKpi) {
        if (upPct < 50) uptimeKpi.dataset.accent = 'danger';
        else if (upPct < 80) uptimeKpi.dataset.accent = 'warning';
        else uptimeKpi.dataset.accent = 'success';
      }

      q('rtAlerts').textContent = al?.active ?? st?.alerts?.active ?? 0;
      const alertKpi = q('rtAlerts')?.closest('.ov-kpi');
      if (alertKpi) {
        const ac = al?.active ?? 0;
        if (ac > 0 && (al?.alerts || []).some(a => a.severity === 'critical' && !a.resolved)) alertKpi.dataset.accent = 'danger';
        else if (ac > 0) alertKpi.dataset.accent = 'warning';
        else alertKpi.dataset.accent = 'success';
      }

      q('rtHealing').textContent = hl?.total ?? st?.self_healing?.events ?? 0;

      /* ── Render panels ── */
      rtRenderChartHealth(rt);
      rtRenderChartErrors(st);
      rtRenderChartLatency(tp);
      rtRenderChartTraffic(tp);
      rtRenderWatchdog(st);
      rtRenderSysSummary(st, tp);
      rtRenderTopology(tp);
      rtRenderAlerts(al);
      rtRenderRoutesTable(rt);
      rtRenderHealLog(hl);
      rtRenderCircuitBreakers(cb);
      rtRenderShorthand(mp);

    } catch (error) {
      showMessage(`Route Control errore: ${String(error)}`, 'warning');
      ['rtChartHealth','rtChartErrors','rtChartLatency','rtChartTraffic','rtSysSummary','rtTopologyPanel','rtWatchdogPanel','rtAlertsPanel','rtRoutesTablePanel','rtHealPanel','rtCircuitPanel','rtShorthandPanel'].forEach(id => {
        const p = q(id);
        if (p) p.innerHTML = `<div class="ov-empty"><i class="bi bi-exclamation-triangle"></i><span class="ov-empty-text">Errore: ${esc(String(error))}</span></div>`;
      });
    }
  };

  const rtToggleAutoRefresh = (enabled) => {
    if (rtAutoRefreshTimer) { clearInterval(rtAutoRefreshTimer); rtAutoRefreshTimer = null; }
    if (enabled) {
      rtAutoRefreshTimer = setInterval(() => {
        if (state.currentView === 'routes') loadRoutesPanel();
      }, 15000);
    }
  };

  const applyModule = async (moduleId) => {
    if (!moduleId) return;
    try {
      await TPL.jsonFetch('/api/modules/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Confirm': 'YES' },
        body: JSON.stringify({ modules: [moduleId] })
      });
      showMessage(`${TPL.t('btn.apply','Apply')}: ${moduleId}`, 'success');
      await loadModules();
    } catch (error) {
      showMessage(`${TPL.t('msg.error','Errore')}: ${String(error)}`, 'danger');
    }
  };

  const resetModule = async (moduleId) => {
    if (!moduleId) return;
    try {
      // Note: POST /modules/reset resets ALL modules state (no per-module reset API)
      await TPL.jsonFetch('/api/modules/reset', {
        method: 'POST',
        headers: { 'X-Confirm': 'YES' },
        body: JSON.stringify({ modules: [moduleId] })
      });
      showMessage(`${TPL.t('btn.reset','Reset')}: ${moduleId}`, 'success');
      await loadModules();
    } catch (error) {
      showMessage(`${TPL.t('msg.error','Errore')}: ${String(error)}`, 'danger');
    }
  };

  // -----------------------------------------------------------------------
  // AI CENTER  v2
  // -----------------------------------------------------------------------

  /* ── AI Center state ── */
  let _aiAutoTimer = null;
  let _aiCache = {};

  /* helpers */
  const _ai2Set = (id, v) => { const el = q(id); if (el) el.textContent = v; };
  const _ai2Html = (id, h) => { const el = q(id); if (el) el.innerHTML = h; };
  const _ai2Empty = (icon, msg) =>
    `<div class="ai2-empty"><i class="bi bi-${icon}"></i><span>${msg}</span></div>`;

  /* ── Main loader ── */
  const loadAICenter = async () => {
    const dot = q('ai2Dot');
    const stxt = q('ai2StatusText');
    if (dot) dot.className = 'ai2-dot';
    if (stxt) stxt.textContent = 'Aggiornamento…';

    try {
      const [data, logData, monData, diagData, capData] = await Promise.all([
        TPL.jsonFetch('/api/ai/dashboard').catch(() => ({})),
        TPL.jsonFetch('/api/ai/summary').catch(e => { console.warn('ai/summary:', e.message); return null; }),
        TPL.jsonFetch('/api/monitoring/summary').catch(e => { console.warn('monitoring/summary:', e.message); return null; }),
        TPL.jsonFetch('/api/diagnosis/ai-analysis').catch(e => { console.warn('diagnosis/ai-analysis:', e.message); return null; }),
        TPL.jsonFetch('/api/resilience/ai-predictions').catch(e => { console.warn('resilience/ai-predictions:', e.message); return null; }),
      ]);
      _aiCache = { data, logData, monData, diagData, capData };

      /* ── Health ring — r=50, C=2π×50≈314 ── */
      const score = data.health?.score ?? 0;
      const grade = data.health?.grade ?? '';
      const offset = 314 * (1 - score / 100);
      const sColor = score >= 85 ? '#22c55e' : score >= 70 ? '#3b82f6' : score >= 40 ? '#f59e0b' : '#ef4444';
      const arc = q('ai2Arc');
      if (arc) { arc.style.strokeDashoffset = offset; arc.style.stroke = sColor; }
      _ai2Set('ai2Score', score);
      _ai2Set('ai2Grade', grade);

      /* Status dot */
      const statusText = score >= 85 ? 'Piattaforma sana' : score >= 70 ? 'Alcuni avvisi' : score >= 40 ? 'Stato degradato' : 'Attenzione critica';
      if (dot) dot.className = 'ai2-dot' + (score < 40 ? ' ai2-dot--err' : score < 70 ? ' ai2-dot--warn' : '');
      if (stxt) stxt.textContent = `Engine attivo — ${statusText}`;

      /* ── KPIs ── */
      const threatCount = data.threats?.threats?.length ?? 0;
      const anomCount   = data.behavior?.anomalies?.length ?? 0;
      const alertCount  = data.alerts?.total_alerts ?? 0;
      const riskScore   = data.risk?.overall_risk ?? 0;
      const dedupPct    = ((data.alerts?.dedup_ratio || 0) * 100).toFixed(0);
      _ai2Set('ai2Threats', threatCount);
      _ai2Set('ai2Risk', riskScore);
      _ai2Set('ai2Alerts', alertCount);
      _ai2Set('ai2Anomalies', anomCount);

      /* ── Summary banner ── */
      const sumEl = q('ai2Summary');
      if (sumEl) {
        const txt = data.health?.summary || logData?.summary || 'Tutti i sistemi operativi. Nessuna anomalia significativa rilevata.';
        sumEl.innerHTML = `<i class="bi bi-cpu ai2-summary-ico"></i><span>${esc(txt)}</span>`;
      }

      /* Threat badge */
      _ai2Set('ai2ThreatBadge', threatCount);
      /* Alert meta */
      const am = q('ai2AlertMeta');
      if (am) am.textContent = `Raw ${data.alerts?.total_raw || 0} → ${alertCount} (−${dedupPct}%)`;

      /* ── Security tab ── */
      _ai2RenderThreats(data.threats?.threats || []);
      _ai2RenderRisk(data.risk);
      _ai2RenderAlerts(data.alerts);
      _ai2RenderBehavior(data.behavior?.anomalies || []);
      _ai2RenderRecs(data.recommendations || []);

      /* ── Ops tab ── */
      _ai2RenderMonitor(monData);
      _ai2RenderGauges(monData);
      _ai2RenderLogAI(logData);
      _ai2RenderLogSources(logData);
      _ai2RenderDiagnosis(diagData);
      _ai2RenderTimeline(data.timeline?.recent_incidents || []);
      _ai2RenderCapacity(capData);

    } catch (err) {
      if (dot) dot.className = 'ai2-dot ai2-dot--err';
      if (stxt) stxt.textContent = 'Errore';
      showMessage('Errore caricamento AI Center: ' + String(err), 'danger');
    }
  };

  /* ══════════════════════════════════════════════════════════════
     Sub-renderers — Security tab
     ══════════════════════════════════════════════════════════════ */

  const _ai2RenderThreats = (threats) => {
    const p = q('ai2ThreatList');
    if (!p) return;
    if (!threats.length) { p.innerHTML = _ai2Empty('shield-check', 'Nessuna minaccia rilevata'); return; }
    p.innerHTML = threats.map(t => {
      const sev = t.severity || 'low';
      return `<div class="ai2-item ai2-item--${sev}">
        <span class="ai2-sev ai2-sev--${sev}">${sev.toUpperCase()}</span>
        <div class="ai2-item-body">
          <div class="ai2-item-title">${esc(t.type || t.title || '')}</div>
          <div class="ai2-item-desc">${esc(t.description || '')}</div>
          ${t.evidence ? `<div class="ai2-item-tag"><i class="bi bi-info-circle me-1"></i>${esc(t.evidence)}</div>` : ''}
          ${t.recommendation ? `<div class="ai2-item-sub"><i class="bi bi-arrow-right-circle me-1"></i>${esc(t.recommendation)}</div>` : ''}
        </div>
      </div>`;
    }).join('');
  };

  const _ai2RenderRisk = (risk) => {
    const p = q('ai2RiskPanel');
    if (!p || !risk) return;
    const dims = risk.dimensions || {};
    const rl = risk.risk_level || 'low';
    const tagBg = rl === 'critical' ? '#fef2f2' : rl === 'high' ? '#fffbeb' : rl === 'medium' ? '#eff6ff' : '#f0fdf4';
    const tagClr = rl === 'critical' ? '#dc2626' : rl === 'high' ? '#d97706' : rl === 'medium' ? '#2563eb' : '#16a34a';
    let html = `<div class="ai2-risk-tag" style="background:${tagBg};color:${tagClr}">
      <i class="bi bi-shield-fill-exclamation"></i> ${risk.overall_risk ?? 0}/100 — ${rl.toUpperCase()}
    </div>`;
    html += Object.entries(dims).map(([key, d]) => {
      const c = d.status === 'critical' ? '#ef4444' : d.status === 'warning' ? '#f59e0b' : '#22c55e';
      const pct = Math.min(100, d.score);
      const label = key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ');
      return `<div class="ai2-risk-row">
        <div class="ai2-risk-label"><span class="ai2-risk-name">${label}</span><span class="ai2-risk-val" style="color:${c}">${d.score}</span></div>
        <div class="ai2-bar"><div class="ai2-bar-fill" style="width:${pct}%;background:${c}"></div></div>
      </div>`;
    }).join('');
    p.innerHTML = html;
  };

  const _ai2RenderAlerts = (alerts) => {
    const p = q('ai2AlertList');
    if (!p) return;
    const list = alerts?.alerts || [];
    if (!list.length) { p.innerHTML = _ai2Empty('bell-slash', 'Nessun alert attivo'); return; }
    p.innerHTML = list.slice(0, 20).map(a => {
      const sev = a.severity || 'medium';
      return `<div class="ai2-item ai2-item--${sev}">
        <span class="ai2-sev ai2-sev--${sev}">${a.count || 1}×</span>
        <div class="ai2-item-body">
          <div class="ai2-item-title">${esc(a.source || '')}${a.event ? ': ' + esc(a.event) : ''}</div>
        </div>
      </div>`;
    }).join('');
  };

  const _ai2RenderBehavior = (anomalies) => {
    const p = q('ai2BehaviorList');
    if (!p) return;
    if (!anomalies.length) { p.innerHTML = _ai2Empty('people-fill', 'Comportamento utenti nella norma'); return; }
    p.innerHTML = anomalies.map(a => {
      const sev = a.severity || 'medium';
      const icon = sev === 'high' ? 'person-x-fill' : sev === 'medium' ? 'person-exclamation' : 'person-check';
      return `<div class="ai2-item ai2-item--${sev}">
        <i class="bi bi-${icon}" style="flex-shrink:0;font-size:1rem;opacity:.7"></i>
        <div class="ai2-item-body">
          <div class="ai2-item-desc">${esc(a.description)}</div>
        </div>
        <span class="ai2-sev ai2-sev--${sev}">${sev}</span>
      </div>`;
    }).join('');
  };

  const _ai2RenderRecs = (recs) => {
    const p = q('ai2RecsList');
    if (!p) return;
    if (!recs.length) { p.innerHTML = _ai2Empty('hand-thumbs-up-fill', 'Nessuna raccomandazione — tutto ok'); return; }
    p.innerHTML = recs.map(r => {
      const pr = r.priority || 'low';
      return `<div class="ai2-item ai2-item--${pr}">
        <span class="ai2-sev ai2-sev--${pr === 'critical' ? 'critical' : pr === 'high' ? 'high' : 'medium'}">${pr.toUpperCase()}</span>
        <div class="ai2-item-body">
          <div class="ai2-item-title">${esc(r.title || '')}</div>
          <div class="ai2-item-desc">${esc(r.description || '')}</div>
        </div>
      </div>`;
    }).join('');
  };

  /* ══════════════════════════════════════════════════════════════
     Sub-renderers — Ops tab
     ══════════════════════════════════════════════════════════════ */

  const _ai2RenderMonitor = (monData) => {
    const p = q('ai2MonitorPanel');
    if (!p) return;
    if (!monData) { p.innerHTML = _ai2Empty('activity', 'Monitoring AI non disponibile'); return; }
    const hs = monData.health_score ?? 0;
    const hColor = hs >= 80 ? '#22c55e' : hs >= 60 ? '#f59e0b' : '#ef4444';
    p.innerHTML = `
      <p style="font-size:.85rem;line-height:1.5;margin:0 0 .6rem">${esc(monData.summary || 'N/A')}</p>
      <div class="ai2-stats">
        <div class="ai2-stat"><div class="ai2-stat-num" style="color:${hColor}">${hs}/100</div><div class="ai2-stat-lbl">Health</div></div>
        <div class="ai2-stat"><div class="ai2-stat-num">${monData.issues_count ?? 0}</div><div class="ai2-stat-lbl">Problemi</div></div>
        <div class="ai2-stat"><div class="ai2-stat-num" style="text-transform:capitalize">${monData.status ?? '—'}</div><div class="ai2-stat-lbl">Stato</div></div>
      </div>`;
  };

  const _ai2RenderGauges = (monData) => {
    const p = q('ai2GaugesPanel');
    if (!p) return;
    if (!monData) { p.innerHTML = _ai2Empty('speedometer', 'Dati risorse non disponibili'); return; }
    const metrics = monData.metrics || monData.resources || {};
    const items = [];
    const add = (label, val) => {
      if (val == null) return;
      const pct = Math.min(100, Math.max(0, typeof val === 'number' ? val : 0));
      const pos = pct <= 60 ? '0%' : pct <= 80 ? '50%' : '100%';
      items.push(`<div class="ai2-gauge">
        <span class="ai2-gauge-name">${label}</span>
        <div class="ai2-gauge-track"><div class="ai2-gauge-bar" style="width:${pct}%;background-position:${pos} 0"></div></div>
        <span class="ai2-gauge-pct">${pct.toFixed(1)}%</span>
      </div>`);
    };
    add('CPU', metrics.cpu_percent ?? metrics.cpu);
    add('RAM', metrics.memory_percent ?? metrics.memory);
    add('Disk', metrics.disk_percent ?? metrics.disk);
    if (metrics.inode_percent) add('Inode', metrics.inode_percent);
    p.innerHTML = items.length ? items.join('') : '<div style="text-align:center;color:#94a3b8;font-size:.8rem">Metriche non disponibili</div>';
  };

  const _ai2RenderLogAI = (logData) => {
    const p = q('ai2LogPanel');
    if (!p) return;
    if (!logData) { p.innerHTML = _ai2Empty('file-earmark-x', 'Analisi log AI non disponibile'); return; }
    p.innerHTML = `
      <p style="font-size:.85rem;line-height:1.5;margin:0 0 .6rem">${esc(logData.summary || 'N/A')}</p>
      <div class="ai2-stats">
        <div class="ai2-stat"><div class="ai2-stat-num" style="color:${(logData.severity_score ?? 0) > 50 ? '#dc2626' : '#16a34a'}">${logData.severity_score ?? '—'}</div><div class="ai2-stat-lbl">Gravità</div></div>
        <div class="ai2-stat"><div class="ai2-stat-num">${logData.total_anomalies ?? '—'}</div><div class="ai2-stat-lbl">Anomalie</div></div>
        <div class="ai2-stat"><div class="ai2-stat-num">${logData.total_events ?? '—'}</div><div class="ai2-stat-lbl">Tot. eventi</div></div>
      </div>`;
  };

  const _ai2RenderLogSources = (logData) => {
    const p = q('ai2LogSourcesPanel');
    if (!p) return;
    if (!logData) { p.innerHTML = ''; return; }
    const sources = logData.sources || {};
    const rows = Object.entries(sources).map(([s, info]) => {
      const total = info.total_events || info.event_count || 0;
      return `<div style="display:flex;justify-content:space-between;align-items:center;padding:.35rem 0;border-bottom:1px solid #f1f5f9">
        <span style="font-size:.78rem;font-weight:600">${esc(s)}</span>
        <span style="font-size:.7rem;background:#e2e8f0;padding:.1rem .45rem;border-radius:1rem;font-weight:700">${total}</span>
      </div>`;
    }).join('');
    p.innerHTML = rows || '<div style="text-align:center;color:#94a3b8;font-size:.8rem">Nessun dato sorgente</div>';
  };

  const _ai2RenderDiagnosis = (diagData) => {
    const p = q('ai2DiagPanel');
    if (!p) return;
    if (!diagData || !diagData.findings) { p.innerHTML = _ai2Empty('search', 'Diagnosi AI non disponibile'); return; }
    const findings = diagData.findings || [];
    if (!findings.length) { p.innerHTML = _ai2Empty('check-circle-fill', 'Nessun problema rilevato'); return; }
    p.innerHTML = findings.slice(0, 15).map(f => {
      const sev = f.severity || 'info';
      const cls = sev === 'critical' || sev === 'high' ? 'ai2-diag--err' : sev === 'medium' ? 'ai2-diag--warn' : 'ai2-diag--ok';
      const icon = sev === 'critical' || sev === 'high' ? 'exclamation-triangle-fill' : sev === 'medium' ? 'exclamation-circle' : 'check-circle';
      return `<div class="ai2-diag ${cls}">
        <div class="ai2-diag-ico"><i class="bi bi-${icon}"></i></div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;font-size:.8rem">${esc(f.title || f.type || '')}</div>
          <div style="font-size:.75rem;color:#64748b">${esc(f.description || f.detail || '')}</div>
        </div>
      </div>`;
    }).join('');
  };

  const _ai2RenderTimeline = (incidents) => {
    const p = q('ai2TimelinePanel');
    if (!p) return;
    if (!incidents.length) { p.innerHTML = _ai2Empty('clock', 'Nessun incidente recente'); return; }
    p.innerHTML = incidents.slice(0, 12).map(inc => {
      const sev = inc.severity || 'info';
      const dotCls = sev === 'critical' || sev === 'failed' ? 'ai2-tl-dot--crit' : sev === 'high' || sev === 'blocked' ? 'ai2-tl-dot--high' : sev === 'error' ? 'ai2-tl-dot--err' : '';
      return `<div class="ai2-tl">
        <div class="ai2-tl-dot ${dotCls}"></div>
        <div class="ai2-tl-body">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-weight:700;font-size:.78rem">${inc.event_count || 0} eventi — ${(inc.sources || []).join(', ') || 'unknown'}</span>
            <span style="font-size:.65rem;background:#e2e8f0;padding:.1rem .4rem;border-radius:1rem">${inc.duration_seconds || 0}s</span>
          </div>
          <div style="font-size:.7rem;color:#94a3b8;margin-top:.1rem">${fmtDate(inc.start_ts)}</div>
        </div>
      </div>`;
    }).join('');
  };

  const _ai2RenderCapacity = (capData) => {
    const p = q('ai2CapPanel');
    if (!p) return;
    if (!capData) { p.innerHTML = _ai2Empty('hdd-stack', 'Previsione capacità non disponibile'); return; }
    let html = '';
    const forecasts = capData.capacity_forecasts || capData.forecasts || [];
    forecasts.forEach(fc => {
      const trend = fc.trend || 'stable';
      const trendCls = trend.includes('ris') || trend.includes('up') ? 'ai2-cap-trend--up' : trend.includes('fall') || trend.includes('down') ? 'ai2-cap-trend--down' : 'ai2-cap-trend--ok';
      html += `<div class="ai2-cap">
        <div class="ai2-cap-top">
          <span class="ai2-cap-name"><i class="bi bi-hdd me-1"></i>${esc(fc.metric || fc.resource || '')}</span>
          <span class="ai2-cap-trend ${trendCls}">${esc(trend)}</span>
        </div>
        <div style="font-size:.78rem;color:#64748b">Attuale: <strong>${typeof fc.current === 'number' ? fc.current.toFixed(1) + '%' : fc.current || '—'}</strong></div>
        ${fc.predictions || fc.forecast ? (() => {
          const pr = fc.predictions || fc.forecast || {};
          return `<div class="ai2-cap-grid">
            ${pr['1h'] != null ? `<div class="ai2-cap-fc"><div class="ai2-cap-fc-num">${typeof pr['1h'] === 'number' ? pr['1h'].toFixed(1) + '%' : pr['1h']}</div><div class="ai2-cap-fc-lbl">+1 ora</div></div>` : ''}
            ${pr['6h'] != null ? `<div class="ai2-cap-fc"><div class="ai2-cap-fc-num">${typeof pr['6h'] === 'number' ? pr['6h'].toFixed(1) + '%' : pr['6h']}</div><div class="ai2-cap-fc-lbl">+6 ore</div></div>` : ''}
            ${pr['24h'] != null ? `<div class="ai2-cap-fc"><div class="ai2-cap-fc-num">${typeof pr['24h'] === 'number' ? pr['24h'].toFixed(1) + '%' : pr['24h']}</div><div class="ai2-cap-fc-lbl">+24 ore</div></div>` : ''}
          </div>`;
        })() : ''}
      </div>`;
    });
    const patterns = capData.failure_patterns || [];
    if (patterns.length) {
      html += `<div style="font-weight:700;font-size:.82rem;margin:.75rem 0 .4rem"><i class="bi bi-exclamation-diamond me-1"></i>Pattern di guasto</div>`;
      html += patterns.map(fp => {
        const sev = fp.severity || 'low';
        return `<div class="ai2-item ai2-item--${sev}" style="margin-bottom:.4rem">
          <span class="ai2-sev ai2-sev--${sev}">${sev.toUpperCase()}</span>
          <div class="ai2-item-body">
            <div class="ai2-item-title">${esc(fp.pattern || fp.type || '')}</div>
            <div class="ai2-item-desc">${esc(fp.description || '')}</div>
          </div>
        </div>`;
      }).join('');
    }
    p.innerHTML = html || _ai2Empty('hdd-stack', 'Nessun dato capacità disponibile');
  };

  /* ══════════════════════════════════════════════════════════════
     Tab switching (3 macro-tabs)
     ══════════════════════════════════════════════════════════════ */

  const _ai2InitTabs = () => {
    const nav = q('ai2Tabs');
    if (!nav) return;
    nav.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.ai2-tab');
      if (!btn) return;
      ev.preventDefault();
      nav.querySelectorAll('.ai2-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.ai2-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const pane = document.getElementById('ai2Pane-' + btn.dataset.tab);
      if (pane) pane.classList.add('active');
    });
  };

  /* ── Auto-refresh ── */
  const _ai2ToggleAutoRefresh = (on) => {
    if (_aiAutoTimer) { clearInterval(_aiAutoTimer); _aiAutoTimer = null; }
    if (on) _aiAutoTimer = setInterval(loadAICenter, 30000);
  };

  /* ══════════════════════════════════════════════════════════════
     Advanced AI Analysis
     ══════════════════════════════════════════════════════════════ */

  const loadAdvancedAI = async () => {
    const set = (id, h) => _ai2Html(id, h);
    const empty = (icon, msg) => _ai2Empty(icon, msg);

    set('ai2AdvReport', '<div style="text-align:center;padding:1.5rem 0"><div class="spinner-border text-primary" role="status"></div><div style="font-size:.82rem;margin-top:.5rem;color:#64748b">Analisi in corso — 9 algoritmi AI…</div></div>');

    try {
      const [report, markov, bayesian, entropy, ewma, isolation, knn, corr, decomp] = await Promise.all([
        TPL.jsonFetch('/api/ai/advanced/full-report').catch(e => { console.warn('ai/full-report:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/markov-prediction').catch(e => { console.warn('ai/markov:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/bayesian-risk').catch(e => { console.warn('ai/bayesian:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/entropy-analysis').catch(e => { console.warn('ai/entropy:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/ewma-monitor').catch(e => { console.warn('ai/ewma:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/anomaly-scores').catch(e => { console.warn('ai/anomaly:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/pattern-match').catch(e => { console.warn('ai/pattern:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/correlation-matrix').catch(e => { console.warn('ai/correlation:', e.message); return null; }),
        TPL.jsonFetch('/api/ai/advanced/time-decomposition').catch(e => { console.warn('ai/decomp:', e.message); return null; }),
      ]);

      /* ── Full Report ── */
      if (report) {
        const s = report.composite_threat_score || 0;
        const rl = report.risk_level || 'low';
        const rlClr = s > 60 ? '#ef4444' : s > 40 ? '#f59e0b' : s > 20 ? '#3b82f6' : '#22c55e';
        const algos = report.algorithms || {};
        let html = `<div style="display:flex;align-items:center;gap:1rem;margin-bottom:.75rem">
          <div style="position:relative;display:inline-flex;align-items:center;justify-content:center">
            <svg viewBox="0 0 100 100" width="80" height="80">
              <circle cx="50" cy="50" r="42" fill="none" stroke="#e2e8f0" stroke-width="8"/>
              <circle cx="50" cy="50" r="42" fill="none" stroke="${rlClr}" stroke-width="8"
                      stroke-dasharray="264" stroke-dashoffset="${264*(1-s/100)}" stroke-linecap="round"
                      transform="rotate(-90 50 50)" class="ai2-arc"/>
            </svg>
            <div style="position:absolute;text-align:center">
              <div style="font-size:1.5rem;font-weight:800;color:#1e293b;line-height:1">${s}</div>
              <div style="font-size:.6rem;font-weight:700;color:${rlClr};text-transform:uppercase">${rl}</div>
            </div>
          </div>
          <div style="flex:1;min-width:0">
            <p style="font-size:.85rem;margin:0 0 .35rem;line-height:1.4">${esc(report.summary || '')}</p>
            <span style="display:inline-flex;align-items:center;gap:.3rem;font-size:.7rem;font-weight:700;color:${rlClr};background:${rlClr}15;padding:.15rem .55rem;border-radius:1rem">${rl.toUpperCase()} — Threat Score ${s}/100</span>
          </div>
        </div>`;
        html += '<div class="ai2-stats" style="grid-template-columns:repeat(4,1fr)">';
        const algoInfo = [
          ['Markov', algos.markov, a => `${a.predictions_count||0} pred.`],
          ['Isolation', algos.isolation, a => `${a.anomaly_count||0} anom.`],
          ['Entropia', algos.entropy, a => `${a.alerts||0} alert`],
          ['EWMA', algos.ewma, a => a.in_control ? '✓ ctrl' : `✗ ${a.violations||0}v`],
          ['Bayesiano', algos.bayesian, a => `${((a.overall_risk||0)*100).toFixed(0)}%`],
          ['KNN', algos.knn, a => a.pattern || '?'],
          ['Decomp.', algos.decomposition, a => a.trend || '?'],
          ['Corr.', algos.correlation, a => `${a.insights_count||0} ins.`],
        ];
        algoInfo.forEach(([label, obj, fn]) => {
          const a = obj || {};
          html += `<div class="ai2-stat"><div class="ai2-stat-num" style="font-size:.95rem">${fn(a)}</div><div class="ai2-stat-lbl">${label}</div></div>`;
        });
        html += '</div>';
        set('ai2AdvReport', html);
      }

      /* ── Markov ── */
      if (markov && markov.predictions) {
        const preds = markov.predictions || [];
        const chains = markov.attack_chains || [];
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(markov.description || '')}</div>`;
        if (preds.length) {
          html += '<div style="font-weight:700;font-size:.8rem;margin-bottom:.35rem"><i class="bi bi-forward me-1"></i>Prossimi eventi predetti</div>';
          html += preds.map(p => {
            const w = Math.round(p.probability * 100);
            return `<div class="ai2-item ai2-item--${p.severity||'low'}" style="margin-bottom:.3rem">
              <span class="ai2-sev ai2-sev--${p.severity||'medium'}">${w}%</span>
              <div class="ai2-item-body"><div class="ai2-item-title">${esc(p.predicted_event)}</div>
              <div class="ai2-item-desc">${esc(p.description)}</div></div></div>`;
          }).join('');
        }
        if (chains.length) {
          html += '<div style="font-weight:700;font-size:.8rem;margin:.6rem 0 .35rem"><i class="bi bi-diagram-3 me-1"></i>Catene d\'attacco</div>';
          html += chains.slice(0, 5).map(c => {
            return `<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.25rem;font-size:.78rem">
              <span class="ai2-sev ai2-sev--${c.risk==='critical'?'critical':c.risk==='high'?'high':'medium'}">${(c.probability*100).toFixed(1)}%</span>
              <span>${c.chain.map(s => `<code>${esc(s)}</code>`).join(' → ')}</span></div>`;
          }).join('');
        }
        if (!preds.length && !chains.length) html += empty('shield-check', 'Nessuna catena di attacco');
        set('ai2AdvMarkov', html);
      } else {
        set('ai2AdvMarkov', empty('diagram-3', 'Dati insufficienti per Markov'));
      }

      /* ── Bayesian ── */
      if (bayesian && bayesian.categories) {
        const obr = bayesian.overall_bayesian_risk || 0;
        const bc = obr > 0.3 ? '#dc2626' : obr > 0.15 ? '#d97706' : '#16a34a';
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(bayesian.description || '')}</div>`;
        html += `<div class="ai2-risk-tag" style="background:${bc}12;color:${bc}"><i class="bi bi-pie-chart"></i> Rischio Bayesiano: ${(obr*100).toFixed(1)}%</div>`;
        for (const [cat, info] of Object.entries(bayesian.categories)) {
          const pp = info.posterior_probability;
          const c = info.risk_level === 'critical' ? '#ef4444' : info.risk_level === 'high' ? '#f59e0b' : info.risk_level === 'medium' ? '#3b82f6' : '#22c55e';
          html += `<div class="ai2-risk-row">
            <div class="ai2-risk-label"><span class="ai2-risk-name">${cat.replace(/_/g, ' ')}</span><span class="ai2-risk-val" style="color:${c}">${(pp*100).toFixed(1)}%</span></div>
            <div class="ai2-bar"><div class="ai2-bar-fill" style="width:${Math.min(100,pp*200)}%;background:${c}"></div></div>
            <div style="font-size:.62rem;color:#94a3b8">CI 95%: ${(info.credible_interval[0]*100).toFixed(1)}%–${(info.credible_interval[1]*100).toFixed(1)}% | BF=${info.bayes_factor}x | ${info.evidence_count}/${info.total_observations}</div>
          </div>`;
        }
        set('ai2AdvBayes', html);
      }

      /* ── Entropy ── */
      if (entropy) {
        const st = entropy.stats || {};
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(entropy.description || '')}</div>`;
        html += `<div class="ai2-stats" style="margin-bottom:.6rem">
          <div class="ai2-stat"><div class="ai2-stat-num">${st.mean_entropy?.toFixed(2) ?? '—'}</div><div class="ai2-stat-lbl">H medio</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${st.current_entropy?.toFixed(2) ?? '—'}</div><div class="ai2-stat-lbl">H attuale</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num" style="color:${(entropy.total_alerts||0)>0?'#dc2626':'#16a34a'}">${entropy.total_alerts || 0}</div><div class="ai2-stat-lbl">Anomalie</div></div>
        </div>`;
        const alerts = entropy.alerts || [];
        if (alerts.length) {
          html += alerts.slice(0, 8).map(a => `<div class="ai2-item ai2-item--${a.severity||'medium'}" style="margin-bottom:.3rem">
            <i class="bi bi-${a.type==='entropy_drop'?'arrow-down-circle':'arrow-up-circle'}" style="flex-shrink:0;opacity:.7"></i>
            <div class="ai2-item-body"><div class="ai2-item-desc">${esc(a.description)}</div></div></div>`).join('');
        } else {
          html += '<div style="color:#16a34a;font-size:.8rem"><i class="bi bi-check-circle me-1"></i>Entropia stabile — nessuna anomalia</div>';
        }
        set('ai2AdvEntropy', html);
      }

      /* ── EWMA ── */
      if (ewma) {
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(ewma.description || '')}</div>`;
        html += `<div class="ai2-stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:.6rem">
          <div class="ai2-stat"><div class="ai2-stat-num">${ewma.current_ewma ?? '—'}</div><div class="ai2-stat-lbl">EWMA</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${ewma.target_mean ?? '—'}</div><div class="ai2-stat-lbl">Target μ</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${ewma.current_ucl ?? '—'}</div><div class="ai2-stat-lbl">UCL</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num" style="color:${ewma.in_control?'#16a34a':'#dc2626'}">${ewma.in_control ? '✓' : '✗'}</div><div class="ai2-stat-lbl">Control</div></div>
        </div>`;
        const violations = ewma.violations || [];
        if (violations.length) {
          html += `<div style="font-weight:700;font-size:.8rem;margin-bottom:.35rem"><i class="bi bi-exclamation-diamond me-1"></i>${violations.length} Violazioni</div>`;
          html += violations.slice(-8).map(v => `<div class="ai2-item ai2-item--${v.severity||'medium'}" style="margin-bottom:.25rem">
            <span class="ai2-sev ai2-sev--${v.type==='upper_violation'?'high':'medium'}">${v.type==='upper_violation'?'↑':'↓'}</span>
            <div class="ai2-item-body"><div class="ai2-item-desc">${esc(v.description)}</div></div></div>`).join('');
        } else {
          html += '<div style="color:#16a34a;font-size:.8rem"><i class="bi bi-check-circle me-1"></i>Processo sotto controllo</div>';
        }
        set('ai2AdvEwma', html);
      }

      /* ── Isolation Scores ── */
      if (isolation && isolation.entities) {
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(isolation.description || '')}</div>`;
        const ents = isolation.entities || [];
        if (ents.length) {
          html += ents.slice(0, 12).map(e => {
            const lvl = e.anomaly_level || 'normal';
            const pct = Math.round(e.isolation_score * 100);
            const cls = e.is_anomaly ? (lvl === 'critical' ? 'ai2-item--critical' : 'ai2-item--high') : '';
            return `<div class="ai2-item ${cls}" style="margin-bottom:.25rem">
              <span class="ai2-sev ai2-sev--${lvl==='critical'?'critical':lvl==='high'?'high':'medium'}">${pct}%</span>
              <div class="ai2-item-body">
                <div class="ai2-item-title">${esc(e.entity)}</div>
                <div class="ai2-item-desc">Top deviation: ${esc(e.top_deviation || '?')}</div>
              </div>
              <i class="bi bi-${e.is_anomaly?'exclamation-triangle text-danger':'check text-success'}" style="flex-shrink:0"></i>
            </div>`;
          }).join('');
        } else {
          html += empty('bullseye', 'Nessuna entità analizzata');
        }
        set('ai2AdvIsolation', html);
      }

      /* ── KNN Pattern ── */
      if (knn) {
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(knn.description || '')}</div>`;
        const cls = knn.pattern_classification || 'unknown';
        const isAnom = cls === 'anomalous';
        html += `<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.6rem">
          <span style="font-size:.78rem;font-weight:700;padding:.25rem .6rem;border-radius:.3rem;color:#fff;background:${isAnom?'#dc2626':'#16a34a'}">${isAnom ? '⚠ Anomalo' : '✓ Normale'}</span>
          <span style="font-size:.75rem;color:#64748b">Rapporto anomali: ${((knn.anomalous_neighbor_ratio||0)*100).toFixed(0)}%</span>
        </div>`;
        const neighbors = knn.neighbors || [];
        if (neighbors.length) {
          html += '<div style="font-weight:700;font-size:.8rem;margin-bottom:.35rem"><i class="bi bi-grid-3x3-gap me-1"></i>Finestre più simili</div>';
          html += neighbors.map(n => `<div style="display:flex;justify-content:space-between;align-items:center;padding:.3rem 0;border-bottom:1px solid #f1f5f9;font-size:.78rem">
            <span>Finestra #${n.window_index} — ${fmtDate(n.start_ts)}</span>
            <span style="background:#e2e8f0;padding:.1rem .4rem;border-radius:1rem;font-weight:700;font-size:.7rem">${(n.similarity*100).toFixed(1)}%</span>
          </div>`).join('');
        }
        set('ai2AdvKnn', html);
      }

      /* ── Correlation Matrix ── */
      if (corr && corr.matrix) {
        const sources = corr.sources || [];
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(corr.description || '')}</div>`;
        if (sources.length) {
          html += '<div class="table-responsive"><table class="table table-sm table-bordered mb-2" style="font-size:.72rem"><thead><tr><th></th>';
          sources.forEach(s => html += `<th class="text-center">${esc(s)}</th>`);
          html += '</tr></thead><tbody>';
          sources.forEach(s1 => {
            html += `<tr><th>${esc(s1)}</th>`;
            sources.forEach(s2 => {
              const r = corr.matrix[s1]?.[s2] ?? 0;
              const bg = r > 0.7 ? 'rgba(239,68,68,.2)' : r > 0.4 ? 'rgba(245,158,11,.15)' : r > -0.1 ? '' : 'rgba(59,130,246,.1)';
              html += `<td class="text-center" style="background:${bg}">${r.toFixed(2)}</td>`;
            });
            html += '</tr>';
          });
          html += '</tbody></table></div>';
        }
        const ins = corr.insights || [];
        if (ins.length) {
          html += '<div style="font-weight:700;font-size:.8rem;margin-bottom:.35rem">Correlazioni significative</div>';
          html += ins.slice(0, 5).map(i => `<div style="font-size:.78rem;margin-bottom:.2rem"><i class="bi bi-link-45deg me-1" style="color:#6366f1"></i>${esc(i.description)}</div>`).join('');
        }
        set('ai2AdvCorr', html);
      }

      /* ── Decomposition ── */
      if (decomp) {
        const st = decomp.stats || {};
        let html = `<div style="font-size:.78rem;color:#64748b;margin-bottom:.5rem">${esc(decomp.description || '')}</div>`;
        html += `<div class="ai2-stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:.6rem">
          <div class="ai2-stat"><div class="ai2-stat-num">${decomp.trend_direction || '?'}</div><div class="ai2-stat-lbl">Trend</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${(decomp.seasonality_strength||0).toFixed(2)}</div><div class="ai2-stat-lbl">Stagionalità</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${decomp.total_anomaly_buckets || 0}</div><div class="ai2-stat-lbl">Anomalie</div></div>
          <div class="ai2-stat"><div class="ai2-stat-num">${(decomp.trend_r2||0).toFixed(2)}</div><div class="ai2-stat-lbl">R²</div></div>
        </div>`;
        html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;font-size:.78rem">
          <div><div style="font-weight:700;margin-bottom:.15rem">Statistiche serie</div>
            <div>Media: ${st.mean ?? '—'} | Mediana: ${st.median ?? '—'} | σ: ${st.std ?? '—'} | P95: ${st.p95 ?? '—'}</div></div>
          <div><div style="font-weight:700;margin-bottom:.15rem">Regressione</div>
            <div>Slope: ${decomp.trend_slope ?? '—'} | Periodo: ${decomp.period_detected ?? '—'} buckets</div></div>
        </div>`;
        set('ai2AdvDecomp', html);
      }

    } catch (err) {
      set('ai2AdvReport', `<div style="color:#dc2626;font-size:.82rem"><i class="bi bi-exclamation-triangle me-1"></i>Errore: ${esc(String(err))}</div>`);
    }
  };

  const bindEvents = () => {
    document.querySelectorAll('#viewNav .sb-item[data-view]').forEach((btn) => {
      btn.addEventListener('click', (e) => { e.preventDefault(); switchView(btn.dataset.view); });
    });

    const langSelect = q('langSelect');
    if (langSelect) {
      langSelect.value = TPL.getLang();
      langSelect.addEventListener('change', async () => {
        TPL.setLang(langSelect.value);
        await TPL.applyI18n();
        await switchView(state.currentView);
      });
    }

    q('reloadBtn')?.addEventListener('click', () => switchView(state.currentView));
    q('refreshRoutesBtn')?.addEventListener('click', loadRoutesPanel);
    q('ai2RefreshBtn')?.addEventListener('click', loadAICenter);
    _ai2InitTabs();
    const aiArCb = q('ai2AutoRefresh');
    if (aiArCb) aiArCb.addEventListener('change', (e) => _ai2ToggleAutoRefresh(e.target.checked));
    q('ai2RunAdvBtn')?.addEventListener('click', loadAdvancedAI);
    const rtArCb = q('rtAutoRefresh');
    if (rtArCb) {
      rtArCb.checked = tplPref('auto_refresh');
      rtArCb.addEventListener('change', (e) => { rtToggleAutoRefresh(e.target.checked); tplSetPref('auto_refresh', e.target.checked); });
    }
    q('rtRestartBtn')?.addEventListener('click', rtDoRestart);

    // Route table filters
    q('rtFilterPath')?.addEventListener('input', rtApplyRouteFilters);
    q('rtFilterMethod')?.addEventListener('change', rtApplyRouteFilters);
    q('rtFilterHealth')?.addEventListener('change', rtApplyRouteFilters);
    q('rtFilterCB')?.addEventListener('change', rtApplyRouteFilters);
    q('rtFilterClear')?.addEventListener('click', () => {
      ['rtFilterPath','rtFilterMethod','rtFilterHealth','rtFilterCB'].forEach(id => { const e = q(id); if (e) e.value = ''; });
      rtApplyRouteFilters();
    });
    // CB filters
    q('rtCBFilterPath')?.addEventListener('input', rtApplyCBFilters);
    q('rtCBFilterState')?.addEventListener('change', rtApplyCBFilters);

    // Collapsible sections init
    rtInitSections();
    secInitSections();

    // Security section events
    q('secAlertFilters')?.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.sec-filter-btn');
      if (!btn) return;
      q('secAlertFilters').querySelectorAll('.sec-filter-btn').forEach(b => b.classList.remove('sec-filter-btn--active'));
      btn.classList.add('sec-filter-btn--active');
      _secFilterSev = btn.dataset.sev || 'all';
      _secPag.alerts.page = 1;
      secRenderFilteredAlerts();
    });

    // Security hero buttons
    q('secRefreshBtn')?.addEventListener('click', () => loadSecurity());
    const secArCb = q('secAutoRefresh');
    if (secArCb) {
      secArCb.checked = tplPref('auto_refresh');
      secArCb.addEventListener('change', (ev) => { secToggleAutoRefresh(ev.target.checked); tplSetPref('auto_refresh', ev.target.checked); });
    }
    q('secScanBtn')?.addEventListener('click', () => {
      showMessage('Scansione di sicurezza in corso...', 'info');
      TPL.jsonFetch('/api/security/integrity')
        .then(() => { showMessage('Scansione completata', 'success'); loadSecurity(); })
        .catch(e => showMessage(`Errore: ${e}`, 'warning'));
    });

    // Alert search
    q('secAlertSearch')?.addEventListener('input', (ev) => {
      _secFilterSearch = ev.target.value;
      _secPag.alerts.page = 1;
      secRenderFilteredAlerts();
    });

    // Blocked IP search
    q('secBlockedSearch')?.addEventListener('input', () => {
      _secPag.blocked.page = 1;
      secRenderBlockedPaged();
    });

    document.addEventListener('click', (ev) => {
      // Unblock IP
      const unblock = ev.target.closest('[data-unblock-ip]');
      if (unblock) {
        const ip = unblock.dataset.unblockIp;
        TPL.jsonFetch('/api/security/ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, action: 'unblock' }) })
          .then(() => { showMessage(`IP ${ip} sbloccato`, 'success'); loadSecurity(); })
          .catch(e => showMessage(`Errore: ${e}`, 'warning'));
        return;
      }
      // Reset Baseline
      if (ev.target.closest('#secResetBaseline')) {
        TPL.jsonFetch('/api/security/integrity/baseline', { method: 'POST' })
          .then(() => { showMessage('Baseline integrità reimpostata', 'success'); loadSecurity(); })
          .catch(e => showMessage(`Errore: ${e}`, 'warning'));
        return;
      }
      // Benchmark
      if (ev.target.closest('#secRunBenchmark')) {
        showMessage('Benchmark in corso...', 'info');
        TPL.jsonFetch('/api/encryption/benchmark')
          .then((data) => { showMessage(`Benchmark completato: encrypt ${data.benchmark?.encrypt_1kb_ms}ms`, 'success'); loadSecurity(); })
          .catch(e => showMessage(`Errore: ${e}`, 'warning'));
        return;
      }
      // Rotate Key
      if (ev.target.closest('#secRotateKey')) {
        TPL.jsonFetch('/api/encryption/rotate', { method: 'POST' })
          .then(() => { showMessage('Chiave ruotata con successo', 'success'); loadSecurity(); })
          .catch(e => showMessage(`Errore: ${e}`, 'warning'));
        return;
      }
      // Generate Token
      if (ev.target.closest('#secGenToken')) {
        TPL.jsonFetch('/api/encryption/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ length: 32, count: 1 }) })
          .then((data) => { const tk = data.tokens?.[0] || ''; navigator.clipboard?.writeText(tk); showMessage('Token generato e copiato!', 'success'); })
          .catch(e => showMessage(`Errore: ${e}`, 'warning'));
        return;
      }
    });

    // Nuovo utente / ricerca
    q('showCreateUserBtn')?.addEventListener('click', openCreateUserModal);
    q('umSaveBtn')?.addEventListener('click', saveUser);
    q('userSearchBtn')?.addEventListener('click', loadUsers);
    q('userSearchInput')?.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') loadUsers(); });

    // Tabella utenti — delegated events
    q('usersTbody')?.addEventListener('click', (ev) => {
      const del = ev.target.closest('[data-delete-user]');
      if (del) { deleteUser(del.dataset.deleteUser); return; }
      const view = ev.target.closest('[data-view-user]');
      if (view) { viewUserDetail(view.dataset.viewUser); return; }
      const edit = ev.target.closest('[data-edit-user]');
      if (edit) { openEditUserModal(edit.dataset.editUser); return; }
      const resetPw = ev.target.closest('[data-reset-pw]');
      if (resetPw) { openAdminResetPasswordModal(resetPw.dataset.resetPw); return; }
      const revoke = ev.target.closest('[data-revoke-user]');
      if (revoke) { revokeUser(revoke.dataset.revokeUser); return; }
      const activate = ev.target.closest('[data-activate-user]');
      if (activate) { activateUser(activate.dataset.activateUser); return; }
    });

    // Password
    q('pwSaveBtn')?.addEventListener('click', savePassword);
    q('mpChangePasswordBtn')?.addEventListener('click', openSelfPasswordModal);
    q('mpSaveProfileBtn')?.addEventListener('click', saveMyProfile);
    q('mpExportBtn')?.addEventListener('click', mpExportProfile);

    // Module Control Center — Tab switching
    q('mcTabs')?.addEventListener('click', (ev) => {
      const tab = ev.target.closest('[data-mc-tab]');
      if (tab) mcSwitchTab(tab.dataset.mcTab);
    });

    // Module search, filter, sort, group
    q('mcModSearch')?.addEventListener('input', () => mcRenderModuleGrid());
    q('mcModFilter')?.addEventListener('change', () => mcRenderModuleGrid());
    q('mcModSort')?.addEventListener('change', () => mcRenderModuleGrid());
    q('mcModGroup')?.addEventListener('change', () => mcRenderModuleGrid());

    // Module refresh
    q('modRefreshBtn')?.addEventListener('click', () => loadModules());

    // Batch actions
    q('mcBatchApplyBtn')?.addEventListener('click', mcBatchApply);
    q('mcBatchUpdateBtn')?.addEventListener('click', mcBatchApply);
    q('mcBatchClearBtn')?.addEventListener('click', mcBatchClear);

    // Module detail modal
    q('mcModDetailClose')?.addEventListener('click', mcCloseDetail);
    q('mcModDetailOverlay')?.addEventListener('click', (ev) => {
      if (ev.target === ev.currentTarget) mcCloseDetail();
    });

    // Module grid — apply/reset/select/detail delegation
    q('modulesGrid')?.addEventListener('click', (ev) => {
      const applyBtn = ev.target.closest('[data-apply-module]');
      if (applyBtn) { applyModule(applyBtn.dataset.applyModule); return; }
      const resetBtn = ev.target.closest('[data-reset-module]');
      if (resetBtn) { resetModule(resetBtn.dataset.resetModule); return; }
      const selectCb = ev.target.closest('[data-mc-select]');
      if (selectCb) { mcToggleSelect(selectCb.dataset.mcSelect); return; }
      const detailBtn = ev.target.closest('[data-mc-detail]');
      if (detailBtn) { mcShowDetail(detailBtn.dataset.mcDetail); return; }
    });

    // Detail modal — apply/reset delegation (buttons inside modal)
    q('mcModDetailBody')?.addEventListener('click', (ev) => {
      const applyBtn = ev.target.closest('[data-apply-module]');
      if (applyBtn) { mcCloseDetail(); applyModule(applyBtn.dataset.applyModule); return; }
      const resetBtn = ev.target.closest('[data-reset-module]');
      if (resetBtn) { mcCloseDetail(); resetModule(resetBtn.dataset.resetModule); return; }
    });

    // Version tab — OTA + Local upload
    q('mcOtaCheckBtn')?.addEventListener('click', mcOtaCheck);
    q('mcLocalUploadBtn')?.addEventListener('click', mcLocalUpload);

    // Backup
    q('mcBackupBtn')?.addEventListener('click', mcCreateBackup);

    // Delegation for dynamic buttons: rollback, restore, remediation
    document.querySelector('#view-modules')?.addEventListener('click', (ev) => {
      const rollback = ev.target.closest('[data-mc-rollback]');
      if (rollback) { mcRollback(rollback.dataset.mcRollback); return; }
      const restore = ev.target.closest('[data-mc-restore]');
      if (restore) { mcRestore(restore.dataset.mcRestore); return; }
      const remed = ev.target.closest('[data-mc-remed]');
      if (remed) { mcRemediate(remed.dataset.mcRemed); return; }
    });

    q('logoutBtn')?.addEventListener('click', () => {
      if (window.TPL?.logout) window.TPL.logout();
      else location.href = '/';
    });

    /* ── Global keyboard shortcuts ── */
    const _kbViewMap = { '1': 'overview', '2': 'workspace', '3': 'myprofile', '4': 'users', '5': 'modules', '6': 'security', '7': 'audit', '8': 'routes', '9': 'ai' };
    const _kbAdminViews = new Set(['users', 'modules', 'security', 'audit', 'routes', 'ai']);

    document.addEventListener('keydown', (ev) => {
      /* Skip when typing in inputs/textareas/selects */
      const tag = ev.target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || ev.target.isContentEditable) return;

      /* Alt+1–9 — switch view */
      if (ev.altKey && !ev.ctrlKey && !ev.metaKey && _kbViewMap[ev.key]) {
        const view = _kbViewMap[ev.key];
        if (_kbAdminViews.has(view) && !state.isAdmin) return;
        ev.preventDefault();
        switchView(view);
        return;
      }

      /* R — refresh current view */
      if (ev.key === 'r' && !ev.altKey && !ev.ctrlKey && !ev.metaKey) {
        ev.preventDefault();
        switchView(state.currentView);
        return;
      }

      /* ? — show shortcuts help */
      if (ev.key === '?' && !ev.altKey && !ev.ctrlKey && !ev.metaKey) {
        ev.preventDefault();
        _showKeyboardHelp();
        return;
      }
    });
  };

  /* ── Keyboard shortcuts help overlay ── */
  const _showKeyboardHelp = () => {
    let overlay = document.getElementById('kbHelpOverlay');
    if (overlay) { overlay.remove(); return; }
    const shortcuts = [
      ['Alt+1', 'Overview'],
      ['Alt+2', 'Workspace'],
      ['Alt+3', 'Il mio Profilo'],
      ...(state.isAdmin ? [
        ['Alt+4', 'Gestione Utenti'],
        ['Alt+5', 'Centro Controllo'],
        ['Alt+6', 'Security Center'],
        ['Alt+7', 'Audit'],
        ['Alt+8', 'Route Control'],
        ['Alt+9', 'AI Center'],
      ] : []),
      ['R', 'Ricarica vista corrente'],
      ['?', 'Mostra/chiudi shortcuts'],
    ];
    overlay = document.createElement('div');
    overlay.id = 'kbHelpOverlay';
    overlay.className = 'ov-modal-overlay';
    overlay.innerHTML = `
      <div class="ov-modal ov-modal--sm" role="dialog" aria-label="Scorciatoie tastiera">
        <div class="ov-modal-head">
          <span><i class="bi bi-keyboard me-1"></i> Scorciatoie Tastiera</span>
          <button class="ov-modal-close" type="button" id="kbHelpClose">&times;</button>
        </div>
        <div class="ov-modal-body">
          <div class="kb-shortcuts-grid">
            ${shortcuts.map(([k, d]) => `<div class="kb-shortcut"><kbd>${k}</kbd><span>${d}</span></div>`).join('')}
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    overlay.classList.remove('d-none');
    document.getElementById('kbHelpClose').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (ev) => { if (ev.target === overlay) overlay.remove(); });
  };

  const init = async () => {
    if (!window.TPL?.token || !window.TPL.token()) {
      location.href = '/';
      return;
    }

    state.me = await TPL.jsonFetch('/api/me');

    // Force password change: redirect to login page if must_change_password
    if (state.me.must_change_password) {
      location.href = '/';
      return;
    }

    state.isAdmin = (state.me.roles || []).includes('admin');

    state.routeControl = new window.DashboardRouteControl((url, options) => TPL.jsonFetch(url, options));
    await state.routeControl.init();

    setAdminVisibility();
    setIdentity();
    bindEvents();

    /* Apply saved preferences (compact mode, etc.) before first render */
    tplApplyPrefs();

    if (window.TPL?.applyI18n) {
      try { await TPL.applyI18n(false); } catch (_) {}
    }

    await switchView('overview');
  };

  /* ── Expose switchView globally for inline HTML buttons ──────── */
  window.TPLDashboard = Object.freeze({ switchView });

  window.addEventListener('load', () => {
    init().catch((error) => {
      showMessage(`Dashboard init failed: ${String(error)}`, 'danger');
      setTimeout(() => {
        location.href = '/';
      }, 1200);
    });
  });
})();
