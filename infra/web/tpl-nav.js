/**
 * TPL Platform — Unified Navigation Module v4.0  «Nebula»
 *
 * Futuristic top navbar with:
 *   • Frosted-glass surface with animated gradient underline
 *   • Status pulse indicator (live system health)
 *   • Identity capsule with gradient role badge
 *   • Notification bell placeholder
 *   • Contextual breadcrumb integration
 *   • Auth bootstrap (auto /api/me)
 *   • Footer auto-render
 *
 * Usage:
 *   <nav id="tplNavbar"></nav>
 *   <footer id="tplFooter"></footer>
 *   <script src="/tpl-nav.js"></script>
 *
 * Public API (window.TPLNav):
 *   .currentUser   – user obj from /api/me (null until ready)
 *   .isAdmin       – boolean
 *   .page          – detected page id
 *   .onReady(fn)   – register callback
 */
(() => {
  'use strict';

  let _user = null;
  let _admin = false;
  const _cbs = [];

  /* ── Page Detection ─────────────────────────────────────── */
  const PAGE = (() => {
    const p = location.pathname;
    if (p.startsWith('/admin/modules')) return 'admin-modules';
    if (p.startsWith('/diagnostics'))   return 'diagnostics';
    if (p.startsWith('/ota'))           return 'ota';
    if (p.startsWith('/advanced'))      return 'advanced';
    return 'dashboard';
  })();

  /* ── Navbar (auto-render into empty #tplNavbar) ─────────── */
  const navEl = document.getElementById('tplNavbar');
  const _autoNav = !!(navEl && navEl.childElementCount === 0);

  if (_autoNav) {
    navEl.className = 'app-header navbar navbar-expand';
    navEl.innerHTML = `
      <div class="container-fluid">

        <!-- Left cluster -->
        <div class="nb-left">
          <button class="nb-toggle" id="sidebarToggle" type="button" aria-label="Toggle sidebar">
            <span class="nb-toggle-bar"></span>
            <span class="nb-toggle-bar"></span>
            <span class="nb-toggle-bar"></span>
          </button>

          <div class="nb-status" id="nbStatus" title="System status">
            <span class="nb-status-dot nb-status-dot--ok"></span>
            <span class="nb-status-label">Online</span>
          </div>
        </div>

        <!-- Right cluster -->
        <div class="nb-right">
          <div class="nb-identity" id="tplIdentityBox">
            <span class="nb-identity-icon"><i class="bi bi-hourglass-split"></i></span>
            <span class="nb-identity-text">caricamento…</span>
          </div>

          <button class="nb-icon-btn nb-notifications" id="nbNotifications" type="button" title="Notifiche" aria-label="Notifications">
            <i class="bi bi-bell"></i>
            <span class="nb-notif-badge" style="display:none">0</span>
          </button>

          <button class="nb-icon-btn nb-logout" id="tplLogoutBtn" type="button" title="Logout" aria-label="Logout">
            <i class="bi bi-box-arrow-right"></i>
          </button>
        </div>

      </div>

      <!-- Animated gradient underline -->
      <div class="nb-glow-line"></div>
    `;

    /* Sidebar toggle */
    const toggleBtn = document.getElementById('sidebarToggle');
    toggleBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      toggleBtn.classList.toggle('is-open');
      if (window.TPLSidebar) TPLSidebar.toggle();
    });

    /* Logout */
    document.getElementById('tplLogoutBtn')?.addEventListener('click', (e) => {
      e.preventDefault();
      if (window.TPL?.logout) TPL.logout();
      else location.href = '/';
    });
  }

  /* ── Footer (auto-render into empty #tplFooter) ─────────── */
  const footerEl = document.getElementById('tplFooter');
  if (footerEl && footerEl.childElementCount === 0) {
    footerEl.className = 'app-footer';
    footerEl.innerHTML = `
      <div class="nb-footer-inner">
        <span class="nb-footer-copy">&copy; TPL Fortress</span>
        <span class="tpl-version-badge tpl-version-badge--dark" id="tplVersionBadge">v—</span>
      </div>
    `;
  }

  /* ── Auth Bootstrap ─────────────────────────────────────── */
  const _bootstrap = async () => {
    if (!_autoNav) return;

    if (!window.TPL?.jsonFetch) {
      console.error('[TPL Nav] app.js must be loaded before tpl-nav.js');
      return;
    }

    try {
      _user = await TPL.jsonFetch('/api/me');
      _admin = !!(_user.roles?.includes('admin'));

      if (_user.must_change_password) { location.href = '/'; return; }

      /* Sidebar */
      if (window.TPLSidebar) {
        TPLSidebar.setAdmin(_admin);
        TPLSidebar.setUser(_user.sub || _user.username || '—', _admin ? 'admin' : 'user');
      }

      /* Identity capsule */
      const box = document.getElementById('tplIdentityBox');
      if (box) {
        const r = _admin ? 'admin' : 'user';
        const roleClass = _admin ? 'nb-role--admin' : 'nb-role--user';
        box.innerHTML = `
          <span class="nb-identity-icon"><i class="bi bi-person-check-fill"></i></span>
          <span class="nb-identity-text">${_user.sub || '—'}</span>
          <span class="nb-role-badge ${roleClass}">${r}</span>
        `;
      }

      /* System status indicator */
      const dot = document.querySelector('.nb-status-dot');
      const label = document.querySelector('.nb-status-label');
      if (dot) { dot.classList.add('nb-status-dot--ok'); }
      if (label) { label.textContent = 'Online'; }

      /* i18n + version badge */
      try { if (TPL.applyI18n) await TPL.applyI18n(); } catch (_) { /* noop */ }
      try { if (TPL.populateVersionBadge) TPL.populateVersionBadge(); } catch (_) { /* noop */ }

      /* Notify callbacks */
      _cbs.forEach(fn => { try { fn(_user); } catch (_) { /* noop */ } });
      window.dispatchEvent(new CustomEvent('tpl:auth-ready', { detail: _user }));
    } catch (e) {
      console.warn('[TPL Nav] auth failed:', e.message);
      /* Update status indicator to error */
      const dot = document.querySelector('.nb-status-dot');
      const label = document.querySelector('.nb-status-label');
      if (dot) { dot.className = 'nb-status-dot nb-status-dot--error'; }
      if (label) { label.textContent = 'Offline'; }
      location.href = '/';
    }
  };

  /* ── Public API ─────────────────────────────────────────── */
  window.TPLNav = Object.freeze({
    get currentUser() { return _user; },
    get isAdmin()     { return _admin; },
    get page()        { return PAGE; },
    onReady(fn) {
      if (typeof fn !== 'function') return;
      if (_user) fn(_user);
      else _cbs.push(fn);
    },
  });

  /* ── Auto-start ─────────────────────────────────────────── */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _bootstrap);
  } else {
    _bootstrap();
  }
})();
