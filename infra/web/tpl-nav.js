/**
 * TPL Platform — Unified Navigation Module (v3.5.0)
 *
 * Centralised platform navigation: top navbar, footer, auth bootstrap.
 *
 * Usage:
 *   <!-- Empty placeholders → auto-rendered -->
 *   <nav id="tplNavbar"></nav>
 *   <footer id="tplFooter"></footer>
 *   <script src="/tpl-nav.js"></script>
 *
 *   Pages that handle their own navbar (e.g. dashboard) omit #tplNavbar.
 *   Footer is always auto-rendered when the placeholder exists.
 *
 * Auth bootstrap (auto):
 *   - Calls /api/me
 *   - Sets sidebar admin/user via TPLSidebar
 *   - Sets identity display  + version badge
 *   - Redirects to / on auth failure
 *   - Fires 'tpl:auth-ready' CustomEvent on window
 *
 * Public API (window.TPLNav):
 *   .currentUser   – user obj from /api/me (null until ready)
 *   .isAdmin       – boolean
 *   .page          – detected page id
 *   .onReady(fn)   – register callback; fires immediately if already authed
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
    navEl.className = 'app-header navbar navbar-expand bg-body';
    navEl.innerHTML = [
      '<div class="container-fluid">',
      '  <ul class="navbar-nav">',
      '    <li class="nav-item">',
      '      <a class="nav-link" id="sidebarToggle" href="#" role="button"',
      '         aria-label="Toggle sidebar"><i class="bi bi-list"></i></a>',
      '    </li>',
      '  </ul>',
      '  <ul class="navbar-nav ms-auto align-items-center">',
      '    <li class="nav-item">',
      '      <span class="nav-link text-muted small" id="tplIdentityBox">',
      '        <i class="bi bi-hourglass-split me-1"></i>caricamento…',
      '      </span>',
      '    </li>',
      '    <li class="nav-item">',
      '      <a class="nav-link text-danger" href="#" id="tplLogoutBtn"',
      '         role="button" title="Logout"><i class="bi bi-box-arrow-right"></i></a>',
      '    </li>',
      '  </ul>',
      '</div>',
    ].join('\n');

    /* Sidebar toggle (sidebar.js can't bind — element didn't exist yet) */
    document.getElementById('sidebarToggle')?.addEventListener('click', (e) => {
      e.preventDefault();
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
    footerEl.innerHTML = [
      '<div class="float-end d-none d-sm-inline">',
      '  <span class="tpl-version-badge" id="tplVersionBadge">v—</span>',
      '</div>',
      '<strong>&copy; TPL Fortress</strong>',
    ].join('\n');
  }

  /* ── Auth Bootstrap ─────────────────────────────────────── */
  const _bootstrap = async () => {
    /* Only bootstrap pages using auto-nav; dashboard handles its own auth */
    if (!_autoNav) return;

    if (!window.TPL?.jsonFetch) {
      console.error('[TPL Nav] app.js must be loaded before tpl-nav.js');
      return;
    }

    try {
      _user = await TPL.jsonFetch('/api/me');
      _admin = !!(_user.roles?.includes('admin'));

      /* Force password change redirect */
      if (_user.must_change_password) { location.href = '/'; return; }

      /* Sidebar */
      if (window.TPLSidebar) {
        TPLSidebar.setAdmin(_admin);
        TPLSidebar.setUser(_user.sub || _user.username || '—');
      }

      /* Identity box */
      const box = document.getElementById('tplIdentityBox');
      if (box) {
        const r = _admin ? 'admin' : 'user';
        box.innerHTML =
          '<i class="bi bi-person-check-fill me-1"></i>' +
          (_user.sub || '—') +
          ' <span class="badge bg-secondary bg-opacity-75 ms-1" style="font-size:.6rem">' + r + '</span>';
      }

      /* i18n + version badge */
      try { if (TPL.applyI18n) await TPL.applyI18n(); } catch (_) { /* noop */ }
      try { if (TPL.populateVersionBadge) TPL.populateVersionBadge(); } catch (_) { /* noop */ }

      /* Notify registered callbacks */
      _cbs.forEach(fn => { try { fn(_user); } catch (_) { /* noop */ } });

      /* DOM event — page-specific handlers can listen */
      window.dispatchEvent(new CustomEvent('tpl:auth-ready', { detail: _user }));
    } catch (e) {
      console.warn('[TPL Nav] auth failed:', e.message);
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
