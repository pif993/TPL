/**
 * TPL Platform — Navigation Module v6.0  «Architect»
 *
 * Clean top navbar featuring:
 *   • Search bar with icon
 *   • Theme toggle (light/dark)
 *   • Notification bell
 *   • User identity dropdown
 *   • Breadcrumb context
 *   • Auth bootstrap (/api/me)
 *   • Footer auto-render
 *
 * Public API (window.TPLNav):
 *   .currentUser   – user obj from /api/me
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

  const PAGE_TITLES = {
    'dashboard':     'Dashboard',
    'ota':           'Aggiornamenti OTA',
    'diagnostics':   'Diagnostica',
    'advanced':      'Advanced Tools',
    'admin-modules': 'Distribuzione Moduli',
  };

  /* ── Theme Management ───────────────────────────────────── */
  const THEME_KEY = 'tpl-theme';
  const getPreferredTheme = () => {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored) return stored;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };
  const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    // Update icon
    const icon = document.getElementById('themeToggleIcon');
    if (icon) icon.className = theme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
  };
  applyTheme(getPreferredTheme());

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem(THEME_KEY)) {
      applyTheme(e.matches ? 'dark' : 'light');
    }
  });

  /* ── Navbar (auto-render into empty #tplNavbar) ─────────── */
  const navEl = document.getElementById('tplNavbar');
  const _autoNav = !!(navEl && navEl.childElementCount === 0);

  if (_autoNav) {
    navEl.className = 'nb-navbar';
    navEl.setAttribute('role', 'banner');
    const currentTheme = getPreferredTheme();
    const themeIcon = currentTheme === 'dark' ? 'bi-sun' : 'bi-moon-stars';

    navEl.innerHTML = `
      <div class="nb-navbar-left">
        <button class="nb-burger" id="sidebarToggle" type="button" aria-label="Apri menu laterale">
          <i class="bi bi-list"></i>
        </button>
        <div class="nb-breadcrumb">
          <span>TPL</span>
          <span class="nb-breadcrumb-sep"><i class="bi bi-chevron-right"></i></span>
          <span class="nb-breadcrumb-current" id="nbPageTitle">${PAGE_TITLES[PAGE] || 'Dashboard'}</span>
        </div>
      </div>

      <div class="nb-navbar-right">
        <div class="nb-search" role="search">
          <i class="bi bi-search nb-search-icon"></i>
          <input type="search" placeholder="Cerca..." aria-label="Cerca nella piattaforma" />
        </div>

        <button class="nb-icon-btn" id="themeToggle" type="button" title="Cambia tema" aria-label="Cambia tema chiaro/scuro">
          <i class="bi ${themeIcon}" id="themeToggleIcon"></i>
        </button>

        <button class="nb-icon-btn" id="nbNotifications" type="button" title="Notifiche" aria-label="Notifiche">
          <i class="bi bi-bell"></i>
          <span class="nb-badge" id="nbNotifBadge" style="display:none"></span>
        </button>

        <div class="nb-divider"></div>

        <button class="nb-user-btn" id="tplIdentityBox" type="button" aria-label="Menu utente">
          <span class="nb-user-avatar" id="nbUserAvatar"><i class="bi bi-person-fill"></i></span>
          <span class="nb-user-name" id="nbUserName">Caricamento...</span>
        </button>

        <button class="nb-icon-btn" id="tplLogoutBtn" type="button" title="Logout" aria-label="Logout">
          <i class="bi bi-box-arrow-right"></i>
        </button>
      </div>
    `;

    /* Theme toggle */
    document.getElementById('themeToggle')?.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });

    /* Sidebar toggle (burger on mobile) */
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
    footerEl.className = 'tpl-footer';
    footerEl.innerHTML = `
      <span>&copy; ${new Date().getFullYear()} TPL Fortress Platform</span>
      <span class="tpl-version-badge" id="tplVersionBadge">v\u2014</span>
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
        TPLSidebar.setUser(_user.sub || _user.username || '\u2014', _admin ? 'admin' : 'user');
      }

      /* Navbar user display */
      const nameEl = document.getElementById('nbUserName');
      if (nameEl) nameEl.textContent = _user.sub || _user.username || '\u2014';

      const avatarEl = document.getElementById('nbUserAvatar');
      if (avatarEl && (_user.sub || _user.username)) {
        const name = _user.sub || _user.username;
        const initials = name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
        avatarEl.textContent = initials;
      }

      /* i18n + version badge */
      try { if (TPL.applyI18n) await TPL.applyI18n(); } catch (_) { /* noop */ }
      try { if (TPL.populateVersionBadge) TPL.populateVersionBadge(); } catch (_) { /* noop */ }

      /* Notify callbacks */
      _cbs.forEach(fn => { try { fn(_user); } catch (_) { /* noop */ } });
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _bootstrap);
  } else {
    _bootstrap();
  }
})();
