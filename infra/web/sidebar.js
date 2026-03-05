/**
 * TPL Platform — Sidebar v6.0  «Architect»
 *
 * Clean navigation panel inspired by modern dashboard UIs:
 *   • Dark navy gradient surface
 *   • Active item accent bar indicator
 *   • Collapse to icon-only with smooth transitions
 *   • Section labels with uppercase dividers
 *   • Mobile slide-in with backdrop overlay
 *   • User card at bottom
 *   • Keyboard shortcut: Ctrl+B toggle
 *
 * Public API  (window.TPLSidebar):
 *   .setUser(name, role)     – update footer identity
 *   .setAdmin(isAdmin)       – toggle admin-only items
 *   .setActiveView(viewId)   – highlight a dashboard sub-view
 *   .collapse() / .expand()  – programmatic control
 *   .toggle()                – toggle state
 */
(() => {
  'use strict';

  const NAV = [
    { section: 'Navigazione' },
    { id: 'overview',  icon: 'bi-speedometer2',   label: 'Overview',          view: true },
    { id: 'workspace', icon: 'bi-collection',      label: 'Workspace',         view: true },
    { id: 'myprofile', icon: 'bi-person-circle',   label: 'Il mio profilo',    view: true },

    { section: 'Amministrazione', admin: true },
    { id: 'users',    icon: 'bi-people',           label: 'Gestione Utenti',   view: true, admin: true },
    { id: 'modules',  icon: 'bi-puzzle',           label: 'Moduli',            view: true, admin: true },
    { id: 'security', icon: 'bi-shield-lock-fill', label: 'Security Center',   view: true, admin: true },
    { id: 'audit',    icon: 'bi-journal-text',     label: 'Audit',             view: true, admin: true },
    { id: 'routes',   icon: 'bi-signpost-split',   label: 'Route Control',     view: true, admin: true },
    { id: 'ai',       icon: 'bi-robot',            label: 'AI Center',         view: true, admin: true },

    { section: 'Strumenti' },
    { id: 'nav-diagnostics', icon: 'bi-heart-pulse',     label: 'Diagnostica',          href: '/diagnostics', admin: true },
    { id: 'nav-ota',         icon: 'bi-cloud-arrow-down',label: 'Aggiornamenti OTA',    href: '/ota', admin: true },
    { id: 'nav-advanced',    icon: 'bi-terminal',        label: 'Advanced',             href: '/advanced' },
    { id: 'nav-modules',     icon: 'bi-box-seam',        label: 'Distribuzione Moduli', href: '/admin/modules', admin: true },
  ];

  const PAGE = (() => {
    const p = location.pathname;
    if (p.startsWith('/admin/modules')) return 'admin-modules';
    if (p.startsWith('/diagnostics'))   return 'diagnostics';
    if (p.startsWith('/ota'))           return 'ota';
    if (p.startsWith('/advanced'))      return 'advanced';
    return 'dashboard';
  })();

  /* ── Build DOM ─────────────────────────────────────────── */
  const buildSidebar = () => {
    const aside = document.createElement('aside');
    aside.id = 'appSidebar';
    aside.className = 'sb-sidebar';
    aside.setAttribute('role', 'navigation');
    aside.setAttribute('aria-label', 'Navigazione principale');

    aside.innerHTML = `
      <a href="/dashboard" class="sb-brand" aria-label="TPL Platform Dashboard">
        <span class="sb-brand-icon">T</span>
        <span class="sb-brand-text">
          <span class="sb-brand-name">TPL Platform</span>
          <span class="sb-brand-sub">Fortress Edition</span>
        </span>
      </a>
      <nav class="sb-nav" id="viewNav" aria-label="Menu di navigazione"></nav>
      <div class="sb-user" id="sidebarFooter">
        <div class="sb-user-avatar" id="sbUserInitials">
          <i class="bi bi-person-fill"></i>
        </div>
        <div class="sb-user-info">
          <span class="sb-user-name" id="sidebarUsername">\u2014</span>
          <span class="sb-user-role" id="sidebarRole">user</span>
        </div>
      </div>`;

    const nav = aside.querySelector('#viewNav');

    NAV.forEach((item) => {
      if (item.section) {
        const div = document.createElement('div');
        div.className = 'sb-section-label' + (item.admin ? ' sb-admin' : '');
        div.textContent = item.section;
        nav.appendChild(div);
        return;
      }

      const a = document.createElement('a');
      a.className = 'sb-item' + (item.admin ? ' sb-admin' : '');
      a.setAttribute('role', 'menuitem');

      if (item.view) {
        a.href = '#';
        a.dataset.view = item.id;
      } else if (item.href) {
        a.href = item.href;
      }

      const isActive =
        (PAGE === 'dashboard' && item.view && item.id === 'overview') ||
        (PAGE === 'ota' && item.id === 'nav-ota') ||
        (PAGE === 'diagnostics' && item.id === 'nav-diagnostics') ||
        (PAGE === 'advanced' && item.id === 'nav-advanced') ||
        (PAGE === 'admin-modules' && item.id === 'nav-modules');

      if (isActive) { a.classList.add('active'); a.setAttribute('aria-current', 'page'); }

      a.innerHTML = `
        <span class="sb-item-icon"><i class="bi ${item.icon}"></i></span>
        <span class="sb-item-label">${item.label}</span>`;
      nav.appendChild(a);
    });

    return aside;
  };

  /* ── Backdrop for mobile ───────────────────────────────── */
  const backdrop = document.createElement('div');
  backdrop.className = 'sb-backdrop';
  backdrop.setAttribute('aria-hidden', 'true');

  /* ── Mount ─────────────────────────────────────────────── */
  const mount = document.getElementById('sidebarMount');
  const sidebar = buildSidebar();

  if (mount) {
    mount.replaceWith(sidebar);
  } else {
    const wrapper = document.querySelector('.app-wrapper') || document.body;
    const main = wrapper.querySelector('main') || wrapper.querySelector('.app-main');
    if (main) wrapper.insertBefore(sidebar, main);
    else wrapper.prepend(sidebar);
  }
  document.body.appendChild(backdrop);

  /* ── State management ──────────────────────────────────── */
  const STORAGE_KEY = 'tpl-sidebar-collapsed';
  let _collapsed = localStorage.getItem(STORAGE_KEY) === '1';
  let _mobileOpen = false;
  const isMobile = () => window.innerWidth <= 1024;

  const applyState = () => {
    sidebar.classList.toggle('collapsed', _collapsed && !isMobile());
    sidebar.classList.toggle('mobile-open', _mobileOpen && isMobile());
    document.body.classList.toggle('sidebar-collapsed', _collapsed && !isMobile());
    backdrop.classList.toggle('show', _mobileOpen && isMobile());
    document.body.style.overflow = (_mobileOpen && isMobile()) ? 'hidden' : '';
  };

  if (_collapsed) applyState();

  /* ── Toggle logic ──────────────────────────────────────── */
  const collapse = () => { _collapsed = true; _mobileOpen = false; localStorage.setItem(STORAGE_KEY, '1'); applyState(); };
  const expand = () => {
    if (isMobile()) { _mobileOpen = true; }
    else { _collapsed = false; localStorage.setItem(STORAGE_KEY, '0'); }
    applyState();
  };
  const toggle = (forceState) => {
    if (typeof forceState === 'boolean') {
      if (forceState) expand(); else collapse();
      return;
    }
    if (isMobile()) {
      _mobileOpen = !_mobileOpen;
      applyState();
    } else {
      _collapsed = !_collapsed;
      localStorage.setItem(STORAGE_KEY, _collapsed ? '1' : '0');
      applyState();
    }
  };

  /* ── Event listeners ───────────────────────────────────── */
  // Navbar toggle (burger)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('#sidebarToggle, .nb-burger');
    if (btn) { e.preventDefault(); toggle(); return; }
    // Close mobile on outside click
    if (_mobileOpen && isMobile() && !sidebar.contains(e.target)) {
      _mobileOpen = false;
      applyState();
    }
  });

  backdrop.addEventListener('click', () => { _mobileOpen = false; applyState(); });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _mobileOpen) { _mobileOpen = false; applyState(); }
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') { e.preventDefault(); toggle(); }
  });

  // Responsive: close mobile on resize to desktop
  window.addEventListener('resize', () => {
    if (!isMobile() && _mobileOpen) { _mobileOpen = false; applyState(); }
  });

  /* ── Public API ────────────────────────────────────────── */
  const setUser = (name, role) => {
    const el = document.getElementById('sidebarUsername');
    if (el) el.textContent = name || '\u2014';
    const rl = document.getElementById('sidebarRole');
    if (rl && role) rl.textContent = role;
    // Set avatar initials
    const av = document.getElementById('sbUserInitials');
    if (av && name) {
      const initials = name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
      av.textContent = initials;
    }
  };

  const setAdmin = (isAdmin) => {
    sidebar.querySelectorAll('.sb-admin').forEach((el) => {
      el.style.display = isAdmin ? '' : 'none';
    });
  };

  const setActiveView = (viewId) => {
    sidebar.querySelectorAll('.sb-item').forEach((el) => {
      el.classList.remove('active');
      el.removeAttribute('aria-current');
    });
    const target = sidebar.querySelector(`.sb-item[data-view="${viewId}"]`);
    if (target) {
      target.classList.add('active');
      target.setAttribute('aria-current', 'page');
    }
  };

  setAdmin(false);

  window.TPLSidebar = Object.freeze({
    setUser,
    setAdmin,
    setActiveView,
    collapse,
    expand,
    toggle,
  });
})();
