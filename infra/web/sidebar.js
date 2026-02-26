/**
 * TPL Platform — Centralised Sidebar
 *
 * Usage:
 *   <script src="/sidebar.js"></script>
 *   Automatically renders into <div id="sidebarMount"> (or creates it).
 *
 * Public API  (window.TPLSidebar):
 *   .setUser(name)           – update footer username
 *   .setAdmin(isAdmin)       – show / hide admin-only items
 *   .setActiveView(viewId)   – highlight a dashboard sub-view
 *   .collapse() / .expand()  – programmatic toggle
 */
(() => {
  'use strict';

  /* ── Navigation definition ─────────────────────────────────── */
  const NAV = [
    { section: 'Navigazione' },
    { id: 'overview',  icon: 'bi-speedometer2',   label: 'Overview',         view: true },
    { id: 'workspace', icon: 'bi-collection',      label: 'Workspace',        view: true },
    { id: 'myprofile', icon: 'bi-person-circle',   label: 'Il mio profilo',   view: true },

    { section: 'Amministrazione', admin: true },
    { id: 'users',    icon: 'bi-people',           label: 'Gestione Utenti',  view: true, admin: true },
    { id: 'modules',  icon: 'bi-puzzle',           label: 'Moduli',           view: true, admin: true },
    { id: 'security', icon: 'bi-shield-lock-fill', label: 'Security Center', view: true, admin: true },
    { id: 'audit',    icon: 'bi-journal-text',     label: 'Audit',            view: true, admin: true },
    { id: 'routes',   icon: 'bi-signpost-split',   label: 'Route Control',    view: true, admin: true },
    { id: 'ai',       icon: 'bi-robot',            label: 'AI Center',        view: true, admin: true },

    { section: 'Strumenti' },
    { id: 'nav-advanced', icon: 'bi-terminal',     label: 'Advanced',     href: '/advanced' },
    { id: 'nav-modules',  icon: 'bi-box-seam',     label: 'Distribuzione Moduli', href: '/admin/modules', admin: true },
  ];

  /* ── Detect which page we're on ────────────────────────────── */
  const PAGE = (() => {
    const p = location.pathname;
    if (p.startsWith('/admin/modules')) return 'admin-modules';
    if (p.startsWith('/advanced'))      return 'advanced';
    return 'dashboard';
  })();

  /* ── Build HTML ────────────────────────────────────────────── */
  const buildSidebar = () => {
    const aside = document.createElement('aside');
    aside.id = 'appSidebar';

    /* Brand */
    aside.innerHTML = `
      <div class="sb-brand">
        <a href="/dashboard" class="sb-brand-link">
          <span class="sb-brand-icon"><i class="bi bi-shield-check"></i></span>
          <span class="sb-brand-text">TPL Platform</span>
        </a>
      </div>
      <nav class="sb-menu" id="viewNav"></nav>
      <div class="sb-footer" id="sidebarFooter">
        <i class="bi bi-person-fill"></i>
        <span id="sidebarUsername">—</span>
      </div>`;

    const nav = aside.querySelector('#viewNav');

    NAV.forEach((item) => {
      if (item.section) {
        const lbl = document.createElement('div');
        lbl.className = 'sb-section' + (item.admin ? ' sb-admin' : '');
        lbl.textContent = item.section;
        nav.appendChild(lbl);
        return;
      }

      const a = document.createElement('a');
      a.className = 'sb-item' + (item.admin ? ' sb-admin' : '');

      if (item.view) {
        /* Dashboard sub-view link */
        a.href = '#';
        a.dataset.view = item.id;
      } else if (item.href) {
        a.href = item.href;
      }

      /* Active detection */
      if (PAGE === 'dashboard' && item.view && item.id === 'overview') {
        a.classList.add('active');
      } else if (PAGE === 'advanced' && item.id === 'nav-advanced') {
        a.classList.add('active');
      } else if (PAGE === 'admin-modules' && item.id === 'nav-modules') {
        a.classList.add('active');
      }

      a.innerHTML = `<i class="bi ${item.icon}"></i><span>${item.label}</span>`;
      nav.appendChild(a);
    });

    return aside;
  };

  /* ── Mount ─────────────────────────────────────────────────── */
  const mount = document.getElementById('sidebarMount');
  const sidebar = buildSidebar();

  if (mount) {
    mount.replaceWith(sidebar);
  } else {
    /* Fallback: insert at the start of .app-wrapper or body */
    const wrapper = document.querySelector('.app-wrapper') || document.body;
    const main = wrapper.querySelector('main') || wrapper.querySelector('.app-main');
    if (main) wrapper.insertBefore(sidebar, main);
    else wrapper.prepend(sidebar);
  }

  /* ── Toggle logic ──────────────────────────────────────────── */
  const toggle = (forceState) => {
    const body = document.body;
    if (typeof forceState === 'boolean') {
      body.classList.toggle('sb-collapsed', !forceState);
      body.classList.toggle('sb-open', forceState && window.innerWidth < 992);
    } else {
      if (window.innerWidth < 992) {
        body.classList.toggle('sb-open');
      } else {
        body.classList.toggle('sb-collapsed');
      }
    }
  };

  const collapse = () => {
    document.body.classList.add('sb-collapsed');
    document.body.classList.remove('sb-open');
  };

  const expand = () => {
    if (window.innerWidth < 992) {
      document.body.classList.add('sb-open');
    } else {
      document.body.classList.remove('sb-collapsed');
    }
  };

  /* Toggle button */
  document.getElementById('sidebarToggle')?.addEventListener('click', (e) => {
    e.preventDefault();
    toggle();
  });

  /* Mobile: close on outside click */
  document.addEventListener('click', (e) => {
    if (document.body.classList.contains('sb-open')) {
      if (!sidebar.contains(e.target) && !e.target.closest('#sidebarToggle')) {
        collapse();
      }
    }
  });

  /* Mobile: close on Escape key */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.body.classList.contains('sb-open')) {
      collapse();
    }
  });

  /* ── Public API ────────────────────────────────────────────── */
  const setUser = (name) => {
    const el = document.getElementById('sidebarUsername');
    if (el) el.textContent = name || '—';
  };

  const setAdmin = (isAdmin) => {
    sidebar.querySelectorAll('.sb-admin').forEach((el) => {
      el.style.display = isAdmin ? '' : 'none';
    });
  };

  const setActiveView = (viewId) => {
    sidebar.querySelectorAll('.sb-item').forEach((el) => el.classList.remove('active'));
    const target = sidebar.querySelector(`.sb-item[data-view="${viewId}"]`);
    if (target) target.classList.add('active');
  };

  /* Hide admin items by default */
  setAdmin(false);

  /* ── Dashboard sub-view click handler ──────────────────────
     Only relevant on the dashboard page. dashboard-system.js
     calls switchView() which uses #viewNav .sb-item[data-view]. */

  window.TPLSidebar = Object.freeze({
    setUser,
    setAdmin,
    setActiveView,
    collapse,
    expand,
    toggle,
  });
})();
