/**
 * TPL Platform — Sidebar v5.0  «Aurora»
 *
 * Crystalline navigation panel featuring:
 *   • Deep-space gradient surface with aurora edge strip
 *   • Clean capsule-style active states with glow indicator
 *   • Smooth collapse to icons-only with spring transitions
 *   • Section dividers with luminous gradient accents
 *   • Scroll-fade masks on overflow
 *   • User presence card with status ring
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

  /* ── Navigation definition ─────────────────────────────────── */
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

  /* ── Detect current page ───────────────────────────────────── */
  const PAGE = (() => {
    const p = location.pathname;
    if (p.startsWith('/admin/modules')) return 'admin-modules';
    if (p.startsWith('/diagnostics'))   return 'diagnostics';
    if (p.startsWith('/ota'))           return 'ota';
    if (p.startsWith('/advanced'))      return 'advanced';
    return 'dashboard';
  })();

  /* ── Build sidebar DOM ─────────────────────────────────────── */
  const buildSidebar = () => {
    const aside = document.createElement('aside');
    aside.id = 'appSidebar';
    aside.setAttribute('role', 'navigation');
    aside.setAttribute('aria-label', 'Main navigation');

    aside.innerHTML = `
      <div class="sb-aurora-strip"></div>

      <div class="sb-brand">
        <a href="/dashboard" class="sb-brand-link" aria-label="TPL Platform Dashboard">
          <span class="sb-brand-icon">
            <svg viewBox="0 0 28 28" fill="none" width="20" height="20">
              <path d="M14 3L3 9l11 5 11-5L14 3z" fill="url(#aG1)" opacity=".95"/>
              <path d="M3 19l11 5 11-5" stroke="url(#aG2)" stroke-width="1.5" stroke-linecap="round" fill="none" opacity=".55"/>
              <path d="M3 14l11 5 11-5" stroke="url(#aG2)" stroke-width="1.5" stroke-linecap="round" fill="none" opacity=".8"/>
              <defs>
                <linearGradient id="aG1" x1="3" y1="3" x2="25" y2="14">
                  <stop offset="0%" stop-color="#6366f1"/>
                  <stop offset="100%" stop-color="#06b6d4"/>
                </linearGradient>
                <linearGradient id="aG2" x1="3" y1="14" x2="25" y2="24">
                  <stop offset="0%" stop-color="#818cf8"/>
                  <stop offset="100%" stop-color="#22d3ee"/>
                </linearGradient>
              </defs>
            </svg>
          </span>
          <span class="sb-brand-text">TPL<span class="sb-brand-accent"> Platform</span></span>
        </a>
        <button class="sb-collapse-btn" id="sbCollapseInner" type="button" aria-label="Collapse sidebar">
          <i class="bi bi-sidebar"></i>
        </button>
      </div>

      <div class="sb-scroll-mask sb-scroll-mask--top"></div>
      <nav class="sb-menu" id="viewNav" aria-label="Navigation menu"></nav>
      <div class="sb-scroll-mask sb-scroll-mask--bottom"></div>

      <div class="sb-footer" id="sidebarFooter">
        <div class="sb-user">
          <div class="sb-user-avatar">
            <i class="bi bi-person-fill"></i>
            <span class="sb-user-presence"></span>
          </div>
          <div class="sb-user-info">
            <span class="sb-user-name" id="sidebarUsername">\u2014</span>
            <span class="sb-user-role" id="sidebarRole">user</span>
          </div>
        </div>
        <div class="sb-kbd-hint">
          <kbd>Ctrl</kbd><span>+</span><kbd>B</kbd>
        </div>
      </div>`;

    const nav = aside.querySelector('#viewNav');

    NAV.forEach((item) => {
      if (item.section) {
        const div = document.createElement('div');
        div.className = 'sb-section' + (item.admin ? ' sb-admin' : '');
        div.innerHTML = `<span class="sb-section-line"></span><span class="sb-section-text">${item.section}</span><span class="sb-section-line"></span>`;
        nav.appendChild(div);
        return;
      }

      const a = document.createElement('a');
      a.className = 'sb-item' + (item.admin ? ' sb-admin' : '');

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

      if (isActive) a.classList.add('active');

      a.innerHTML = `
        <span class="sb-item-indicator"></span>
        <span class="sb-item-icon"><i class="bi ${item.icon}"></i></span>
        <span class="sb-item-label">${item.label}</span>
        <span class="sb-item-tooltip">${item.label}</span>`;
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
    const wrapper = document.querySelector('.app-wrapper') || document.body;
    const main = wrapper.querySelector('main') || wrapper.querySelector('.app-main');
    if (main) wrapper.insertBefore(sidebar, main);
    else wrapper.prepend(sidebar);
  }

  /* ── Scroll fade masks ─────────────────────────────────────── */
  const menu = sidebar.querySelector('.sb-menu');
  const maskTop = sidebar.querySelector('.sb-scroll-mask--top');
  const maskBottom = sidebar.querySelector('.sb-scroll-mask--bottom');

  const updateScrollMasks = () => {
    if (!menu) return;
    const t = menu.scrollTop;
    const h = menu.scrollHeight - menu.clientHeight;
    if (maskTop) maskTop.classList.toggle('visible', t > 8);
    if (maskBottom) maskBottom.classList.toggle('visible', t < h - 8);
  };
  menu?.addEventListener('scroll', updateScrollMasks, { passive: true });
  requestAnimationFrame(updateScrollMasks);

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
    setTimeout(updateScrollMasks, 350);
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

  /* Toggle buttons */
  document.getElementById('sidebarToggle')?.addEventListener('click', (e) => {
    e.preventDefault();
    toggle();
  });
  document.getElementById('sbCollapseInner')?.addEventListener('click', (e) => {
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

  /* Keyboard shortcuts */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.body.classList.contains('sb-open')) collapse();
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') { e.preventDefault(); toggle(); }
  });

  /* ── Public API ────────────────────────────────────────────── */
  const setUser = (name, role) => {
    const el = document.getElementById('sidebarUsername');
    if (el) el.textContent = name || '\u2014';
    const rl = document.getElementById('sidebarRole');
    if (rl && role) rl.textContent = role;
  };

  const setAdmin = (isAdmin) => {
    sidebar.querySelectorAll('.sb-admin').forEach((el) => {
      el.style.display = isAdmin ? '' : 'none';
    });
    const rl = document.getElementById('sidebarRole');
    if (rl) rl.textContent = isAdmin ? 'admin' : 'user';
  };

  const setActiveView = (viewId) => {
    sidebar.querySelectorAll('.sb-item').forEach((el) => el.classList.remove('active'));
    const target = sidebar.querySelector(`.sb-item[data-view="${viewId}"]`);
    if (target) target.classList.add('active');
  };

  /* Hide admin items by default */
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
