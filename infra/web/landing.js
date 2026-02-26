/**
 * TPL Fortress — Login page controller v3.0
 *
 * Handles fortress auth flow: Ed25519 JWT + refresh-token rotation +
 * mandatory password change + dynamic policy from /auth/password-policy.
 * ──────────────────────────────────────────────────────────────────────
 */
(() => {
  'use strict';

  // ── DOM refs ──────────────────────────────────────────────────
  const $  = (id) => document.getElementById(id);
  const o            = $('o');
  const u            = $('u');
  const p            = $('p');
  const go           = $('go');
  const loginForm    = $('loginForm');
  const langSel      = $('lang');
  const togglePw     = $('togglePw');
  const togglePwIcon = $('togglePwIcon');
  const secBadge     = $('secBadge');
  const secLabel     = $('secLabel');
  const sessionInfo  = $('sessionInfo');
  const tokenTTL     = $('tokenTTL');

  // Password-change overlay
  const pwOverlay  = $('pwOverlay');
  const pwCurrent  = $('pwCurrent');
  const pwNew      = $('pwNew');
  const pwConfirm  = $('pwConfirm');
  const pwSubmit   = $('pwSubmit');
  const pwMsg      = $('pwMsg');
  const pwStrength = $('pwStrength');
  const pwMinLen   = $('pwMinLen');

  // ── State ─────────────────────────────────────────────────────
  let _pendingUsername = '';
  let _pendingPassword = '';
  let _pwPolicy        = null;        // fetched from server
  let _loginBusy       = false;

  // ── Toast helpers ─────────────────────────────────────────────
  const msg = (text, cls = 'info') => {
    if (!o) return;
    o.className = `ov-toast ov-toast--${cls}`;
    o.textContent = text;
    o.style.display = 'block';
  };

  const pwm = (text, cls = 'info') => {
    if (!pwMsg) return;
    pwMsg.className = `ov-toast ov-toast--${cls} mt-3`;
    pwMsg.textContent = text;
    pwMsg.style.display = 'block';
  };

  // ── Password visibility toggle ────────────────────────────────
  if (togglePw && p) {
    togglePw.addEventListener('click', () => {
      const hidden = p.type === 'password';
      p.type = hidden ? 'text' : 'password';
      if (togglePwIcon) togglePwIcon.className = hidden ? 'bi bi-eye-slash' : 'bi bi-eye';
    });
  }

  // ── Security badge ────────────────────────────────────────────
  if (secBadge) {
    const secure = location.protocol === 'https:' || location.hostname === 'localhost';
    if (!secure) {
      secBadge.classList.add('ov-security-badge--insecure');
      if (secLabel) secLabel.textContent = 'Connessione non sicura';
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  Password policy (fetched from /auth/password-policy)
  // ────────────────────────────────────────────────────────────────
  const FALLBACK_POLICY = {
    min_length: 14, require_upper: true, require_lower: true,
    require_digit: true, require_special: true, min_entropy: 3.0,
  };

  const fetchPasswordPolicy = async () => {
    try {
      _pwPolicy = await TPL.jsonFetch('/api/auth/password-policy');
      if (pwMinLen && _pwPolicy.min_length) {
        pwMinLen.textContent = String(_pwPolicy.min_length);
      }
    } catch (_) {
      _pwPolicy = { ...FALLBACK_POLICY };
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Password validation (7 rules)
  // ────────────────────────────────────────────────────────────────
  const checkRules = () => {
    const nv     = pwNew     ? pwNew.value     : '';
    const cv     = pwConfirm ? pwConfirm.value : '';
    const minLen = (_pwPolicy && _pwPolicy.min_length) || 14;

    const rules = {
      len:     nv.length >= minLen,
      upper:   /[A-Z]/.test(nv),
      lower:   /[a-z]/.test(nv),
      digit:   /[0-9]/.test(nv),
      special: /[^A-Za-z0-9]/.test(nv),
      match:   nv.length > 0 && nv === cv,
      noUser:  nv.length > 0 && _pendingUsername.length > 0
                 ? !nv.toLowerCase().includes(_pendingUsername.toLowerCase())
                 : true,
    };

    // Update visual indicators
    for (const [key, ok] of Object.entries(rules)) {
      const el = $('pwRule' + key.charAt(0).toUpperCase() + key.slice(1));
      if (!el) continue;
      el.className = ok ? 'ov-pw-rule-ok' : '';
      const icon = el.querySelector('i');
      if (icon) icon.className = ok ? 'bi bi-check-circle-fill' : 'bi bi-x-circle';
    }

    // Strength bar
    const score = Object.values(rules).filter(Boolean).length;
    const total = Object.keys(rules).length;
    const pct   = Math.round((score / total) * 100);
    const color = pct < 30 ? '#dc3545' : pct < 60 ? '#ffc107' : pct < 100 ? '#0dcaf0' : '#198754';
    const label = pct < 30 ? 'Molto debole' : pct < 60 ? 'Debole'
                : pct < 85 ? 'Media' : pct < 100 ? 'Buona' : 'Forte';
    if (pwStrength) {
      pwStrength.innerHTML =
        `<div class="ov-pw-bar"><div style="width:${pct}%;background:${color}"></div></div>` +
        `<small style="color:${color}">${label}</small>`;
    }

    const allOk = Object.values(rules).every(Boolean);
    if (pwSubmit) pwSubmit.disabled = !allOk;
    return allOk;
  };

  // ────────────────────────────────────────────────────────────────
  //  Password change overlay
  // ────────────────────────────────────────────────────────────────
  const showPasswordChange = (username, password) => {
    _pendingUsername = username;
    _pendingPassword = password;
    if (pwCurrent) pwCurrent.value = password;
    if (pwNew)     pwNew.value     = '';
    if (pwConfirm) pwConfirm.value = '';
    if (pwMsg) pwMsg.style.display = 'none';
    checkRules();
    if (pwOverlay) pwOverlay.style.display = 'flex';
    if (pwNew) pwNew.focus();
    fetchPasswordPolicy();      // refresh policy while user types
  };

  const doPasswordChange = async () => {
    if (!checkRules()) return;
    if (pwSubmit) pwSubmit.disabled = true;
    pwm('Cambio password in corso…', 'info');
    try {
      await TPL.jsonFetch('/api/users/me/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          current_password: pwCurrent.value,
          new_password:     pwNew.value,
        }),
      });
      pwm('Password cambiata! Effettua il login con la nuova password.', 'success');
      // Destroy session server-side + wipe local state, then back to login
      await TPL.logout();                // revokes refresh token, clears storage, redirects to /
    } catch (e) {
      pwm(`Errore: ${e.message || String(e)}`, 'danger');
      if (pwSubmit) pwSubmit.disabled = false;
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Store fortress auth response
  // ────────────────────────────────────────────────────────────────
  const _storeAuthResponse = (d) => {
    if (typeof d === 'object' && d.access_token) {
      TPL.setToken(d.access_token);
      TPL.setRefreshToken(d.refresh_token  || '');
      TPL.setSessionId(d.session_id        || '');
      // Show session-info badge
      if (sessionInfo && d.expires_in) {
        if (tokenTTL) tokenTTL.textContent = String(Math.floor(d.expires_in / 60));
        sessionInfo.style.display = 'block';
      }
    } else {
      // Legacy / keycloak compat
      TPL.setToken(d.access_token || '');
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Login
  // ────────────────────────────────────────────────────────────────
  const doLogin = async (e) => {
    if (e) e.preventDefault();
    if (_loginBusy) return;
    _loginBusy = true;

    const username = (u ? u.value : '').trim();
    const password = p ? p.value : '';

    if (!username || !password) {
      msg(TPL.t('login.enter_creds', 'Inserisci username e password.'), 'warning');
      _loginBusy = false;
      return;
    }

    msg(TPL.t('login.logging_in', 'Login in corso…'), 'info');
    if (go) { go.disabled = true; go.classList.add('ov-login-btn--loading'); }

    try {
      const d = await TPL.jsonFetch('/api/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      _storeAuthResponse(d);

      // Fetch user profile
      const me = await TPL.jsonFetch('/api/me');

      // Mandatory password change?
      if (me.must_change_password) {
        msg('Cambio password obbligatorio al primo accesso.', 'warning');
        showPasswordChange(username, password);
        _loginBusy = false;
        if (go) { go.disabled = false; go.classList.remove('ov-login-btn--loading'); }
        return;
      }

      msg(TPL.t('login.success', 'Accesso riuscito. Reindirizzamento…'), 'success');
      setTimeout(() => { location.href = TPL.roleRoute(me.roles || []); }, 600);
    } catch (e) {
      msg(`${TPL.t('msg.error', 'Errore')}: ${e.message || String(e)}`, 'danger');
      _loginBusy = false;
      if (go) { go.disabled = false; go.classList.remove('ov-login-btn--loading'); }
    }
  };

  // ────────────────────────────────────────────────────────────────
  //  Event bindings
  // ────────────────────────────────────────────────────────────────
  if (loginForm) loginForm.addEventListener('submit', doLogin);
  if (go) go.addEventListener('click', doLogin);
  if (u)  u.addEventListener('keydown', e => { if (e.key === 'Enter') (p ? p.focus() : doLogin()); });

  // Password-change events
  if (pwNew)     pwNew.addEventListener('input', checkRules);
  if (pwConfirm) pwConfirm.addEventListener('input', checkRules);
  if (pwConfirm) pwConfirm.addEventListener('keydown', e => {
    if (e.key === 'Enter' && pwSubmit && !pwSubmit.disabled) doPasswordChange();
  });
  if (pwSubmit) pwSubmit.addEventListener('click', doPasswordChange);

  // Language selector
  if (langSel) {
    langSel.value = TPL.getLang();
    langSel.addEventListener('change', async () => {
      TPL.setLang(langSel.value);
      await TPL.applyI18n();
    });
  }

  // ────────────────────────────────────────────────────────────────
  //  Boot — check existing session / auto-redirect
  // ────────────────────────────────────────────────────────────────
  (async () => {
    await TPL.applyI18n();

    if (TPL.token()) {
      try {
        const me = await TPL.jsonFetch('/api/me');
        if (me.must_change_password) {
          showPasswordChange(me.sub, '');
          return;
        }
        location.href = TPL.roleRoute(me.roles || []);
      } catch (_) {
        // Token expired / revoked — clear everything
        TPL.setToken('');
        TPL.setRefreshToken('');
        TPL.setSessionId('');
      }
    }

    // Pre-fetch password policy so the modal is ready instantly
    fetchPasswordPolicy();
  })();
})();
