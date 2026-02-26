#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"30_web_gui","ver":"1.2.0","deps":["10_traefik"],"desc":"Professional GUI + hardened nginx headers + admin audit panel"}
JSON
}

apply(){
  # Idempotency guard: if enhanced dashboard already exists, skip
  if [[ -f infra/web/dashboard-system.js ]] && [[ -f infra/web/sidebar.js ]]; then
    echo "SKIP 30_web_gui: enhanced frontend already exists" >&2
    return 0
  fi
  mkdir -p infra/web compose.d

  cat > infra/web/nginx.conf <<'NGX'
server {
  listen 80;
  server_name _;
  server_tokens off;

  root /usr/share/nginx/html;
  index index.html;

  location = /login { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store" always; try_files /login.html =404; }
  location = /dashboard { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store" always; try_files /dashboard.html =404; }
  location = /admin { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store" always; try_files /admin.html =404; }
  location = /admin/modules { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store" always; try_files /admin-modules.html =404; }
  location = /advanced { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store" always; try_files /advanced.html =404; }

  location ~* ^/(index|login|dashboard|admin|admin-modules|advanced)\.html$ { add_header X-Frame-Options "DENY" always; add_header X-Content-Type-Options "nosniff" always; add_header Referrer-Policy "no-referrer" always; add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always; add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0" always; add_header Pragma "no-cache" always; add_header Expires "0" always; }

  location / {
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; script-src 'self'; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0" always;
    add_header Pragma "no-cache" always;
    add_header Expires "0" always;
    try_files $uri $uri/ /index.html;
  }
}
NGX

  cat > infra/web/index.html <<'HTML'
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TPL · Control Center</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="/styles.css" rel="stylesheet">
</head>
<body>
  <nav class="navbar navbar-expand-lg nav-pro border-bottom"><div class="container"><a class="navbar-brand fw-semibold" href="/">TPL Control Center</a><div class="ms-auto d-flex gap-2"><a class="btn btn-outline-secondary btn-sm" href="/advanced">Security & Dev</a><a class="btn btn-primary btn-sm" href="/login">Accedi</a></div></div></nav>
  <main class="container py-4 py-lg-5"><div class="row g-4 align-items-stretch"><section class="col-12 col-lg-8"><div class="card shadow-soft h-100 border-0 rounded-4"><div class="card-body p-4 p-lg-5"><span class="badge text-bg-primary mb-3">Enterprise Ready</span><h1 class="h3 mb-2">Dashboard professionale per utenti e amministratori</h1><p class="text-muted mb-4">Gestione accessi, monitoraggio stack, operazioni modulo e verifiche sicurezza in un unico punto.</p><div class="d-flex flex-wrap gap-2"><a class="btn btn-success" href="/dashboard">Apri dashboard</a><a class="btn btn-outline-primary" href="/admin">Area admin</a></div></div></div></section><section class="col-12 col-lg-4"><div class="card shadow-soft h-100 border-0 rounded-4"><div class="card-body p-4"><h2 class="h6 mb-3">Runtime status</h2><div class="small text-muted mb-3">API/health e modalità auth in tempo reale.</div><button class="btn btn-outline-primary btn-sm" id="chk" type="button">Aggiorna stato</button><pre class="status-box mt-3 mb-0" id="st">—</pre></div></div></section></div></main>
  <script src="/app.js" defer></script><script src="/index.js" defer></script>
</body>
</html>
HTML

  cat > infra/web/login.html <<'HTML'
<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TPL · Login</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="/styles.css" rel="stylesheet"></head>
<body><main class="container py-5" style="max-width:560px;"><div class="card shadow-soft rounded-4 border-0"><div class="card-body p-4 p-lg-5"><h1 class="h4 mb-1">Accesso sicuro</h1><p class="text-muted small mb-3">Session token in <strong>sessionStorage</strong>.</p><div class="vstack gap-2"><label class="small text-muted" for="u">Username</label><input class="form-control" id="u" autocomplete="username" maxlength="64" placeholder="Username"><label class="small text-muted mt-1" for="p">Password</label><input class="form-control" id="p" type="password" autocomplete="current-password" maxlength="128" placeholder="Password"><button class="btn btn-primary mt-2" id="go" type="button">Accedi</button><a class="btn btn-outline-secondary" href="/">Torna alla home</a></div><div class="alert alert-info small mt-3 mb-0" id="o">—</div></div></div></main><script src="/app.js" defer></script><script src="/login.js" defer></script></body></html>
HTML

  cat > infra/web/dashboard.html <<'HTML'
<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TPL · User Dashboard</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="/styles.css" rel="stylesheet"></head>
<body><nav class="navbar nav-pro border-bottom"><div class="container"><a class="navbar-brand fw-semibold" href="/">TPL Dashboard</a><div class="ms-auto d-flex gap-2"><a class="btn btn-outline-secondary btn-sm" href="/advanced">Avanzate</a><button class="btn btn-outline-danger btn-sm" id="lo" type="button">Logout</button></div></div></nav><main class="container py-4 py-lg-5"><div class="row g-4"><section class="col-12 col-lg-4"><div class="card shadow-soft border-0 rounded-4 h-100"><div class="card-body p-4"><h2 class="h6">Profilo</h2><div class="small text-muted mb-2">Identità e ruoli attivi</div><pre class="status-box" id="me">—</pre></div></div></section><section class="col-12 col-lg-8"><div class="card shadow-soft border-0 rounded-4 h-100"><div class="card-body p-4"><h2 class="h6 mb-3">Workspace</h2><div class="row g-3"><div class="col-12 col-md-6"><a class="btn btn-primary w-100 py-3" href="/admin" id="abtn">Admin Console</a></div><div class="col-12 col-md-6"><a class="btn btn-outline-primary w-100 py-3" href="/admin/modules" id="mbtn">Module Orchestrator</a></div><div class="col-12"><button class="btn btn-outline-secondary w-100" id="statusRefresh" type="button">Aggiorna stato API</button><pre class="status-box mt-2 mb-0" id="apiStatus">—</pre></div></div><div class="small text-muted mt-3">Le funzioni admin sono attivabili solo con ruolo <code>admin</code>.</div></div></div></section></div></main><script src="/app.js" defer></script><script src="/dashboard.js" defer></script></body></html>
HTML

  cat > infra/web/admin.html <<'HTML'
<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TPL · Admin Console</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="/styles.css" rel="stylesheet"></head>
<body><nav class="navbar nav-pro border-bottom"><div class="container"><a class="navbar-brand fw-semibold" href="/dashboard">Admin Console</a><div class="ms-auto d-flex gap-2"><a class="btn btn-outline-secondary btn-sm" href="/dashboard">Dashboard</a><a class="btn btn-outline-primary btn-sm" href="/admin/modules">Moduli</a></div></div></nav><main class="container py-4 py-lg-5"><div class="alert alert-warning" id="g">Verifica privilegi amministrativi...</div><div class="card shadow-soft border-0 rounded-4"><div class="card-body p-4"><h1 class="h5 mb-3">Centro operativo amministrazione</h1><div class="row g-3"><div class="col-12 col-lg-4"><div class="metric-card"><div class="metric-label">Integrità API</div><div class="metric-value" id="mApi">—</div></div></div><div class="col-12 col-lg-4"><div class="metric-card"><div class="metric-label">Ruolo attivo</div><div class="metric-value" id="mRole">—</div></div></div><div class="col-12 col-lg-4"><div class="metric-card"><div class="metric-label">Auth mode</div><div class="metric-value" id="mAuth">—</div></div></div><div class="col-12 mt-1"><a class="btn btn-primary" href="/admin/modules">Gestione moduli</a><button class="btn btn-outline-secondary ms-2" id="auditRefresh" type="button">Aggiorna audit</button></div></div></div></div><div class="card shadow-soft border-0 rounded-4 mt-4"><div class="card-body p-4"><h2 class="h6 mb-3">Audit trail (ultimi eventi)</h2><div class="table-responsive"><table class="table table-sm align-middle"><thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Outcome</th><th>IP</th></tr></thead><tbody id="auditRows"><tr><td colspan="5" class="text-muted">Caricamento...</td></tr></tbody></table></div></div></div></main><script src="/app.js" defer></script><script src="/admin.js" defer></script></body></html>
HTML

  cat > infra/web/admin-modules.html <<'HTML'
<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TPL · Admin Modules</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="/styles.css" rel="stylesheet"></head>
<body><nav class="navbar nav-pro border-bottom"><div class="container"><a class="navbar-brand fw-semibold" href="/admin">Admin Modules</a><div class="ms-auto d-flex gap-2"><a class="btn btn-outline-secondary btn-sm" href="/dashboard">Dashboard</a></div></div></nav><main class="container py-4 py-lg-5"><div class="alert alert-warning" id="g">Verifica privilegi amministrativi...</div><div class="card shadow-soft border-0 rounded-4"><div class="card-body p-4"><div class="d-flex flex-wrap gap-2 mb-2"><button class="btn btn-outline-primary btn-sm" id="r" type="button">Aggiorna</button><button class="btn btn-warning btn-sm" id="a" type="button">Installa selezionati</button><button class="btn btn-outline-danger btn-sm" id="x" type="button">Reset stato</button></div><p class="small text-muted mb-2">Le azioni critiche richiedono conferma esplicita e ruolo <code>admin</code>.</p><div id="ml" class="border rounded bg-white p-2" style="min-height:160px;"></div><pre class="status-box mt-2 mb-0" id="o">—</pre></div></div></main><script src="/app.js" defer></script><script src="/admin-modules.js" defer></script></body></html>
HTML

  cat > infra/web/advanced.html <<'HTML'
<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TPL · Advanced & Security</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="/styles.css" rel="stylesheet"></head>
<body><main class="container py-5" style="max-width:820px;"><div class="card shadow-soft border-0 rounded-4"><div class="card-body p-4 p-lg-5"><h1 class="h4 mb-1">Advanced & Security</h1><p class="text-muted mb-3">Endpoint utili per debug operativo, health checks e observability.</p><div class="d-grid gap-2"><a class="btn btn-outline-primary" href="/api/docs" target="_blank" rel="noopener">Swagger</a><a class="btn btn-outline-primary" href="/api/openapi.json" target="_blank" rel="noopener">OpenAPI JSON</a><a class="btn btn-outline-primary" href="/api/health" target="_blank" rel="noopener">Health</a><a class="btn btn-outline-primary" href="/api/status" target="_blank" rel="noopener">Status</a></div><a class="btn btn-outline-secondary mt-3" href="/">Home</a></div></div></main></body></html>
HTML

  cat > infra/web/styles.css <<'CSS'
body{background:linear-gradient(180deg,#f5f7fb 0%,#f9fafc 100%);min-height:100vh}
.nav-pro{background:#ffffffcc;backdrop-filter:blur(6px)}
.shadow-soft{box-shadow:0 10px 35px rgba(32,63,128,.10)}
.status-box{background:#0f172a;color:#dbeafe;border-radius:.75rem;border:1px solid #1e293b;min-height:90px;margin:0;padding:.75rem;white-space:pre-wrap;font-size:.85rem}
.metric-card{border:1px solid #e2e8f0;border-radius:.8rem;padding:.9rem;background:#fff}
.metric-label{color:#64748b;font-size:.8rem;margin-bottom:.25rem}
.metric-value{color:#0f172a;font-size:1.1rem;font-weight:700}
CSS

  cat > infra/web/app.js <<'JS'
(()=>{const K="tpl_token";const H=()=>{const t=sessionStorage.getItem(K)||"";return t?{Authorization:`Bearer ${t}`}:{}};const S=(t)=>{if(!t){sessionStorage.removeItem(K);return;}sessionStorage.setItem(K,t)};const L=()=>{sessionStorage.removeItem(K);location.href="/"};const J=async(u,o={})=>{const r=await fetch(u,{...o,headers:{...(o.headers||{}),...H()}});const tx=await r.text();let d=tx;try{d=JSON.parse(tx)}catch(_){}if(!r.ok)throw new Error(typeof d==="string"?d:JSON.stringify(d));return d};window.TPL={authHeader:H,setToken:S,logout:L,jsonFetch:J,token:()=>sessionStorage.getItem(K)||""};})();
JS

  cat > infra/web/index.js <<'JS'
(()=>{const o=document.getElementById("st"),b=document.getElementById("chk");const f=async()=>{o.textContent="Loading...";try{const s=await TPL.jsonFetch("/api/status"),h=await TPL.jsonFetch("/api/health");o.textContent=JSON.stringify({status:s,health:h},null,2)}catch(e){o.textContent=`ERR: ${String(e)}`}};b&&b.addEventListener("click",f);f();})();
JS

  cat > infra/web/login.js <<'JS'
(()=>{const o=document.getElementById("o"),u=document.getElementById("u"),p=document.getElementById("p"),g=document.getElementById("go");const m=(t,c="alert-info")=>{o.className=`alert ${c} small mt-3 mb-0`;o.textContent=t};g&&g.addEventListener("click",async()=>{m("Login in corso...");const username=(u.value||"").trim(),password=p.value||"";if(!username||!password){m("Inserisci username e password.","alert-warning");return;}try{const d=await TPL.jsonFetch("/api/token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});TPL.setToken(d.access_token||"");m("Accesso riuscito. Redirect in corso...","alert-success");location.href="/dashboard"}catch(e){m(`Errore login: ${String(e)}`,"alert-danger")}});})();
JS

  cat > infra/web/dashboard.js <<'JS'
(()=>{const me=document.getElementById("me"),s=document.getElementById("apiStatus"),a=document.getElementById("abtn"),m=document.getElementById("mbtn"),r=document.getElementById("statusRefresh"),l=document.getElementById("lo");const d=()=>{a&&a.classList.add("disabled");m&&m.classList.add("disabled")};const fs=async()=>{s.textContent="Loading...";try{s.textContent=JSON.stringify(await TPL.jsonFetch("/api/status"),null,2)}catch(e){s.textContent=`ERR: ${String(e)}`}};(async()=>{if(!TPL.token()){location.href="/login";return;}try{const j=await TPL.jsonFetch("/api/me");me.textContent=JSON.stringify(j,null,2);if(!(j.roles||[]).includes("admin"))d()}catch(_){TPL.logout();return;}await fs();})();r&&r.addEventListener("click",fs);l&&l.addEventListener("click",TPL.logout);})();
JS

  cat > infra/web/admin.js <<'JS'
(()=>{const g=document.getElementById("g"),a=document.getElementById("mApi"),r=document.getElementById("mRole"),m=document.getElementById("mAuth"),rows=document.getElementById("auditRows"),rf=document.getElementById("auditRefresh");const deny=()=>{g.className="alert alert-danger";g.textContent="Accesso negato. Privilegi admin richiesti."};const ts=v=>!v?"-":new Date(v*1000).toLocaleString();const render=(items=[])=>{if(!items.length){rows.innerHTML='<tr><td colspan="5" class="text-muted">Nessun evento registrato.</td></tr>';return;}rows.innerHTML=items.slice().reverse().map(x=>`<tr><td>${ts(x.ts)}</td><td><code>${x.actor||"-"}</code></td><td>${x.action||"-"}</td><td><span class="badge text-bg-${x.outcome==="success"?"success":(x.outcome==="failed"?"danger":"warning")}">${x.outcome||"-"}</span></td><td>${x.ip||"-"}</td></tr>`).join("")};const load=async()=>{rows.innerHTML='<tr><td colspan="5" class="text-muted">Caricamento...</td></tr>';try{const d=await TPL.jsonFetch("/api/audit/logs?limit=80");render(d.items||[]);}catch(e){rows.innerHTML=`<tr><td colspan="5" class="text-danger">Errore audit: ${String(e)}</td></tr>`;}};(async()=>{if(!TPL.token()){location.href="/login";return;}try{const me=await TPL.jsonFetch("/api/me");if(!(me.roles||[]).includes("admin")){deny();return;}g.className="alert alert-success";g.textContent=`Accesso autorizzato: ${me.sub}`;r.textContent=(me.roles||[]).join(", ")||"n/a";const st=await TPL.jsonFetch("/api/status");a.textContent=st.ok?"OK":"WARN";m.textContent=st.auth||"n/a";await load();}catch(_){deny();}})();rf&&rf.addEventListener("click",load);})();
JS

  cat > infra/web/admin-modules.js <<'JS'
(()=>{const g=document.getElementById("g"),o=document.getElementById("o"),l=document.getElementById("ml");const out=t=>o.textContent=t;const set=(ok,t)=>{g.className=`alert ${ok?"alert-success":"alert-danger"}`;g.textContent=t};const guard=async()=>{if(!TPL.token()){location.href="/login";return false;}try{const me=await TPL.jsonFetch("/api/me");if(!(me.roles||[]).includes("admin")){set(false,"Accesso negato. Login admin richiesto.");return false;}set(true,`OK admin: ${me.sub}`);return true;}catch(_){set(false,"Sessione non valida.");return false;}};const render=(a=[])=>{if(!a.length){l.innerHTML="<div class='text-muted small'>Nessun modulo disponibile.</div>";return;}l.innerHTML=a.map(x=>`<div class="form-check d-flex align-items-center gap-2 py-1 border-bottom"><input class="form-check-input" type="checkbox" value="${x.id}" id="m_${x.id}"><label class="form-check-label" for="m_${x.id}"><div class="fw-semibold">${x.id}</div><div class="text-muted small">${x.desc||"Core module"}</div></label><span class="badge ${x.installed?"text-bg-success":"text-bg-secondary"} ms-auto">${x.installed?"Installato":"Non installato"}</span></div>`).join("")};const refresh=async()=>{out("Aggiornamento...");try{const j=await TPL.jsonFetch("/api/modules/state");render(j.modules||[]);out(JSON.stringify(j,null,2));}catch(e){out(`ERR: ${String(e)}`)}};const post=(p,b)=>TPL.jsonFetch(p,{method:"POST",headers:{"Content-Type":"application/json","X-Confirm":"YES"},body:JSON.stringify(b)});document.getElementById("r")?.addEventListener("click",async()=>{if(await guard())await refresh();});document.getElementById("a")?.addEventListener("click",async()=>{if(!(await guard()))return;const s=[...document.querySelectorAll("#ml input:checked")].map(e=>e.value);if(!s.length){out("Seleziona almeno un modulo.");return;}if(!confirm("Confermi installazione moduli selezionati?"))return;try{out(JSON.stringify(await post("/api/modules/apply",{modules:s}),null,2));await refresh();}catch(e){out(`ERR: ${String(e)}`)}});document.getElementById("x")?.addEventListener("click",async()=>{if(!(await guard()))return;if(!confirm("Confermi reset stato installazione?"))return;try{out(JSON.stringify(await post("/api/modules/reset",{}),null,2));await refresh();}catch(e){out(`ERR: ${String(e)}`)}});(async()=>{if(await guard())await refresh();})();})();
JS

  cat > compose.d/30-web.yml <<'YML'
services:
  web:
    image: nginx:alpine
    volumes:
      - ./infra/web/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./infra/web:/usr/share/nginx/html:ro
    restart: unless-stopped
YML
}

check(){ true; }
rollback(){ rm -f compose.d/30-web.yml; }
