'use strict';

const { escapeHtml: esc } = require('../../shared/http');

const STYLE = `
:root { color-scheme: light dark; --bg:#faf9f8; --fg:#201f1e; --card:#fff; --line:#e1dfdd; --muted:#605e5c; --accent:#0067b8; }
@media (prefers-color-scheme: dark) { :root { --bg:#1b1a19; --fg:#f3f2f1; --card:#252423; --line:#3b3a39; --muted:#a19f9d; --accent:#4aa3e8; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }
header { background:var(--card); border-bottom:1px solid var(--line); padding:14px 24px; display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
header strong { font-size:15px; }
nav { margin-left:auto; display:flex; gap:14px; font-size:14px; }
main { max-width:900px; margin:0 auto; padding:24px; }
h1 { font-size:22px; margin:0 0 4px; }
h2 { font-size:15px; margin:28px 0 8px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
p { line-height:1.55; font-size:14px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:20px 22px; margin-bottom:16px; }
a { color:var(--accent); }
a.btn, button { display:inline-block; background:var(--accent); color:#fff; border:0; border-radius:4px; padding:9px 18px;
  font-size:14px; cursor:pointer; text-decoration:none; margin:4px 6px 0 0; font-family:inherit; }
a.btn.secondary, button.secondary { background:transparent; color:var(--fg); border:1px solid var(--line); }
pre { background:var(--bg); border:1px solid var(--line); border-radius:4px; padding:12px; overflow:auto; font-size:12.5px;
  font-family:ui-monospace,"Cascadia Code",Consolas,monospace; }
table { border-collapse:collapse; width:100%; font-size:13.5px; }
td, th { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { width:34%; color:var(--muted); font-weight:600; }
.err { background:#fde7e9; color:#4b1113; border-left:4px solid #a80000; padding:12px 14px; border-radius:4px; font-size:13.5px; white-space:pre-wrap; }
.pill { display:inline-block; background:var(--bg); border:1px solid var(--line); border-radius:999px; padding:2px 10px; font-size:12px; margin-right:6px; }
.muted { color:var(--muted); font-size:13px; }
`;

function layout(title, body, { user } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>${STYLE}</style></head><body>
<header><strong>Sample App</strong><span class="muted">protected by Entra ID</span>
<nav>${
    user
      ? `<a href="/">Profile</a><a href="/api/me">Graph /me</a><a href="/admin">Admin</a><a href="/logout">Sign out</a>`
      : `<a href="/login">Sign in</a>`
  }</nav></header>
<main>${body}</main></body></html>`;
}

function claimsTable(claims) {
  return `<table>${Object.entries(claims)
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${
      Array.isArray(v) ? v.map((i) => `<span class="pill">${esc(i)}</span>`).join('') : `<code>${esc(v)}</code>`
    }</td></tr>`)
    .join('')}</table>`;
}

function signedOut({ authority, clientId }) {
  return layout('Sign in', `
    <div class="card">
      <h1>You are signed out</h1>
      <p>This app uses the OpenID Connect authorization code flow with PKCE against
      <code>${esc(authority)}</code> as client <code>${esc(clientId)}</code>.</p>
      <a class="btn" href="/login">Sign in</a>
      <a class="btn secondary" href="/login?prompt=select_account">Sign in with a different account</a>
    </div>`);
}

function profile({ user, claims, tokenResponse, accessTokenClaims }) {
  return layout('Profile', `
    <div class="card">
      <h1>Signed in as ${esc(claims.name || claims.preferred_username)}</h1>
      <p class="muted">${esc(claims.preferred_username)} &middot; object id <code>${esc(claims.oid)}</code></p>
      <a class="btn" href="/api/me">Call Microsoft Graph</a>
      <a class="btn secondary" href="/refresh">Refresh tokens</a>
      <a class="btn secondary" href="/logout">Sign out</a>
    </div>
    <div class="card"><h2>id_token claims</h2>${claimsTable(claims)}</div>
    <div class="card"><h2>access token claims</h2>${
      accessTokenClaims ? claimsTable(accessTokenClaims) : '<p class="muted">Opaque to this app.</p>'
    }</div>
    <div class="card"><h2>token response</h2><pre>${esc(JSON.stringify({
      ...tokenResponse,
      access_token: `${String(tokenResponse.access_token).slice(0, 24)}…`,
      id_token: `${String(tokenResponse.id_token).slice(0, 24)}…`,
      refresh_token: tokenResponse.refresh_token ? `${String(tokenResponse.refresh_token).slice(0, 16)}…` : undefined,
    }, null, 2))}</pre></div>`, { user: true });
}

function graphResult(data) {
  return layout('Microsoft Graph', `
    <div class="card">
      <h1>GET /v1.0/me</h1>
      <p class="muted">Called with the access token this app received, using the same code path a real Graph call uses.</p>
      <pre>${esc(JSON.stringify(data, null, 2))}</pre>
      <a class="btn secondary" href="/">Back</a>
    </div>`, { user: true });
}

function adminPage({ allowed, roles }) {
  return layout('Admin', `
    <div class="card">
      <h1>Admin area</h1>
      ${allowed
        ? '<p>Access granted. Your token carries the <span class="pill">Admin</span> app role.</p>'
        : `<div class="err">403 Forbidden - this page requires the "Admin" app role. Your roles: ${
            roles.length ? esc(roles.join(', ')) : '(none)'
          }</div>`}
      <a class="btn secondary" href="/">Back</a>
    </div>`, { user: true });
}

function errorPage(title, detail, { signedIn = false } = {}) {
  return layout(title, `
    <div class="card">
      <h1>${esc(title)}</h1>
      <div class="err">${esc(detail)}</div>
      <a class="btn secondary" href="/">Back</a>
    </div>`, { user: signedIn });
}

module.exports = { layout, signedOut, profile, graphResult, adminPage, errorPage };
