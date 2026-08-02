'use strict';

// The interactive screens. They intentionally look like a stripped-down
// Microsoft sign-in experience (same steps, same field names) but are branded
// as a mock so nobody mistakes one for the real thing.

const { escapeHtml: esc } = require('../../shared/http');

const STYLE = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif; background:#f3f2f1; color:#201f1e; padding:24px; }
.card { background:#fff; width:min(440px,100%); padding:36px 44px 32px; box-shadow:0 2px 6px rgba(0,0,0,.18); }
.wide { width:min(920px,100%); }
h1 { font-size:24px; font-weight:600; margin:0 0 4px; }
h2 { font-size:16px; font-weight:600; margin:24px 0 8px; }
p { font-size:14px; line-height:1.5; margin:8px 0; }
.muted { color:#605e5c; font-size:13px; }
label { display:block; font-size:13px; margin:14px 0 4px; }
input[type=text], input[type=password] { width:100%; padding:9px 10px; border:1px solid #605e5c; border-radius:2px; font-size:15px; background:#fff; color:#201f1e; }
button { margin-top:20px; padding:9px 24px; border:0; background:#0067b8; color:#fff; font-size:15px; cursor:pointer; border-radius:2px; }
button.secondary { background:#fff; color:#201f1e; border:1px solid #8a8886; margin-right:8px; }
button:hover { filter:brightness(1.08); }
.banner { background:#fff4ce; border-left:4px solid #ffb900; padding:8px 12px; font-size:12px; margin-bottom:24px; }
.accounts { list-style:none; padding:0; margin:16px 0 0; border-top:1px solid #edebe9; }
.accounts li { border-bottom:1px solid #edebe9; }
.accounts button { width:100%; margin:0; text-align:left; background:none; color:inherit; padding:12px 4px; display:flex; gap:12px; align-items:center; }
.avatar { width:32px; height:32px; border-radius:50%; background:#0067b8; color:#fff; display:grid; place-items:center; font-size:13px; flex:0 0 auto; }
.err { background:#fde7e9; border-left:4px solid #a80000; padding:10px 12px; font-size:13px; margin:16px 0; white-space:pre-wrap; }
code, pre { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size:12.5px; }
pre { background:#faf9f8; border:1px solid #edebe9; padding:12px; overflow:auto; }
table { border-collapse:collapse; width:100%; font-size:13px; margin-top:8px; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #edebe9; vertical-align:top; }
th { color:#605e5c; font-weight:600; }
a { color:#0067b8; }
.scopes { margin:12px 0; padding:0; list-style:none; }
.scopes li { padding:6px 0; border-bottom:1px solid #edebe9; font-size:14px; }
@media (prefers-color-scheme: dark) {
  body { background:#1b1a19; color:#f3f2f1; }
  .card { background:#292827; box-shadow:none; border:1px solid #3b3a39; }
  input[type=text], input[type=password] { background:#1b1a19; color:#f3f2f1; border-color:#605e5c; }
  button.secondary { background:#292827; color:#f3f2f1; }
  pre { background:#1b1a19; border-color:#3b3a39; }
  th, td, .accounts li, .accounts, .scopes li { border-color:#3b3a39; }
  .banner { background:#433519; border-color:#ffb900; }
  .err { background:#442726; border-color:#f1707b; }
}
`;

function layout(title, body, { wide = false } = {}) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head>
<body><main class="card${wide ? ' wide' : ''}">${body}</main></body></html>`;
}

function hiddenFields(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('\n');
}

function initials(name) {
  return String(name || '?')
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0])
    .join('')
    .toUpperCase();
}

function loginPage({ tenant, app, users, requestParams, error, prefillUsername, showPasswordHints }) {
  const accounts = users
    .map(
      (u) => `<li><button type="submit" name="username" value="${esc(u.userPrincipalName)}">
        <span class="avatar">${esc(initials(u.displayName))}</span>
        <span><strong>${esc(u.displayName)}</strong><br><span class="muted">${esc(u.userPrincipalName)}</span></span>
      </button></li>`,
    )
    .join('\n');

  return layout('Sign in to your account', `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; test identity provider. Not Microsoft.</div>
    <h1>Sign in</h1>
    <p class="muted">to continue to <strong>${esc(app.displayName)}</strong> &middot; ${esc(tenant.displayName)}</p>
    ${error ? `<div class="err">${esc(error)}</div>` : ''}
    <form method="post" action="/${esc(tenant.id)}/login">
      ${hiddenFields(requestParams)}
      <label for="username">Email or username</label>
      <input id="username" name="username" type="text" autocomplete="username" required value="${esc(prefillUsername || '')}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
      <h2>Pick a test account</h2>
      <ul class="accounts">${accounts}</ul>
      ${showPasswordHints ? `<p class="muted">Passwords come from <code>directory.json</code>; the seeded accounts all use <code>Passw0rd!</code>. Choosing an account above still requires the password.</p>` : ''}
    </form>`);
}

function consentPage({ tenant, app, user, scopes, requestParams }) {
  const list = scopes.map((s) => `<li><code>${esc(s)}</code></li>`).join('');
  return layout('Permissions requested', `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; test identity provider. Not Microsoft.</div>
    <h1>Permissions requested</h1>
    <p class="muted">${esc(app.displayName)} &middot; ${esc(tenant.displayName)}</p>
    <p>Signed in as <strong>${esc(user.userPrincipalName)}</strong></p>
    <p>This application would like to:</p>
    <ul class="scopes">${list}</ul>
    <form method="post" action="/${esc(tenant.id)}/consent">
      ${hiddenFields(requestParams)}
      <button class="secondary" type="submit" name="decision" value="deny">Cancel</button>
      <button type="submit" name="decision" value="accept">Accept</button>
    </form>`);
}

function devicePage({ tenant, userCode = '', error, message }) {
  return layout('Enter code', `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; device sign-in. Not Microsoft.</div>
    <h1>Enter code</h1>
    ${message ? `<p>${esc(message)}</p>` : '<p class="muted">Enter the code displayed by your app or device.</p>'}
    ${error ? `<div class="err">${esc(error)}</div>` : ''}
    ${message ? '' : `<form method="post" action="/${esc(tenant.id)}/oauth2/deviceauth">
      <label for="user_code">Code</label>
      <input id="user_code" name="user_code" type="text" required value="${esc(userCode)}" autocomplete="off">
      <button type="submit">Next</button>
    </form>`}`);
}

function messagePage(title, bodyHtml) {
  return layout(title, `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; test identity provider. Not Microsoft.</div>
    <h1>${esc(title)}</h1>${bodyHtml}`);
}

function errorPage(err) {
  return layout('Sign-in error', `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; test identity provider. Not Microsoft.</div>
    <h1>Sign-in error</h1>
    <div class="err">${esc(err.description || err.message)}</div>
    <p class="muted">The real Entra ID shows this page when it cannot safely redirect the error back to the application &mdash; usually an unregistered <code>redirect_uri</code> or an unknown <code>client_id</code>.</p>`);
}

/** response_mode=form_post: auto-submitting form, exactly as Entra returns it. */
function formPostPage(redirectUri, params) {
  return `<!doctype html><html><head><title>Working...</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${esc(redirectUri)}">
${hiddenFields(params)}
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`;
}

function homePage({ tenant, issuer, baseUrl, apps, users, log }) {
  const appRows = apps
    .map(
      (a) => `<tr><td><strong>${esc(a.displayName)}</strong></td><td><code>${esc(a.appId)}</code></td>
        <td>${a.isPublicClient ? 'public' : 'confidential'}</td>
        <td>${esc((a.allowedGrants || []).join(', '))}</td>
        <td>${(a.redirectUris || []).map((u) => `<code>${esc(u)}</code>`).join('<br>') || '&mdash;'}</td></tr>`,
    )
    .join('');
  const userRows = users
    .map(
      (u) => `<tr><td>${esc(u.displayName)}</td><td><code>${esc(u.userPrincipalName)}</code></td>
        <td><code>${esc(u.objectId)}</code></td>
        <td>${u.accountEnabled === false ? 'disabled' : u.requiresMfa ? 'MFA required' : 'enabled'}</td></tr>`,
    )
    .join('');
  const logRows = log
    .slice(0, 25)
    .map(
      (l) => `<tr><td class="muted">${esc(l.at)}</td><td>${esc(l.event)}</td><td>${esc(l.detail || '')}</td></tr>`,
    )
    .join('') || '<tr><td colspan="3" class="muted">No requests yet.</td></tr>';

  return layout('Mock Entra ID', `
    <div class="banner"><strong>Mock Entra ID</strong> &mdash; a local stand-in for login.microsoftonline.com. Not Microsoft.</div>
    <h1>Mock Entra ID</h1>
    <p class="muted">Tenant <strong>${esc(tenant.displayName)}</strong> &middot; <code>${esc(tenant.id)}</code></p>
    <h2>Endpoints</h2>
    <pre>authority     ${esc(baseUrl)}/${esc(tenant.id)}
issuer        ${esc(issuer)}
discovery     ${esc(baseUrl)}/${esc(tenant.id)}/v2.0/.well-known/openid-configuration
jwks          ${esc(baseUrl)}/${esc(tenant.id)}/discovery/v2.0/keys
authorize     ${esc(baseUrl)}/${esc(tenant.id)}/oauth2/v2.0/authorize
token         ${esc(baseUrl)}/${esc(tenant.id)}/oauth2/v2.0/token
logout        ${esc(baseUrl)}/${esc(tenant.id)}/oauth2/v2.0/logout
devicecode    ${esc(baseUrl)}/${esc(tenant.id)}/oauth2/v2.0/devicecode
graph (mock)  ${esc(baseUrl)}/v1.0/me</pre>
    <h2>App registrations</h2>
    <table><tr><th>Name</th><th>Application (client) ID</th><th>Type</th><th>Grants</th><th>Redirect URIs</th></tr>${appRows}</table>
    <h2>Users</h2>
    <table><tr><th>Name</th><th>UPN</th><th>Object ID</th><th>State</th></tr>${userRows}</table>
    <h2>Recent requests</h2>
    <table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>${logRows}</table>`, { wide: true });
}

module.exports = { layout, loginPage, consentPage, devicePage, errorPage, formPostPage, homePage, messagePage };
