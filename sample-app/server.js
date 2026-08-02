'use strict';

/**
 * Sample web application protected by Entra ID.
 *
 * It is written against the OpenID Connect and Microsoft Graph contracts, not
 * against the mock: every provider-specific value comes from configuration.
 * To go live, change AUTH_AUTHORITY / AUTH_CLIENT_ID / AUTH_CLIENT_SECRET /
 * GRAPH_BASE_URL to the real ones - no code changes. See docs/going-live.md.
 */

const http = require('node:http');
const crypto = require('node:crypto');

const { OidcClient } = require('./lib/oidc');
const views = require('./lib/views');
const { html, redirect, json, parseCookies, cookie } = require('../shared/http');

const config = {
  port: Number(process.env.PORT || 3000),
  baseUrl: (process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/$/, ''),
  authority: (process.env.AUTH_AUTHORITY || 'http://localhost:8080/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb').replace(/\/$/, ''),
  clientId: process.env.AUTH_CLIENT_ID || '8f1e0b32-6a1e-4c1e-9a11-2b3c4d5e6f70',
  clientSecret: process.env.AUTH_CLIENT_SECRET || 'super-secret-value-not-for-production',
  scopes: process.env.AUTH_SCOPES || 'openid profile email offline_access User.Read',
  graphBaseUrl: (process.env.GRAPH_BASE_URL || 'http://localhost:8080').replace(/\/$/, ''),
  requiredRole: process.env.ADMIN_ROLE || 'Admin',
};

const client = new OidcClient({
  authority: config.authority,
  clientId: config.clientId,
  clientSecret: config.clientSecret,
  redirectUri: `${config.baseUrl}/auth/callback`,
});

// Session and pending-login state. A real deployment would use a shared,
// persistent store (Redis, a database, encrypted cookies); the shape of what
// is stored does not change.
const sessions = new Map();
const pendingLogins = new Map();
const SESSION_COOKIE = 'sample_app_sid';
const TX_COOKIE = 'sample_app_tx';

function currentSession(req) {
  const cookies = parseCookies(req);
  const session = sessions.get(cookies[SESSION_COOKIE]);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(cookies[SESSION_COOKIE]);
    return null;
  }
  return session;
}

function startSession(res, data) {
  const sid = crypto.randomBytes(24).toString('base64url');
  sessions.set(sid, { ...data, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
  res.setHeader('set-cookie', cookie(SESSION_COOKIE, sid, { maxAge: 8 * 60 * 60 }));
  return sid;
}

// ------------------------------------------------------------------ routes

async function handleLogin(req, res, url) {
  const pkce = OidcClient.createPkcePair();
  const state = OidcClient.randomString();
  const nonce = OidcClient.randomString();
  const txId = crypto.randomBytes(16).toString('base64url');

  pendingLogins.set(txId, { state, nonce, codeVerifier: pkce.verifier, createdAt: Date.now() });

  const authUrl = await client.authorizationUrl({
    scope: config.scopes,
    state,
    nonce,
    codeChallenge: pkce.challenge,
    prompt: url.searchParams.get('prompt') || undefined,
    loginHint: url.searchParams.get('login_hint') || undefined,
  });

  res.setHeader('set-cookie', cookie(TX_COOKIE, txId, { maxAge: 600 }));
  return redirect(res, authUrl);
}

async function handleCallback(req, res, url) {
  const cookies = parseCookies(req);
  const tx = pendingLogins.get(cookies[TX_COOKIE]);
  pendingLogins.delete(cookies[TX_COOKIE]);

  const error = url.searchParams.get('error');
  if (error) {
    // Entra reports failures here as error / error_description with an
    // AADSTS code - surface it rather than swallowing it.
    return html(res, 400, views.errorPage(
      `Sign-in failed (${error})`,
      url.searchParams.get('error_description') || 'No description provided.',
    ));
  }
  if (!tx) {
    return html(res, 400, views.errorPage('Sign-in failed', 'No login transaction found. Start again from the home page.'));
  }
  if (url.searchParams.get('state') !== tx.state) {
    return html(res, 400, views.errorPage('Sign-in failed', 'State parameter mismatch - possible CSRF, request rejected.'));
  }

  let tokenResponse;
  try {
    tokenResponse = await client.redeemCode({
      code: url.searchParams.get('code'),
      codeVerifier: tx.codeVerifier,
    });
  } catch (err) {
    return html(res, 400, views.errorPage('Token request failed', err.message));
  }

  let claims;
  try {
    claims = await client.validateIdToken(tokenResponse.id_token, { nonce: tx.nonce });
  } catch (err) {
    return html(res, 401, views.errorPage('id_token validation failed', err.message));
  }

  startSession(res, { claims, tokenResponse });
  return redirect(res, '/');
}

async function handleHome(req, res, session) {
  if (!session) {
    return html(res, 200, views.signedOut({ authority: config.authority, clientId: config.clientId }));
  }
  let accessTokenClaims = null;
  try {
    // Only decodable because the mock (and Entra, for custom APIs) issues JWT
    // access tokens. Graph tokens from real Entra are opaque to clients -
    // never depend on being able to read one.
    accessTokenClaims = OidcClient.decode(session.tokenResponse.access_token).payload;
  } catch { /* opaque token - fine */ }

  return html(res, 200, views.profile({
    claims: session.claims,
    tokenResponse: session.tokenResponse,
    accessTokenClaims,
  }));
}

async function handleGraphMe(req, res, session) {
  const response = await fetch(`${config.graphBaseUrl}/v1.0/me`, {
    headers: { authorization: `Bearer ${session.tokenResponse.access_token}` },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    return html(res, response.status, views.errorPage(
      `Graph call failed (${response.status})`,
      JSON.stringify(data, null, 2),
      { signedIn: true },
    ));
  }
  return html(res, 200, views.graphResult(data));
}

async function handleRefresh(req, res, session) {
  if (!session.tokenResponse.refresh_token) {
    return html(res, 400, views.errorPage(
      'No refresh token',
      "Request the 'offline_access' scope to receive a refresh token.",
      { signedIn: true },
    ));
  }
  try {
    const refreshed = await client.refresh({ refreshToken: session.tokenResponse.refresh_token });
    session.tokenResponse = refreshed;
    if (refreshed.id_token) session.claims = await client.validateIdToken(refreshed.id_token);
    return redirect(res, '/');
  } catch (err) {
    return html(res, 400, views.errorPage('Refresh failed', err.message, { signedIn: true }));
  }
}

async function handleLogout(req, res) {
  const cookies = parseCookies(req);
  sessions.delete(cookies[SESSION_COOKIE]);
  res.setHeader('set-cookie', cookie(SESSION_COOKIE, '', { maxAge: 0 }));
  const url = await client.logoutUrl({ postLogoutRedirectUri: `${config.baseUrl}/` });
  return redirect(res, url);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, config.baseUrl);
  const session = currentSession(req);

  const requireSession = () => {
    if (!session) {
      redirect(res, '/login');
      return false;
    }
    return true;
  };

  try {
    switch (url.pathname) {
      case '/':
        return await handleHome(req, res, session);
      case '/login':
        return await handleLogin(req, res, url);
      case '/auth/callback':
        return await handleCallback(req, res, url);
      case '/api/me':
        return requireSession() ? await handleGraphMe(req, res, session) : undefined;
      case '/refresh':
        return requireSession() ? await handleRefresh(req, res, session) : undefined;
      case '/admin': {
        if (!requireSession()) return undefined;
        const roles = session.claims.roles || [];
        const allowed = roles.includes(config.requiredRole);
        return html(res, allowed ? 200 : 403, views.adminPage({ allowed, roles }));
      }
      case '/logout':
        return await handleLogout(req, res);
      case '/healthz':
        return json(res, 200, { status: 'ok' });
      case '/favicon.ico':
        res.writeHead(204);
        return res.end();
      default:
        return html(res, 404, views.errorPage('Not found', `No route for ${url.pathname}`, { signedIn: !!session }));
    }
  } catch (err) {
    console.error(err);
    return html(res, 500, views.errorPage('Unexpected error', String(err && err.message), { signedIn: !!session }));
  }
});

if (require.main === module) {
  server.listen(config.port, () => {
    console.log(
      `Sample app listening on ${config.baseUrl}\n` +
      `  authority ${config.authority}\n` +
      `  client_id ${config.clientId}\n` +
      `  scopes    ${config.scopes}`,
    );
  });
}

module.exports = { server, config, client };
