'use strict';

// End-to-end: the sample application signing a user in through the mock,
// driven the way a browser would drive it.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { startMock, get, postForm, freePort, Jar, CLIENTS } = require('./helpers');

let mock;
let app;
let appBaseUrl;

/** A directory whose redirect URIs point at wherever the sample app is listening. */
function directoryFor(baseUrl) {
  const source = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'mock-entra', 'directory.json'), 'utf8'));
  for (const application of source.applications) {
    if (application.appId !== CLIENTS.web.clientId) continue;
    application.redirectUris = [`${baseUrl}/auth/callback`];
    application.postLogoutRedirectUris = [`${baseUrl}/`];
  }
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mock-entra-dir-')), 'directory.json');
  fs.writeFileSync(file, JSON.stringify(source));
  return file;
}

test.before(async () => {
  const appPort = await freePort();
  appBaseUrl = `http://127.0.0.1:${appPort}`;

  // A tenant whose registered redirect URIs point at this test's app port.
  mock = await startMock({ directoryPath: directoryFor(appBaseUrl) });

  // The sample app reads its configuration from the environment at load time.
  process.env.PORT = String(appPort);
  process.env.APP_BASE_URL = appBaseUrl;
  process.env.AUTH_AUTHORITY = mock.authority;
  process.env.AUTH_CLIENT_ID = CLIENTS.web.clientId;
  process.env.AUTH_CLIENT_SECRET = CLIENTS.web.clientSecret;
  process.env.GRAPH_BASE_URL = mock.baseUrl;

  app = require('../sample-app/server');
  await new Promise((resolve) => app.server.listen(appPort, '127.0.0.1', resolve));
});

test.after(async () => {
  await new Promise((resolve) => app.server.close(resolve));
  await mock.close();
});

test('a user signs in, sees their claims, calls Graph and signs out', async () => {
  const jar = new Jar();

  const anonymous = await get(`${appBaseUrl}/`, { jar });
  assert.equal(anonymous.status, 200);
  assert.match(await anonymous.text(), /You are signed out/);

  // /login redirects to the identity provider.
  const toIdp = await get(`${appBaseUrl}/login`, { jar });
  assert.equal(toIdp.status, 302);
  const authorizeUrl = new URL(toIdp.headers.get('location'));
  assert.equal(authorizeUrl.origin + authorizeUrl.pathname, `${mock.authority}/oauth2/v2.0/authorize`);
  assert.equal(authorizeUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(authorizeUrl.searchParams.get('code_challenge'));
  assert.ok(authorizeUrl.searchParams.get('state'));
  assert.ok(authorizeUrl.searchParams.get('nonce'));

  // The identity provider shows its sign-in form.
  const loginPage = await get(authorizeUrl.toString(), { jar });
  assert.equal(loginPage.status, 200);
  assert.match(await loginPage.text(), /Sign in/);

  const formFields = Object.fromEntries(authorizeUrl.searchParams);
  const signedIn = await postForm(`${mock.authority}/login`, {
    ...formFields,
    username: 'alice@contoso.onmicrosoft.com',
    password: 'Passw0rd!',
  }, { jar });
  assert.equal(signedIn.status, 302);

  // Back to the application's redirect URI with the authorization code.
  const callbackUrl = new URL(signedIn.headers.get('location'));
  assert.equal(callbackUrl.origin, appBaseUrl);
  assert.ok(callbackUrl.searchParams.get('code'));

  const callback = await get(callbackUrl.toString(), { jar });
  assert.equal(callback.status, 302, 'code redeemed and session established');
  assert.equal(callback.headers.get('location'), '/');

  const profile = await get(`${appBaseUrl}/`, { jar });
  assert.equal(profile.status, 200);
  const profileHtml = await profile.text();
  assert.match(profileHtml, /Alice Anderson/);
  assert.match(profileHtml, /alice@contoso\.onmicrosoft\.com/);

  // The access token works against (mock) Microsoft Graph.
  const graph = await get(`${appBaseUrl}/api/me`, { jar });
  assert.equal(graph.status, 200);
  assert.match(await graph.text(), /Finance Director/);

  // Alice holds the Admin app role.
  const admin = await get(`${appBaseUrl}/admin`, { jar });
  assert.equal(admin.status, 200);
  assert.match(await admin.text(), /Access granted/);

  // Refresh exchanges the refresh token for a new set.
  const refreshed = await get(`${appBaseUrl}/refresh`, { jar });
  assert.equal(refreshed.status, 302);
  assert.equal(refreshed.headers.get('location'), '/');

  // Sign-out clears the app session and sends the browser to the IdP.
  const logout = await get(`${appBaseUrl}/logout`, { jar });
  assert.equal(logout.status, 302);
  assert.match(logout.headers.get('location'), new RegExp(`^${mock.authority}/oauth2/v2\\.0/logout`));

  const after = await get(`${appBaseUrl}/`, { jar });
  assert.match(await after.text(), /You are signed out/);
});

test('a user without the Admin role is refused the admin page', async () => {
  const jar = new Jar();
  const toIdp = await get(`${appBaseUrl}/login`, { jar });
  const authorizeUrl = new URL(toIdp.headers.get('location'));
  await get(authorizeUrl.toString(), { jar });

  const signedIn = await postForm(`${mock.authority}/login`, {
    ...Object.fromEntries(authorizeUrl.searchParams),
    username: 'bob@contoso.onmicrosoft.com',
    password: 'Passw0rd!',
  }, { jar });
  await get(new URL(signedIn.headers.get('location')).toString(), { jar });

  const admin = await get(`${appBaseUrl}/admin`, { jar });
  assert.equal(admin.status, 403);
  assert.match(await admin.text(), /403 Forbidden/);
});

test('the callback rejects a mismatched state', async () => {
  const jar = new Jar();
  await get(`${appBaseUrl}/login`, { jar });
  const res = await get(`${appBaseUrl}/auth/callback?code=abc&state=not-the-state`, { jar });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /State parameter mismatch/);
});

test('the callback surfaces an AADSTS error returned by the identity provider', async () => {
  const jar = new Jar();
  await get(`${appBaseUrl}/login`, { jar });
  const res = await get(
    `${appBaseUrl}/auth/callback?error=access_denied&error_description=${encodeURIComponent('AADSTS65004: User declined to consent.')}`,
    { jar },
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /AADSTS65004/);
});
