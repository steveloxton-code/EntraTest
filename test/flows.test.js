'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { startMock, signIn, postForm, get, pkce, Jar, CLIENTS } = require('./helpers');
const { verifyJwt, decodeJwt } = require('../shared/jose');

let mock;
let jwks;

test.before(async () => {
  mock = await startMock();
  const res = await get(`${mock.authority}/discovery/v2.0/keys`);
  jwks = (await res.json()).keys;
});

test.after(async () => {
  await mock.close();
});

const tokenEndpoint = () => `${mock.authority}/oauth2/v2.0/token`;

// --------------------------------------------------------------- discovery

test('discovery document advertises the v2.0 endpoints', async () => {
  const res = await get(`${mock.authority}/v2.0/.well-known/openid-configuration`);
  assert.equal(res.status, 200);
  const doc = await res.json();

  assert.equal(doc.issuer, mock.issuer);
  assert.equal(doc.authorization_endpoint, `${mock.authority}/oauth2/v2.0/authorize`);
  assert.equal(doc.token_endpoint, `${mock.authority}/oauth2/v2.0/token`);
  assert.equal(doc.jwks_uri, `${mock.authority}/discovery/v2.0/keys`);
  assert.deepEqual(doc.id_token_signing_alg_values_supported, ['RS256']);
  assert.deepEqual(doc.subject_types_supported, ['pairwise']);
  assert.ok(doc.response_modes_supported.includes('form_post'));
});

test('the discovery document is also served from /common', async () => {
  const res = await get(`${mock.baseUrl}/common/v2.0/.well-known/openid-configuration`);
  assert.equal(res.status, 200);
  const doc = await res.json();
  assert.equal(doc.authorization_endpoint, `${mock.baseUrl}/common/oauth2/v2.0/authorize`);
  // The issuer always names the real tenant, exactly as Entra does.
  assert.equal(doc.issuer, mock.issuer);
});

test('JWKS exposes an RS256 signing key', async () => {
  assert.ok(jwks.length >= 1);
  const [key] = jwks;
  assert.equal(key.kty, 'RSA');
  assert.equal(key.use, 'sig');
  assert.ok(key.kid);
  assert.ok(key.n && key.e);
});

// ------------------------------------------------- authorization code flow

test('authorization code + PKCE returns validated id and access tokens', async () => {
  const { verifier, challenge } = pkce();
  const { code, state } = await signIn(mock, { challenge });
  assert.ok(code, 'authorization code returned');
  assert.equal(state, 'test-state');

  const res = await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.expires_in > 0);
  assert.ok(body.access_token && body.id_token && body.refresh_token);

  const idClaims = verifyJwt(body.id_token, {
    jwks, issuer: mock.issuer, audience: CLIENTS.web.clientId, nonce: 'test-nonce',
  });
  assert.equal(idClaims.preferred_username, 'alice@contoso.onmicrosoft.com');
  assert.equal(idClaims.name, 'Alice Anderson');
  assert.equal(idClaims.oid, '00000000-0000-0000-0000-00000000a001');
  assert.equal(idClaims.tid, mock.tenantId);
  assert.equal(idClaims.ver, '2.0');
  assert.equal(idClaims.email, 'alice@contoso.com');
  assert.deepEqual(idClaims.roles, ['Admin']);
  assert.notEqual(idClaims.sub, idClaims.oid, 'sub is pairwise, not the object id');

  const accessClaims = verifyJwt(body.access_token, {
    jwks, issuer: mock.issuer, audience: 'https://graph.microsoft.com',
  });
  assert.equal(accessClaims.scp, 'User.Read');
  assert.equal(accessClaims.azp, CLIENTS.web.clientId);
  assert.equal(accessClaims.oid, idClaims.oid);
});

test('sub is pairwise: same user, different applications, different subjects', async () => {
  async function idTokenFor(client, secret) {
    const { verifier, challenge } = pkce();
    const { code } = await signIn(mock, { client, challenge, scope: 'openid' });
    const body = await (await postForm(tokenEndpoint(), {
      grant_type: 'authorization_code',
      client_id: client.clientId,
      ...(secret ? { client_secret: secret } : {}),
      code,
      redirect_uri: client.redirectUri,
      code_verifier: verifier,
    })).json();
    return decodeJwt(body.id_token).payload;
  }

  const web = await idTokenFor(CLIENTS.web, CLIENTS.web.clientSecret);
  const webAgain = await idTokenFor(CLIENTS.web, CLIENTS.web.clientSecret);
  const publicClient = await idTokenFor(CLIENTS.publicClient);

  assert.equal(web.oid, publicClient.oid, 'the object id identifies the user across apps');
  assert.equal(web.sub, webAgain.sub, 'sub is stable for a given app');
  assert.notEqual(web.sub, publicClient.sub, 'sub differs between apps');
});

test('an authorization code can only be redeemed once (AADSTS54005)', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const payload = {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  };
  assert.equal((await postForm(tokenEndpoint(), payload)).status, 200);

  const replay = await postForm(tokenEndpoint(), payload);
  assert.equal(replay.status, 400);
  const err = await replay.json();
  assert.equal(err.error, 'invalid_grant');
  assert.deepEqual(err.error_codes, [54005]);
  assert.match(err.error_description, /^AADSTS54005:/);
  assert.ok(err.trace_id && err.correlation_id && err.timestamp);
});

test('a mismatched PKCE verifier is rejected (AADSTS50148)', async () => {
  const { challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: pkce().verifier,
  });
  assert.equal(res.status, 400);
  const err = await res.json();
  assert.deepEqual(err.error_codes, [50148]);
});

test('a confidential client must present the right secret (AADSTS7000215)', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: 'wrong-secret',
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  });
  assert.equal(res.status, 401);
  const err = await res.json();
  assert.equal(err.error, 'invalid_client');
  assert.deepEqual(err.error_codes, [7000215]);
});

test('a public client redeems its code with PKCE and no secret', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { client: CLIENTS.publicClient, challenge, scope: 'openid offline_access' });
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.publicClient.clientId,
    code,
    redirect_uri: CLIENTS.publicClient.redirectUri,
    code_verifier: verifier,
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  const claims = decodeJwt(body.access_token).payload;
  assert.equal(claims.azpacr, '0', 'public client');
});

test('PKCE is mandatory when the app registration requires it', async () => {
  const { response } = await signIn(mock, { client: CLIENTS.publicClient, challenge: undefined });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'invalid_request');
  assert.match(location.searchParams.get('error_description'), /code_challenge/);
});

// -------------------------------------------------------------- validation

test('an unregistered redirect_uri is shown as an error page, never redirected to (AADSTS50011)', async () => {
  const url = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  url.searchParams.set('client_id', CLIENTS.web.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', 'https://attacker.example/steal');
  url.searchParams.set('scope', 'openid');

  const res = await get(url.toString());
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('location'), null);
  assert.match(await res.text(), /AADSTS50011/);
});

test('an unknown client_id is rejected (AADSTS700016)', async () => {
  const url = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  url.searchParams.set('client_id', '00000000-0000-0000-0000-000000000000');
  url.searchParams.set('redirect_uri', 'http://localhost:3000/auth/callback');
  const res = await get(url.toString());
  assert.equal(res.status, 400);
  assert.match(await res.text(), /AADSTS700016/);
});

test('an unknown API resource is rejected (AADSTS500011)', async () => {
  const { response } = await signIn(mock, { challenge: pkce().challenge, scope: 'openid api://not-registered/read' });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get('location'));
  assert.match(location.searchParams.get('error_description'), /AADSTS500011/);
});

test('prompt=none without a session returns login_required (AADSTS50058)', async () => {
  const url = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  const params = {
    client_id: CLIENTS.web.clientId,
    response_type: 'code',
    redirect_uri: CLIENTS.web.redirectUri,
    scope: 'openid',
    prompt: 'none',
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
    state: 'silent',
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

  const res = await get(url.toString());
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'login_required');
  assert.equal(location.searchParams.get('state'), 'silent');
  assert.match(location.searchParams.get('error_description'), /AADSTS50058/);
});

test('an existing session gives silent single sign-on to a second application', async () => {
  const jar = new Jar();
  const first = await signIn(mock, { challenge: pkce().challenge, jar });
  assert.ok(first.code);

  // Second app, same browser session: no sign-in form, straight to a code.
  const url = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  const params = {
    client_id: CLIENTS.publicClient.clientId,
    response_type: 'code',
    redirect_uri: CLIENTS.publicClient.redirectUri,
    scope: 'openid',
    prompt: 'none',
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

  const res = await get(url.toString(), { jar });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.ok(location.searchParams.get('code'), 'silent code issued from the existing session');
});

test('response_mode=form_post returns a self-submitting form', async () => {
  const { response } = await signIn(mock, {
    challenge: pkce().challenge,
    extra: { response_mode: 'form_post' },
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /<form method="post" action="http:\/\/localhost:3000\/auth\/callback">/);
  assert.match(body, /name="code"/);
  assert.match(body, /name="state" value="test-state"/);
});

// ------------------------------------------------------------- credentials

test('a wrong password re-renders the sign-in form with AADSTS50126', async () => {
  const { response } = await signIn(mock, { challenge: pkce().challenge, password: 'nope' });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /AADSTS50126/);
});

test('an account requiring MFA reports AADSTS50076', async () => {
  const { response } = await signIn(mock, {
    challenge: pkce().challenge,
    username: 'mfa@contoso.onmicrosoft.com',
  });
  assert.match(await response.text(), /AADSTS50076/);
});

test('a disabled account reports AADSTS50057', async () => {
  const { response } = await signIn(mock, {
    challenge: pkce().challenge,
    username: 'disabled@contoso.onmicrosoft.com',
  });
  assert.match(await response.text(), /AADSTS50057/);
});

// ----------------------------------------------------------- refresh token

test('refresh tokens rotate and the old one stops working', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const first = await (await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  })).json();

  const refreshed = await (await postForm(tokenEndpoint(), {
    grant_type: 'refresh_token',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    refresh_token: first.refresh_token,
  })).json();

  assert.ok(refreshed.access_token && refreshed.id_token);
  assert.notEqual(refreshed.refresh_token, first.refresh_token, 'refresh token rotated');
  verifyJwt(refreshed.id_token, { jwks, issuer: mock.issuer, audience: CLIENTS.web.clientId });

  const reuse = await postForm(tokenEndpoint(), {
    grant_type: 'refresh_token',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    refresh_token: first.refresh_token,
  });
  assert.equal(reuse.status, 400);
  assert.equal((await reuse.json()).error, 'invalid_grant');
});

test('a refresh request cannot widen scope', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge, scope: 'openid offline_access User.Read' });
  const first = await (await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  })).json();

  const res = await postForm(tokenEndpoint(), {
    grant_type: 'refresh_token',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    refresh_token: first.refresh_token,
    scope: 'openid offline_access Directory.ReadWrite.All',
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_scope');
});

// ------------------------------------------------------- client credentials

test('client credentials issues an app-only token with application roles', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'client_credentials',
    client_id: CLIENTS.daemon.clientId,
    client_secret: CLIENTS.daemon.clientSecret,
    scope: 'https://graph.microsoft.com/.default',
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.access_token);
  assert.equal(body.refresh_token, undefined, 'no refresh token for app-only tokens');
  assert.equal(body.id_token, undefined, 'no id_token for app-only tokens');

  const claims = verifyJwt(body.access_token, {
    jwks, issuer: mock.issuer, audience: 'https://graph.microsoft.com',
  });
  assert.equal(claims.idtyp, 'app');
  assert.equal(claims.scp, undefined, 'app-only tokens carry roles, not scp');
  assert.deepEqual(claims.roles, ['User.Read.All']);
});

test('client credentials without /.default is rejected (AADSTS1002012)', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'client_credentials',
    client_id: CLIENTS.daemon.clientId,
    client_secret: CLIENTS.daemon.clientSecret,
    scope: 'User.Read.All',
  });
  assert.equal(res.status, 400);
  assert.deepEqual((await res.json()).error_codes, [1002012]);
});

test('a grant that is not enabled for the app is refused', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'client_credentials',
    client_id: CLIENTS.publicClient.clientId,
    scope: 'https://graph.microsoft.com/.default',
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'unauthorized_client');
});

// ------------------------------------------------------------------- ROPC

test('resource owner password credentials issues tokens', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'password',
    client_id: CLIENTS.publicClient.clientId,
    username: 'bob@contoso.onmicrosoft.com',
    password: 'Passw0rd!',
    scope: 'openid profile User.Read',
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  const claims = verifyJwt(body.id_token, {
    jwks, issuer: mock.issuer, audience: CLIENTS.publicClient.clientId,
  });
  assert.equal(claims.preferred_username, 'bob@contoso.onmicrosoft.com');
});

test('resource owner password credentials rejects a bad password (AADSTS50126)', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'password',
    client_id: CLIENTS.publicClient.clientId,
    username: 'bob@contoso.onmicrosoft.com',
    password: 'wrong',
    scope: 'openid',
  });
  assert.equal(res.status, 400);
  assert.deepEqual((await res.json()).error_codes, [50126]);
});

// ------------------------------------------------------------ device code

test('device code flow: pending, then approved after the user signs in', async () => {
  const start = await postForm(`${mock.authority}/oauth2/v2.0/devicecode`, {
    client_id: CLIENTS.publicClient.clientId,
    scope: 'openid profile offline_access User.Read',
  });
  assert.equal(start.status, 200);
  const device = await start.json();
  assert.match(device.user_code, /^[A-Z]{9}$/);
  assert.ok(device.device_code && device.verification_uri && device.interval);

  const poll = () => postForm(tokenEndpoint(), {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: CLIENTS.publicClient.clientId,
    device_code: device.device_code,
  });

  const pending = await poll();
  assert.equal(pending.status, 400);
  assert.equal((await pending.json()).error, 'authorization_pending');

  // The user opens the verification URI in a browser and signs in.
  const jar = new Jar();
  const codePage = await postForm(`${mock.authority}/oauth2/deviceauth`, { user_code: device.user_code }, { jar });
  assert.equal(codePage.status, 200);
  const approved = await postForm(`${mock.authority}/oauth2/deviceauth/login`, {
    user_code: device.user_code,
    username: 'alice@contoso.onmicrosoft.com',
    password: 'Passw0rd!',
  }, { jar });
  assert.equal(approved.status, 200);

  const success = await poll();
  assert.equal(success.status, 200);
  const body = await success.json();
  const claims = verifyJwt(body.id_token, {
    jwks, issuer: mock.issuer, audience: CLIENTS.publicClient.clientId,
  });
  assert.equal(claims.preferred_username, 'alice@contoso.onmicrosoft.com');
});

// ------------------------------------------------------------- mock Graph

test('mock Graph accepts an access token issued for it', async () => {
  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const tokens = await (await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  })).json();

  const me = await get(`${mock.baseUrl}/v1.0/me`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(me.status, 200);
  const profile = await me.json();
  assert.equal(profile.userPrincipalName, 'alice@contoso.onmicrosoft.com');
  assert.equal(profile.jobTitle, 'Finance Director');

  const memberOf = await get(`${mock.baseUrl}/v1.0/me/memberOf`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(memberOf.status, 200);
  assert.equal((await memberOf.json()).value[0].displayName, 'Finance');

  const userinfo = await get(`${mock.baseUrl}/oidc/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(userinfo.status, 200);
  assert.equal((await userinfo.json()).email, 'alice@contoso.com');
});

test('mock Graph rejects a token minted for a different audience', async () => {
  const res = await postForm(tokenEndpoint(), {
    grant_type: 'client_credentials',
    client_id: CLIENTS.daemon.clientId,
    client_secret: CLIENTS.daemon.clientSecret,
    scope: 'api://8f1e0b32-6a1e-4c1e-9a11-2b3c4d5e6f70/.default',
  });
  const { access_token: wrongAudience } = await res.json();

  const me = await get(`${mock.baseUrl}/v1.0/me`, {
    headers: { authorization: `Bearer ${wrongAudience}` },
  });
  assert.equal(me.status, 401);
  assert.equal((await me.json()).error.code, 'InvalidAuthenticationToken');
});

test('mock Graph rejects a missing or tampered token', async () => {
  assert.equal((await get(`${mock.baseUrl}/v1.0/me`)).status, 401);

  const { verifier, challenge } = pkce();
  const { code } = await signIn(mock, { challenge });
  const tokens = await (await postForm(tokenEndpoint(), {
    grant_type: 'authorization_code',
    client_id: CLIENTS.web.clientId,
    client_secret: CLIENTS.web.clientSecret,
    code,
    redirect_uri: CLIENTS.web.redirectUri,
    code_verifier: verifier,
  })).json();

  const [header, payload, signature] = tokens.access_token.split('.');
  const forged = JSON.parse(Buffer.from(payload, 'base64url').toString());
  forged.oid = '00000000-0000-0000-0000-00000000a002';
  const tampered = `${header}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${signature}`;

  const res = await get(`${mock.baseUrl}/v1.0/me`, { headers: { authorization: `Bearer ${tampered}` } });
  assert.equal(res.status, 401);
});

// ----------------------------------------------------------------- logout

test('logout clears the session and returns to a registered URL', async () => {
  const jar = new Jar();
  await signIn(mock, { challenge: pkce().challenge, jar });

  const url = new URL(`${mock.authority}/oauth2/v2.0/logout`);
  url.searchParams.set('post_logout_redirect_uri', 'http://localhost:3000/');
  const res = await get(url.toString(), { jar });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'http://localhost:3000/');

  // The session cookie is gone, so prompt=none now fails.
  const silent = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  for (const [k, v] of Object.entries({
    client_id: CLIENTS.web.clientId,
    response_type: 'code',
    redirect_uri: CLIENTS.web.redirectUri,
    scope: 'openid',
    prompt: 'none',
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
  })) silent.searchParams.set(k, v);

  const after = await get(silent.toString(), { jar });
  const location = new URL(after.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'login_required');
});

test('logout refuses to redirect to an unregistered URL', async () => {
  const url = new URL(`${mock.authority}/oauth2/v2.0/logout`);
  url.searchParams.set('post_logout_redirect_uri', 'https://attacker.example/');
  const res = await get(url.toString());
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('location'), null);
});
