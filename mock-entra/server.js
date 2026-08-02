'use strict';

/**
 * Mock Microsoft Entra ID (Azure AD) v2.0 endpoint.
 *
 * Implements the same URL layout, request/response shapes, token claims and
 * error codes as login.microsoftonline.com, so an application written against
 * this server can be pointed at a real tenant by changing configuration only.
 *
 *   authority: http://localhost:8080/<tenant-id>
 *   real:      https://login.microsoftonline.com/<tenant-id>
 *
 * Run: node mock-entra/server.js
 */

const http = require('node:http');
const crypto = require('node:crypto');

const { loadDirectory, resolveResource, GRAPH_RESOURCE } = require('./lib/config');
const { load: loadKeys } = require('./lib/keys');
const { Store } = require('./lib/store');
const { AadError } = require('./lib/aadsts');
const tokens = require('./lib/tokens');
const pages = require('./lib/pages');
const { verifyJwt } = require('../shared/jose');
const {
  json, html, redirect, formBody, queryParams, parseCookies, cookie,
  basicAuth, bearerToken, escapeHtml,
} = require('../shared/http');

const SESSION_COOKIE = 'ESTSAUTH';
const KNOWN_GRANTS = new Set([
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'password',
  'urn:ietf:params:oauth:grant-type:device_code',
]);
const AUTHORIZE_PARAMS = [
  'client_id', 'response_type', 'redirect_uri', 'scope', 'state', 'nonce',
  'response_mode', 'code_challenge', 'code_challenge_method', 'prompt',
  'login_hint', 'domain_hint', 'client_info',
];

function createServer(options = {}) {
  const directory = loadDirectory(options.directoryPath);
  const key = loadKeys();
  const store = new Store();
  const port = Number(options.port || process.env.MOCK_ENTRA_PORT || 8080);
  const baseUrl = (options.baseUrl || process.env.MOCK_ENTRA_BASE_URL || `http://localhost:${port}`)
    .replace(/\/$/, '');
  const tenant = directory.tenant;
  const issuer = `${baseUrl}/${tenant.id}/v2.0`;

  // ---------------------------------------------------------------- helpers

  const isTenantSegment = (segment) =>
    segment === tenant.id ||
    segment === tenant.domain ||
    segment === 'common' ||
    segment === 'organizations';

  function requireApp(clientId) {
    if (!clientId) throw new AadError(900144, "'client_id'.");
    const app = directory.app(clientId);
    if (!app) {
      throw new AadError(700016, `Application with identifier '${clientId}' was not found in the directory '${tenant.displayName}'.`);
    }
    return app;
  }

  function requireGrant(app, grant) {
    if (!app.allowedGrants.includes(grant)) {
      throw new AadError(700051, `The grant type '${grant}' is not enabled for the application '${app.appId}'.`, {
        error: 'unauthorized_client',
      });
    }
  }

  /** Confidential clients must present their secret on the token endpoint. */
  function authenticateClient(app, presentedSecret) {
    if (app.isPublicClient) return;
    if (!presentedSecret) {
      throw new AadError(7000215, `A client secret is required for confidential client '${app.appId}'.`);
    }
    const ok = app.clientSecrets.some((secret) => {
      const a = Buffer.from(secret);
      const b = Buffer.from(presentedSecret);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    });
    if (!ok) throw new AadError(7000215);
  }

  function resolveResourceOrThrow(scope) {
    const resolved = resolveResource(scope, directory);
    if (resolved.error) throw new AadError(70011, resolved.error);
    if (resolved.resource !== GRAPH_RESOURCE && !resolved.resourceApp) {
      throw new AadError(500011, `The resource principal named ${resolved.resource} was not found in the tenant named ${tenant.displayName}.`);
    }
    return resolved;
  }

  /** Scope string echoed back to the client, in Entra's format. */
  function echoScopes(resolved) {
    const prefix = resolved.resourceApp ? `${resolved.resource}/` : '';
    return [...resolved.oidcScopes, ...resolved.scopes.map((s) => prefix + s)].join(' ');
  }

  function verifyPkce(entry, codeVerifier) {
    if (!entry.codeChallenge) return;
    if (!codeVerifier) {
      throw new AadError(50148, "The request body must contain the parameter 'code_verifier'.");
    }
    const method = (entry.codeChallengeMethod || 'plain').toUpperCase();
    const computed =
      method === 'S256'
        ? crypto.createHash('sha256').update(codeVerifier).digest('base64url')
        : codeVerifier;
    if (computed !== entry.codeChallenge) throw new AadError(50148);
  }

  function clientInfo(user) {
    return Buffer.from(JSON.stringify({ uid: user.objectId, utid: tenant.id })).toString('base64url');
  }

  /** Assemble a token endpoint response for a user-delegated grant. */
  function issueUserTokens({ app, user, scope, nonce, authTime, sessionId, includeClientInfo }) {
    const resolved = resolveResourceOrThrow(scope);

    if (app.requireUserAssignment && !tokens.userRolesFor(user, app).length) {
      throw new AadError(50105, `The user '${user.userPrincipalName}' is not assigned to a role for the application '${app.appId}'.`);
    }

    const accessToken = tokens.buildUserAccessToken({
      issuer, tenant, user, app, key,
      resource: resolved,
      audience: resolved.audience,
      scopes: resolved.scopes.length ? resolved.scopes : ['user_impersonation'],
    });

    const body = {
      token_type: 'Bearer',
      scope: echoScopes(resolved),
      expires_in: tokens.ACCESS_TOKEN_LIFETIME,
      ext_expires_in: tokens.ACCESS_TOKEN_LIFETIME,
      access_token: accessToken,
    };

    if (resolved.oidcScopes.includes('offline_access')) {
      body.refresh_token = store.createRefreshToken({
        clientId: app.appId,
        userOid: user.objectId,
        scope,
        sessionId,
        authTime,
      });
    }
    if (resolved.oidcScopes.includes('openid')) {
      body.id_token = tokens.buildIdToken({
        issuer, tenant, user, app, nonce, key, directory,
        authTime: authTime || Math.floor(Date.now() / 1000),
        scopes: resolved.oidcScopes,
      });
    }
    if (includeClientInfo) body.client_info = clientInfo(user);
    return body;
  }

  // ------------------------------------------------------------- discovery

  function openidConfiguration(tenantSegment) {
    const authority = `${baseUrl}/${tenantSegment}`;
    return {
      token_endpoint: `${authority}/oauth2/v2.0/token`,
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      jwks_uri: `${authority}/discovery/v2.0/keys`,
      response_modes_supported: ['query', 'fragment', 'form_post'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256'],
      response_types_supported: ['code', 'id_token', 'code id_token', 'id_token token'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      issuer,
      request_uri_parameter_supported: false,
      userinfo_endpoint: `${baseUrl}/oidc/userinfo`,
      authorization_endpoint: `${authority}/oauth2/v2.0/authorize`,
      device_authorization_endpoint: `${authority}/oauth2/v2.0/devicecode`,
      http_logout_supported: true,
      frontchannel_logout_supported: true,
      end_session_endpoint: `${authority}/oauth2/v2.0/logout`,
      claims_supported: [
        'sub', 'iss', 'cloud_instance_name', 'cloud_instance_host_name', 'cloud_graph_host_name',
        'msgraph_host', 'aud', 'exp', 'iat', 'auth_time', 'acr', 'nonce', 'preferred_username',
        'name', 'tid', 'ver', 'at_hash', 'c_hash', 'email',
      ],
      tenant_region_scope: tenant.region || 'NA',
      cloud_instance_name: 'microsoftonline.com',
      cloud_graph_host_name: 'graph.windows.net',
      msgraph_host: 'graph.microsoft.com',
      rbac_url: `${baseUrl}/rbac`,
    };
  }

  // ------------------------------------------------------------- authorize

  function respondToClient(res, params, redirectUri, responseMode) {
    const mode = responseMode || 'query';
    if (mode === 'form_post') {
      return html(res, 200, pages.formPostPage(redirectUri, params));
    }
    const url = new URL(redirectUri);
    const search = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''),
    );
    if (mode === 'fragment') {
      url.hash = search.toString();
    } else {
      for (const [k, v] of search) url.searchParams.append(k, v);
    }
    return redirect(res, url.toString());
  }

  function authorizeError(res, params, err) {
    // If we cannot trust redirect_uri we must show an error page instead of
    // handing the error to a potentially attacker-controlled URL.
    if (!params.__redirectValidated) {
      store.record({ event: 'authorize.error', detail: err.message });
      return html(res, 400, pages.errorPage(err));
    }
    store.record({ event: 'authorize.error', detail: err.message });
    return respondToClient(
      res,
      { ...err.toParams(), state: params.state },
      params.redirect_uri,
      params.response_mode,
    );
  }

  function handleAuthorize(req, res, params, cookies) {
    let app;
    try {
      app = requireApp(params.client_id);
      if (!params.redirect_uri) throw new AadError(900144, "'redirect_uri'.");
      if (!app.redirectUris.includes(params.redirect_uri)) {
        throw new AadError(50011, `The redirect URI '${params.redirect_uri}' specified in the request does not match the redirect URIs configured for the application '${app.appId}'.`);
      }
    } catch (err) {
      return authorizeError(res, params, err);
    }
    params.__redirectValidated = true;

    try {
      requireGrant(app, 'authorization_code');

      const responseType = params.response_type || 'code';
      if (responseType !== 'code') {
        throw new AadError(700051, `Only response_type=code is implemented by the mock (got '${responseType}'). Use the authorization code flow with PKCE.`, {
          error: 'unsupported_response_type',
        });
      }
      if (!params.response_mode) params.response_mode = 'query';
      if (!['query', 'fragment', 'form_post'].includes(params.response_mode)) {
        throw new AadError(9002313, `Unsupported response_mode '${params.response_mode}'.`);
      }
      if ((app.requirePkce || app.isPublicClient) && !params.code_challenge) {
        throw new AadError(9002313, "The request must contain 'code_challenge' (PKCE is required for this application).");
      }
      if (params.code_challenge && params.code_challenge_method &&
          !['S256', 'plain'].includes(params.code_challenge_method)) {
        throw new AadError(9002313, `Unsupported code_challenge_method '${params.code_challenge_method}'.`);
      }
      // Fail fast on an unknown resource rather than at the token endpoint.
      resolveResourceOrThrow(params.scope);

      const prompt = params.prompt || '';
      const session = store.getSession(cookies[SESSION_COOKIE]);
      const forceLogin = prompt.includes('login') || prompt.includes('select_account');

      if (!session || forceLogin) {
        if (prompt.includes('none')) {
          throw new AadError(50058, 'The application requested prompt=none but no user is signed in to the mock.');
        }
        return html(res, 200, pages.loginPage({
          tenant, app,
          users: directory.users,
          requestParams: pickAuthorizeParams(params),
          prefillUsername: params.login_hint,
          showPasswordHints: true,
        }));
      }

      return completeAuthorize(req, res, params, app, session);
    } catch (err) {
      if (err instanceof AadError) return authorizeError(res, params, err);
      throw err;
    }
  }

  function pickAuthorizeParams(params) {
    const out = {};
    for (const name of AUTHORIZE_PARAMS) if (params[name] !== undefined) out[name] = params[name];
    return out;
  }

  /** Post-authentication: consent if needed, then hand back an auth code. */
  function completeAuthorize(req, res, params, app, session) {
    const user = directory.user(session.userOid);
    const resolved = resolveResourceOrThrow(params.scope);
    const consentScopes = [...resolved.oidcScopes, ...resolved.scopes.map((s) => `${resolved.resource}/${s}`)];
    const needsConsent =
      (app.requireConsent && !store.hasConsent(user.objectId, app.appId, consentScopes)) ||
      (params.prompt || '').includes('consent');

    if (needsConsent) {
      if ((params.prompt || '').includes('none')) {
        throw new AadError(65001, `The user or administrator has not consented to use the application with ID '${app.appId}'.`);
      }
      return html(res, 200, pages.consentPage({
        tenant, app, user, scopes: consentScopes, requestParams: pickAuthorizeParams(params),
      }));
    }

    const code = store.createCode({
      clientId: app.appId,
      redirectUri: params.redirect_uri,
      scope: params.scope || '',
      nonce: params.nonce,
      codeChallenge: params.code_challenge,
      codeChallengeMethod: params.code_challenge_method || (params.code_challenge ? 'plain' : undefined),
      userOid: user.objectId,
      authTime: session.authTime,
      sessionId: session.id,
      clientInfo: params.client_info === '1',
    });

    store.record({ event: 'authorize', detail: `${app.displayName} -> ${user.userPrincipalName}` });

    return respondToClient(
      res,
      {
        code,
        state: params.state,
        session_state: session.id,
        ...(params.client_info === '1' ? { client_info: clientInfo(user) } : {}),
      },
      params.redirect_uri,
      params.response_mode,
    );
  }

  async function handleLogin(req, res) {
    const body = await formBody(req);
    const params = pickAuthorizeParams(body);
    params.__redirectValidated = false;

    let app;
    try {
      app = requireApp(params.client_id);
      if (!app.redirectUris.includes(params.redirect_uri)) throw new AadError(50011);
      params.__redirectValidated = true;
    } catch (err) {
      return authorizeError(res, params, err);
    }

    const showLoginError = (message, prefill) =>
      html(res, 200, pages.loginPage({
        tenant, app, users: directory.users, requestParams: pickAuthorizeParams(params),
        error: message, prefillUsername: prefill, showPasswordHints: true,
      }));

    const user = directory.userByName(body.username);
    if (!user || !body.password || body.password !== user.password) {
      const err = new AadError(50126, 'Your account or password is incorrect.');
      store.record({ event: 'login.failed', detail: `${body.username || '(none)'}` });
      return showLoginError(err.message, body.username);
    }
    if (user.accountEnabled === false) {
      return showLoginError(new AadError(50057, `Account '${user.userPrincipalName}' is disabled.`).message, body.username);
    }
    if (user.requiresMfa) {
      // The mock has no second factor; it reproduces the error an app must
      // handle, which is the part worth testing.
      return showLoginError(new AadError(50076, `Multi-factor authentication is required for '${user.userPrincipalName}'.`).message, body.username);
    }

    const sessionId = store.createSession(user.objectId);
    store.record({ event: 'login', detail: user.userPrincipalName });

    res.setHeader('set-cookie', cookie(SESSION_COOKIE, sessionId, { maxAge: 8 * 60 * 60 }));
    try {
      return completeAuthorize(req, res, params, app, store.getSession(sessionId));
    } catch (err) {
      if (err instanceof AadError) return authorizeError(res, params, err);
      throw err;
    }
  }

  async function handleConsent(req, res, cookies) {
    const body = await formBody(req);
    const params = pickAuthorizeParams(body);
    params.__redirectValidated = false;

    let app;
    try {
      app = requireApp(params.client_id);
      if (!app.redirectUris.includes(params.redirect_uri)) throw new AadError(50011);
      params.__redirectValidated = true;

      const session = store.getSession(cookies[SESSION_COOKIE]);
      if (!session) throw new AadError(50058);

      if (body.decision !== 'accept') {
        throw new AadError(65004, `User declined to consent to access the app '${app.appId}'.`);
      }
      const resolved = resolveResourceOrThrow(params.scope);
      store.grantConsent(session.userOid, app.appId, [
        ...resolved.oidcScopes,
        ...resolved.scopes.map((s) => `${resolved.resource}/${s}`),
      ]);
      store.record({ event: 'consent', detail: `${app.displayName}` });

      const withoutPrompt = { ...params, prompt: '' };
      return completeAuthorize(req, res, withoutPrompt, app, session);
    } catch (err) {
      if (err instanceof AadError) return authorizeError(res, params, err);
      throw err;
    }
  }

  // ----------------------------------------------------------------- token

  async function handleToken(req, res) {
    const body = await formBody(req);
    const basic = basicAuth(req);
    const clientId = body.client_id || (basic && basic.clientId);
    const clientSecret = body.client_secret || (basic && basic.clientSecret);
    const grantType = body.grant_type;

    const app = requireApp(clientId);
    if (!grantType) throw new AadError(900144, "'grant_type'.");
    if (!KNOWN_GRANTS.has(grantType)) throw new AadError(9002313, `Unsupported grant_type '${grantType}'.`);
    requireGrant(app, grantType === 'urn:ietf:params:oauth:grant-type:device_code' ? 'device_code' : grantType);

    // Public clients authenticate with PKCE alone; everyone else needs a secret.
    if (grantType !== 'urn:ietf:params:oauth:grant-type:device_code') {
      authenticateClient(app, clientSecret);
    }

    switch (grantType) {
      case 'authorization_code': {
        if (!body.code) throw new AadError(900144, "'code'.");
        const { entry, error } = store.takeCode(body.code);
        if (error === 'redeemed') throw new AadError(54005);
        if (error === 'expired') throw new AadError(70008);
        if (error) throw new AadError(70000, 'The authorization code is invalid or unknown.');
        if (entry.clientId !== app.appId) {
          throw new AadError(70000, 'The authorization code was issued to a different application.');
        }
        if (body.redirect_uri && body.redirect_uri !== entry.redirectUri) {
          throw new AadError(50011, `The redirect URI '${body.redirect_uri}' does not match the redirect URI used in the authorization request.`);
        }
        verifyPkce(entry, body.code_verifier);

        const user = directory.user(entry.userOid);
        const result = issueUserTokens({
          app, user,
          scope: body.scope || entry.scope,
          nonce: entry.nonce,
          authTime: entry.authTime,
          sessionId: entry.sessionId,
          includeClientInfo: entry.clientInfo,
        });
        store.record({ event: 'token.authorization_code', detail: `${app.displayName} -> ${user.userPrincipalName}` });
        return json(res, 200, result);
      }

      case 'refresh_token': {
        if (!body.refresh_token) throw new AadError(900144, "'refresh_token'.");
        const { entry, error } = store.takeRefreshToken(body.refresh_token);
        if (error === 'expired') throw new AadError(70008);
        if (error) throw new AadError(70000, 'The refresh token is invalid, expired, or has already been used.');
        if (entry.clientId !== app.appId) {
          throw new AadError(70000, 'The refresh token was issued to a different application.');
        }
        const user = directory.user(entry.userOid);
        if (!user || user.accountEnabled === false) throw new AadError(50057);

        // A refresh may narrow scope, never widen it.
        const requested = (body.scope || entry.scope).split(/\s+/).filter(Boolean);
        const original = new Set(entry.scope.split(/\s+/).filter(Boolean));
        const widened = requested.filter((s) => !original.has(s));
        if (body.scope && widened.length) {
          throw new AadError(70011, `The scope(s) ${widened.join(', ')} were not granted to the original token.`);
        }

        const result = issueUserTokens({
          app, user,
          scope: requested.join(' '),
          authTime: entry.authTime,
          sessionId: entry.sessionId,
          includeClientInfo: true,
        });
        store.record({ event: 'token.refresh_token', detail: `${app.displayName} -> ${user.userPrincipalName}` });
        return json(res, 200, result);
      }

      case 'client_credentials': {
        const scope = body.scope || '';
        if (!/\/\.default(\s|$)/.test(scope)) {
          throw new AadError(1002012, `The provided value for scope '${scope}' is not valid.`);
        }
        const resolved = resolveResourceOrThrow(scope);
        const accessToken = tokens.buildAppAccessToken({
          issuer, tenant, app, key, resource: resolved, audience: resolved.audience,
        });
        store.record({ event: 'token.client_credentials', detail: `${app.displayName} -> ${resolved.resource}` });
        return json(res, 200, {
          token_type: 'Bearer',
          expires_in: tokens.ACCESS_TOKEN_LIFETIME,
          ext_expires_in: tokens.ACCESS_TOKEN_LIFETIME,
          access_token: accessToken,
        });
      }

      case 'password': {
        const user = directory.userByName(body.username);
        if (!user || body.password !== user.password) throw new AadError(50126);
        if (user.accountEnabled === false) throw new AadError(50057);
        if (user.requiresMfa) {
          throw new AadError(50076, 'The resource owner password credentials grant cannot satisfy a multi-factor authentication requirement.');
        }
        const result = issueUserTokens({
          app, user,
          scope: body.scope || '',
          authTime: Math.floor(Date.now() / 1000),
          includeClientInfo: true,
        });
        store.record({ event: 'token.password', detail: `${app.displayName} -> ${user.userPrincipalName}` });
        return json(res, 200, result);
      }

      case 'urn:ietf:params:oauth:grant-type:device_code': {
        if (!body.device_code) throw new AadError(900144, "'device_code'.");
        const entry = store.getDeviceCode(body.device_code);
        if (!entry) throw new AadError(70019);
        if (entry.clientId !== app.appId) throw new AadError(70000, 'The device code was issued to a different application.');
        if (entry.status === 'pending') throw new AadError(70016);
        if (entry.status === 'denied') {
          store.consumeDeviceCode(entry.deviceCode);
          throw new AadError(65004);
        }
        store.consumeDeviceCode(entry.deviceCode);
        const user = directory.user(entry.userOid);
        const result = issueUserTokens({
          app, user, scope: entry.scope, authTime: entry.authTime, includeClientInfo: true,
        });
        store.record({ event: 'token.device_code', detail: `${app.displayName} -> ${user.userPrincipalName}` });
        return json(res, 200, result);
      }

      default:
        throw new AadError(9002313, `Unsupported grant_type '${grantType}'.`);
    }
  }

  // ---------------------------------------------------------- device login

  async function handleDeviceCodeRequest(req, res, tenantSegment) {
    const body = await formBody(req);
    const app = requireApp(body.client_id);
    requireGrant(app, 'device_code');
    resolveResourceOrThrow(body.scope);

    const entry = store.createDeviceCode({ clientId: app.appId, scope: body.scope || '' });
    const verificationUri = `${baseUrl}/${tenantSegment}/oauth2/deviceauth`;
    store.record({ event: 'devicecode', detail: `${app.displayName} user_code=${entry.userCode}` });

    return json(res, 200, {
      user_code: entry.userCode,
      device_code: entry.deviceCode,
      verification_uri: verificationUri,
      expires_in: entry.expiresAt - Math.floor(Date.now() / 1000),
      interval: 5,
      message: `To sign in, use a web browser to open the page ${verificationUri} and enter the code ${entry.userCode} to authenticate.`,
    });
  }

  async function handleDeviceAuth(req, res, cookies, url) {
    if (req.method === 'GET') {
      return html(res, 200, pages.devicePage({ tenant, userCode: url.searchParams.get('code') || '' }));
    }
    const body = await formBody(req);
    const entry = store.getDeviceCodeByUserCode(body.user_code);
    if (!entry) {
      return html(res, 400, pages.devicePage({
        tenant, userCode: body.user_code, error: new AadError(70018).message,
      }));
    }
    const app = directory.app(entry.clientId);
    const session = store.getSession(cookies[SESSION_COOKIE]);
    if (!session) {
      // Reuse the normal sign-in screen, then come back here.
      return html(res, 200, pages.loginPage({
        tenant, app, users: directory.users,
        requestParams: { client_id: app.appId, redirect_uri: '', scope: entry.scope, user_code: entry.userCode },
        showPasswordHints: true,
      }).replace(`action="/${tenant.id}/login"`, `action="/${tenant.id}/oauth2/deviceauth/login"`));
    }
    entry.status = 'approved';
    entry.userOid = session.userOid;
    entry.authTime = session.authTime;
    store.record({ event: 'devicecode.approved', detail: entry.userCode });
    return html(res, 200, pages.devicePage({
      tenant, message: 'You have signed in to the application on your device. You may now close this window.',
    }));
  }

  async function handleDeviceLogin(req, res) {
    const body = await formBody(req);
    const entry = store.getDeviceCodeByUserCode(body.user_code);
    const app = entry ? directory.app(entry.clientId) : null;
    const user = directory.userByName(body.username);

    if (!entry) {
      return html(res, 400, pages.devicePage({ tenant, error: new AadError(70018).message }));
    }
    if (!user || body.password !== user.password || user.accountEnabled === false || user.requiresMfa) {
      const err = user && user.requiresMfa ? new AadError(50076) : new AadError(50126);
      return html(res, 200, pages.loginPage({
        tenant, app, users: directory.users,
        requestParams: { client_id: app.appId, redirect_uri: '', scope: entry.scope, user_code: entry.userCode },
        error: err.message, prefillUsername: body.username, showPasswordHints: true,
      }).replace(`action="/${tenant.id}/login"`, `action="/${tenant.id}/oauth2/deviceauth/login"`));
    }

    const sessionId = store.createSession(user.objectId);
    entry.status = 'approved';
    entry.userOid = user.objectId;
    entry.authTime = Math.floor(Date.now() / 1000);
    store.record({ event: 'devicecode.approved', detail: `${entry.userCode} ${user.userPrincipalName}` });
    res.setHeader('set-cookie', cookie(SESSION_COOKIE, sessionId, { maxAge: 8 * 60 * 60 }));
    return html(res, 200, pages.devicePage({
      tenant, message: 'You have signed in to the application on your device. You may now close this window.',
    }));
  }

  // ---------------------------------------------------------------- logout

  function handleLogout(res, url, cookies) {
    const session = store.getSession(cookies[SESSION_COOKIE]);
    if (session) {
      store.endSession(session.id);
      store.record({ event: 'logout', detail: session.userOid });
    }
    res.setHeader('set-cookie', cookie(SESSION_COOKIE, '', { maxAge: 0 }));

    const target = url.searchParams.get('post_logout_redirect_uri');
    const state = url.searchParams.get('state');
    const registered = directory.applications.some((a) => (a.postLogoutRedirectUris || []).includes(target));
    if (target && registered) {
      const dest = new URL(target);
      if (state) dest.searchParams.append('state', state);
      return redirect(res, dest.toString());
    }
    return html(res, 200, pages.messagePage(
      'You have signed out',
      target
        ? `<p>The application asked to return you to <code>${escapeHtml(target)}</code>, but that URL is not registered as a front-channel logout URL for any application in this tenant.</p>`
        : '<p>You have signed out of your account. It is a good idea to close all browser windows.</p>',
    ));
  }

  // ------------------------------------------------ userinfo / mock Graph

  function requireResourceToken(req, expectedAudience) {
    const token = bearerToken(req);
    if (!token) {
      throw Object.assign(new Error('missing bearer token'), { httpStatus: 401, graphCode: 'InvalidAuthenticationToken' });
    }
    try {
      return verifyJwt(token, { jwks: key.jwks.keys, issuer, audience: expectedAudience });
    } catch (err) {
      throw Object.assign(new Error(`CompactToken validation failed: ${err.message}`), {
        httpStatus: 401, graphCode: 'InvalidAuthenticationToken',
      });
    }
  }

  function graphError(res, err) {
    return json(res, err.httpStatus || 500, {
      error: {
        code: err.graphCode || 'generalException',
        message: err.message,
        innerError: { date: new Date().toISOString(), 'request-id': crypto.randomUUID() },
      },
    });
  }

  function handleUserinfo(req, res) {
    const claims = requireResourceToken(req, GRAPH_RESOURCE);
    const user = directory.user(claims.oid);
    if (!user) throw Object.assign(new Error('user not found'), { httpStatus: 404, graphCode: 'ResourceNotFound' });
    return json(res, 200, {
      sub: claims.sub,
      name: user.displayName,
      family_name: user.surname,
      given_name: user.givenName,
      email: user.mail,
      picture: `${baseUrl}/v1.0/me/photo/$value`,
    });
  }

  function handleGraphMe(req, res) {
    const claims = requireResourceToken(req, GRAPH_RESOURCE);
    const user = directory.user(claims.oid);
    if (!user) throw Object.assign(new Error('user not found'), { httpStatus: 404, graphCode: 'ResourceNotFound' });
    return json(res, 200, {
      '@odata.context': `${baseUrl}/v1.0/$metadata#users/$entity`,
      id: user.objectId,
      displayName: user.displayName,
      givenName: user.givenName,
      surname: user.surname,
      userPrincipalName: user.userPrincipalName,
      mail: user.mail || null,
      jobTitle: user.jobTitle || null,
      department: user.department || null,
      officeLocation: user.officeLocation || null,
      mobilePhone: user.mobilePhone || null,
      businessPhones: user.businessPhones || [],
      preferredLanguage: user.preferredLanguage || 'en-GB',
    });
  }

  function handleGraphMemberOf(req, res) {
    const claims = requireResourceToken(req, GRAPH_RESOURCE);
    const user = directory.user(claims.oid);
    const groups = (user.groups || []).map((id) => directory.group(id)).filter(Boolean);
    return json(res, 200, {
      '@odata.context': `${baseUrl}/v1.0/$metadata#directoryObjects`,
      value: groups.map((g) => ({
        '@odata.type': '#microsoft.graph.group',
        id: g.id,
        displayName: g.displayName,
        securityEnabled: true,
      })),
    });
  }

  // ---------------------------------------------------------------- router

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, baseUrl);
    const segments = url.pathname.split('/').filter(Boolean);
    const cookies = parseCookies(req);

    try {
      if (url.pathname === '/favicon.ico') {
        res.writeHead(204);
        return res.end();
      }
      if (url.pathname === '/' || url.pathname === '') {
        return html(res, 200, pages.homePage({
          tenant, issuer, baseUrl, apps: directory.applications, users: directory.users, log: store.log,
        }));
      }

      // Mock Microsoft Graph, hosted alongside the identity endpoints.
      if (segments[0] === 'v1.0' || segments[0] === 'beta') {
        const rest = segments.slice(1).join('/');
        try {
          if (rest === 'me' && req.method === 'GET') return handleGraphMe(req, res);
          if (rest === 'me/memberOf' && req.method === 'GET') return handleGraphMemberOf(req, res);
          return graphError(res, Object.assign(new Error(`Resource '/${rest}' is not implemented by the mock Graph.`), {
            httpStatus: 404, graphCode: 'ResourceNotFound',
          }));
        } catch (err) {
          return graphError(res, err);
        }
      }
      if (url.pathname === '/oidc/userinfo') {
        try {
          return handleUserinfo(req, res);
        } catch (err) {
          return graphError(res, err);
        }
      }

      const tenantSegment = segments[0];
      if (!isTenantSegment(tenantSegment)) {
        throw new AadError(900023, `Tenant '${tenantSegment}' was not found. This mock hosts a single tenant: '${tenant.id}' (${tenant.domain}); 'common' and 'organizations' are also accepted.`);
      }
      const route = segments.slice(1).join('/');

      switch (`${req.method} /${route}`) {
        case 'GET /v2.0/.well-known/openid-configuration':
          return json(res, 200, openidConfiguration(tenantSegment), { 'cache-control': 'max-age=86400, private' });

        case 'GET /discovery/v2.0/keys':
          return json(res, 200, key.jwks, { 'cache-control': 'max-age=86400, private' });

        case 'GET /oauth2/v2.0/authorize':
          return handleAuthorize(req, res, queryParams(url), cookies);

        case 'POST /oauth2/v2.0/authorize':
          return handleAuthorize(req, res, await formBody(req), cookies);

        case 'POST /login':
          return await handleLogin(req, res);

        case 'POST /consent':
          return await handleConsent(req, res, cookies);

        case 'POST /oauth2/v2.0/token':
          return await handleToken(req, res);

        case 'GET /oauth2/v2.0/logout':
          return handleLogout(res, url, cookies);

        case 'POST /oauth2/v2.0/devicecode':
          return await handleDeviceCodeRequest(req, res, tenantSegment);

        case 'GET /oauth2/deviceauth':
        case 'POST /oauth2/deviceauth':
          return await handleDeviceAuth(req, res, cookies, url);

        case 'POST /oauth2/deviceauth/login':
          return await handleDeviceLogin(req, res);

        default:
          if (/^\/oauth2\/(authorize|token)$/.test(`/${route}`)) {
            throw new AadError(9002313, 'This mock implements the v2.0 endpoints only. Use /oauth2/v2.0/authorize and /oauth2/v2.0/token, and the v2.0 discovery document.');
          }
          throw new AadError(9002313, `No route for ${req.method} ${url.pathname}.`);
      }
    } catch (err) {
      if (err instanceof AadError) {
        store.record({ event: 'error', detail: err.message });
        return json(res, err.status, err.toJSON());
      }
      store.record({ event: 'error', detail: String(err && err.message) });
      // eslint-disable-next-line no-console
      console.error(err);
      return json(res, 500, { error: 'server_error', error_description: String(err && err.message) });
    }
  });

  server.on('listening', () => {
    const addr = server.address();
    // eslint-disable-next-line no-console
    console.log(
      `Mock Entra ID listening on http://localhost:${addr.port}\n` +
      `  authority  ${baseUrl}/${tenant.id}\n` +
      `  discovery  ${baseUrl}/${tenant.id}/v2.0/.well-known/openid-configuration\n` +
      `  dev console ${baseUrl}/`,
    );
  });

  return Object.assign(server, { directory, store, key, issuer, baseUrl, tenant });
}

if (require.main === module) {
  const server = createServer();
  server.listen(Number(process.env.MOCK_ENTRA_PORT || 8080));
}

module.exports = { createServer };
