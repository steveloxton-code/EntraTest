'use strict';

// Claim sets that match what Entra ID puts in v2.0 id_tokens and access
// tokens. Reference:
// https://learn.microsoft.com/entra/identity-platform/id-token-claims-reference
// https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference

const crypto = require('node:crypto');
const { signJwt, b64url } = require('../../shared/jose');

const ID_TOKEN_LIFETIME = 60 * 60;
const ACCESS_TOKEN_LIFETIME = 60 * 60 + 19 * 60; // Entra's ~1h+ variable lifetime

function rand(bytes) {
  return b64url(crypto.randomBytes(bytes));
}

/**
 * `sub` is a pairwise identifier: stable for a given user in a given
 * application, and different for the same user in another application. Apps
 * that key their own records on `sub` behave identically against real Entra
 * only if we reproduce that, so we derive it deterministically.
 */
function pairwiseSub(tenantId, userOid, clientId) {
  return b64url(
    crypto.createHash('sha256').update(`${tenantId}|${userOid}|${clientId}`).digest(),
  ).slice(0, 43);
}

function baseClaims({ issuer, tenantId, lifetime }) {
  const iat = Math.floor(Date.now() / 1000);
  return {
    iss: issuer,
    iat,
    nbf: iat,
    exp: iat + lifetime,
    aio: rand(24),
    rh: `0.${rand(16)}.`,
    tid: tenantId,
    uti: rand(16),
    ver: '2.0',
  };
}

function userRolesFor(user, app) {
  return (user.appRoles && user.appRoles[app.appId]) || [];
}

/**
 * id_token - describes *who signed in*, audience is always the client itself.
 */
function buildIdToken({ issuer, tenant, user, app, nonce, authTime, key, directory, scopes = [] }) {
  const claims = {
    aud: app.appId,
    ...baseClaims({ issuer, tenantId: tenant.id, lifetime: ID_TOKEN_LIFETIME }),
    auth_time: authTime,
    name: user.displayName,
    oid: user.objectId,
    preferred_username: user.userPrincipalName,
    sub: pairwiseSub(tenant.id, user.objectId, app.appId),
  };
  if (nonce) claims.nonce = nonce;
  if (scopes.includes('email') && user.mail) claims.email = user.mail;
  if (scopes.includes('profile')) {
    if (user.givenName) claims.given_name = user.givenName;
    if (user.surname) claims.family_name = user.surname;
  }
  const roles = userRolesFor(user, app);
  if (roles.length) claims.roles = roles;
  if (app.groupsClaim && user.groups && user.groups.length) claims.groups = user.groups;

  return signJwt(claims, key.privateKey, { kid: key.kid, ...(key.x5t ? { x5t: key.x5t } : {}) });
}

/**
 * Delegated access token - "app X acting for user Y against resource R".
 */
function buildUserAccessToken({ issuer, tenant, user, app, resource, audience, scopes, key }) {
  const resourceApp = resource.resourceApp;
  const claims = {
    aud: audience,
    ...baseClaims({ issuer, tenantId: tenant.id, lifetime: ACCESS_TOKEN_LIFETIME }),
    azp: app.appId,
    azpacr: app.isPublicClient ? '0' : '1', // 0 = public client, 1 = client secret
    name: user.displayName,
    oid: user.objectId,
    preferred_username: user.userPrincipalName,
    scp: scopes.join(' '),
    sub: pairwiseSub(tenant.id, user.objectId, app.appId),
  };
  const roles = resourceApp ? userRolesFor(user, resourceApp) : [];
  if (roles.length) claims.roles = roles;
  if (resourceApp && resourceApp.groupsClaim && user.groups && user.groups.length) {
    claims.groups = user.groups;
  }
  return signJwt(claims, key.privateKey, { kid: key.kid, ...(key.x5t ? { x5t: key.x5t } : {}) });
}

/**
 * App-only access token (client credentials). No user claims; authorization
 * comes from `roles` (application permissions), and there is no `scp`.
 */
function buildAppAccessToken({ issuer, tenant, app, resource, audience, key }) {
  const roles =
    (app.applicationRoles && (app.applicationRoles[resource.resourceApp?.appId] ||
      app.applicationRoles[resource.resource])) || [];
  const claims = {
    aud: audience,
    ...baseClaims({ issuer, tenantId: tenant.id, lifetime: ACCESS_TOKEN_LIFETIME }),
    azp: app.appId,
    azpacr: '1',
    oid: `00000000-0000-0000-0000-${app.appId.replace(/-/g, '').slice(0, 12)}`,
    sub: `00000000-0000-0000-0000-${app.appId.replace(/-/g, '').slice(0, 12)}`,
    idtyp: 'app',
  };
  if (roles.length) claims.roles = roles;
  return signJwt(claims, key.privateKey, { kid: key.kid, ...(key.x5t ? { x5t: key.x5t } : {}) });
}

module.exports = {
  buildIdToken,
  buildUserAccessToken,
  buildAppAccessToken,
  pairwiseSub,
  userRolesFor,
  ID_TOKEN_LIFETIME,
  ACCESS_TOKEN_LIFETIME,
};
