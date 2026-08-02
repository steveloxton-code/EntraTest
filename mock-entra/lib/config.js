'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Well-known Microsoft identifiers that real apps hard-code, so the mock uses
// the same ones.
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
const GRAPH_RESOURCE = 'https://graph.microsoft.com';
const OIDC_SCOPES = new Set(['openid', 'profile', 'email', 'offline_access']);

const DEFAULT_CONFIG_PATH = path.join(__dirname, '..', 'directory.json');

function loadDirectory(configPath = process.env.MOCK_ENTRA_DIRECTORY || DEFAULT_CONFIG_PATH) {
  const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const tenant = raw.tenant;
  const users = raw.users || [];
  const groups = raw.groups || [];
  const applications = (raw.applications || []).map((app) => ({
    allowedGrants: ['authorization_code', 'refresh_token'],
    clientSecrets: [],
    redirectUris: [],
    postLogoutRedirectUris: [],
    exposedScopes: [],
    appRoles: [],
    applicationRoles: {},
    isPublicClient: false,
    requirePkce: true,
    requireConsent: false,
    requireUserAssignment: false,
    groupsClaim: false,
    ...app,
  }));

  const byAppId = new Map(applications.map((a) => [a.appId, a]));
  const byIdentifierUri = new Map(
    applications.filter((a) => a.identifierUri).map((a) => [a.identifierUri.replace(/\/$/, ''), a]),
  );

  return {
    configPath,
    tenant,
    users,
    groups,
    applications,

    app: (appId) => byAppId.get(appId),
    appByIdentifierUri: (uri) => byIdentifierUri.get(String(uri || '').replace(/\/$/, '')),
    user: (objectId) => users.find((u) => u.objectId === objectId),
    userByName: (name) => {
      const needle = String(name || '').toLowerCase();
      return users.find(
        (u) =>
          u.userPrincipalName.toLowerCase() === needle ||
          String(u.mail || '').toLowerCase() === needle,
      );
    },
    group: (id) => groups.find((g) => g.id === id),
  };
}

/**
 * Work out which resource (API) a token request is for.
 *
 * Entra requires every scope in a single request to belong to one resource,
 * and returns one access token for that resource. `openid`/`profile`/`email`/
 * `offline_access` are OIDC scopes and do not select a resource.
 *
 * @returns {{resource: string, audience: string, scopes: string[], oidcScopes: string[], isDefault: boolean, resourceApp: object|undefined}}
 */
function resolveResource(scopeString, directory) {
  const requested = String(scopeString || '').split(/\s+/).filter(Boolean);
  const oidcScopes = requested.filter((s) => OIDC_SCOPES.has(s));
  const resourceScopes = requested.filter((s) => !OIDC_SCOPES.has(s));

  const resources = new Set();
  const shortScopes = [];
  let isDefault = false;

  for (const scope of resourceScopes) {
    const idx = scope.lastIndexOf('/');
    if (idx > 0 && /^[a-z][a-z0-9+.-]*:\/\//i.test(scope)) {
      resources.add(scope.slice(0, idx));
      shortScopes.push(scope.slice(idx + 1));
    } else {
      // A bare scope such as "User.Read" targets Microsoft Graph.
      resources.add(GRAPH_RESOURCE);
      shortScopes.push(scope);
    }
  }
  if (shortScopes.includes('.default')) isDefault = true;

  if (resources.size > 1) {
    return { error: `Scopes from multiple resources requested: ${[...resources].join(', ')}` };
  }

  const resource = resources.size === 1 ? [...resources][0] : GRAPH_RESOURCE;
  const resourceApp = directory.appByIdentifierUri(resource);

  // v2.0 access tokens for a registered API carry the resource's app ID as the
  // audience; Microsoft Graph tokens carry the resource URI.
  const audience = resourceApp ? resourceApp.appId : resource;

  return {
    resource,
    audience,
    resourceApp,
    scopes: shortScopes.filter((s) => s !== '.default'),
    oidcScopes,
    isDefault,
  };
}

module.exports = { loadDirectory, resolveResource, GRAPH_APP_ID, GRAPH_RESOURCE, OIDC_SCOPES };
