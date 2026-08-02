'use strict';

const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

// Keep signing keys out of the working tree during tests.
if (!process.env.MOCK_ENTRA_KEY_DIR) {
  process.env.MOCK_ENTRA_KEY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mock-entra-test-keys-'));
}

const { createServer } = require('../mock-entra/server');

const CLIENTS = {
  web: {
    clientId: '8f1e0b32-6a1e-4c1e-9a11-2b3c4d5e6f70',
    clientSecret: 'super-secret-value-not-for-production',
    redirectUri: 'http://localhost:3000/auth/callback',
  },
  publicClient: {
    clientId: 'c4d5e6f7-1234-4321-9876-0a1b2c3d4e5f',
    redirectUri: 'http://localhost:5173/auth/callback',
  },
  daemon: {
    clientId: 'd10e5f60-7788-99aa-bbcc-ddeeff001122',
    clientSecret: 'daemon-secret-value',
  },
};

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function startMock({ directoryPath } = {}) {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const server = createServer({ port, baseUrl, directoryPath });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));

  const tenantId = server.tenant.id;
  return {
    server,
    baseUrl,
    tenantId,
    authority: `${baseUrl}/${tenantId}`,
    issuer: `${baseUrl}/${tenantId}/v2.0`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return {
    verifier,
    challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
  };
}

/** Minimal cookie jar so tests can behave like a browser session. */
class Jar {
  constructor() {
    this.cookies = new Map();
  }

  absorb(res) {
    for (const raw of res.headers.getSetCookie ? res.headers.getSetCookie() : []) {
      const [pair] = raw.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function get(url, { jar, headers = {} } = {}) {
  const res = await fetch(url, {
    redirect: 'manual',
    headers: { ...(jar ? { cookie: jar.header() } : {}), ...headers },
  });
  if (jar) jar.absorb(res);
  return res;
}

async function postForm(url, body, { jar, headers = {} } = {}) {
  const res = await fetch(url, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(jar ? { cookie: jar.header() } : {}),
      ...headers,
    },
    body: new URLSearchParams(body),
  });
  if (jar) jar.absorb(res);
  return res;
}

/**
 * Drive the interactive sign-in the way a browser would: request the
 * authorization endpoint, post credentials to the sign-in form, and return the
 * authorization code from the redirect.
 */
async function signIn(mock, {
  client = CLIENTS.web,
  username = 'alice@contoso.onmicrosoft.com',
  password = 'Passw0rd!',
  scope = 'openid profile email offline_access User.Read',
  challenge,
  state = 'test-state',
  nonce = 'test-nonce',
  jar = new Jar(),
  extra = {},
} = {}) {
  const authorizeUrl = new URL(`${mock.authority}/oauth2/v2.0/authorize`);
  const params = {
    client_id: client.clientId,
    response_type: 'code',
    redirect_uri: client.redirectUri,
    scope,
    state,
    nonce,
    ...(challenge ? { code_challenge: challenge, code_challenge_method: 'S256' } : {}),
    ...extra,
  };
  for (const [k, v] of Object.entries(params)) if (v !== undefined) authorizeUrl.searchParams.set(k, v);

  const page = await get(authorizeUrl.toString(), { jar });
  if (page.status !== 200) return { jar, response: page, params };

  const loginRes = await postForm(`${mock.authority}/login`, { ...params, username, password }, { jar });
  if (loginRes.status !== 302) return { jar, response: loginRes, params };

  const location = new URL(loginRes.headers.get('location'));
  return {
    jar,
    response: loginRes,
    params,
    location,
    code: location.searchParams.get('code'),
    state: location.searchParams.get('state'),
  };
}

module.exports = { startMock, signIn, postForm, get, pkce, freePort, Jar, CLIENTS };
