'use strict';

// A small, standards-only OpenID Connect client.
//
// Nothing in here is mock-specific: it discovers the provider through the
// OpenID Connect discovery document, validates id_tokens against the published
// JWKS, and uses the authorization code flow with PKCE. Point `authority` at
// https://login.microsoftonline.com/<tenant-id> and it talks to real Entra ID.

const crypto = require('node:crypto');
const { verifyJwt, decodeJwt } = require('../../shared/jose');

class OidcClient {
  /**
   * @param {object} opts
   * @param {string} opts.authority e.g. http://localhost:8080/<tenant-id>
   * @param {string} opts.clientId
   * @param {string} [opts.clientSecret] omit for public clients
   * @param {string} opts.redirectUri
   * @param {number} [opts.discoveryTtlMs]
   */
  constructor(opts) {
    this.authority = opts.authority.replace(/\/$/, '');
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.redirectUri = opts.redirectUri;
    this.discoveryTtlMs = opts.discoveryTtlMs ?? 24 * 60 * 60 * 1000;
    this._metadata = null;
    this._jwks = null;
    this._fetchedAt = 0;
  }

  async metadata() {
    if (this._metadata && Date.now() - this._fetchedAt < this.discoveryTtlMs) return this._metadata;
    const url = `${this.authority}/v2.0/.well-known/openid-configuration`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`discovery failed: ${res.status} ${await res.text()}`);
    this._metadata = await res.json();
    this._fetchedAt = Date.now();
    this._jwks = null;
    return this._metadata;
  }

  async jwks() {
    if (this._jwks) return this._jwks;
    const { jwks_uri: jwksUri } = await this.metadata();
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    this._jwks = (await res.json()).keys;
    return this._jwks;
  }

  /** PKCE pair: keep `verifier` server-side, send `challenge` to the IdP. */
  static createPkcePair() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge, method: 'S256' };
  }

  static randomString(bytes = 16) {
    return crypto.randomBytes(bytes).toString('base64url');
  }

  async authorizationUrl({ scope, state, nonce, codeChallenge, prompt, loginHint, responseMode }) {
    const { authorization_endpoint: endpoint } = await this.metadata();
    const url = new URL(endpoint);
    const params = {
      client_id: this.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      response_mode: responseMode || 'query',
      prompt,
      login_hint: loginHint,
    };
    for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
    return url.toString();
  }

  async #postToken(body) {
    const { token_endpoint: endpoint } = await this.metadata();
    const form = new URLSearchParams({ client_id: this.clientId, ...body });
    if (this.clientSecret) form.set('client_secret', this.clientSecret);

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(payload.error_description || `token request failed: ${res.status}`);
      err.oauth = payload;
      err.status = res.status;
      throw err;
    }
    return payload;
  }

  redeemCode({ code, codeVerifier, scope }) {
    return this.#postToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      code_verifier: codeVerifier,
      ...(scope ? { scope } : {}),
    });
  }

  refresh({ refreshToken, scope }) {
    return this.#postToken({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      ...(scope ? { scope } : {}),
    });
  }

  clientCredentials({ scope }) {
    return this.#postToken({ grant_type: 'client_credentials', scope });
  }

  /** Validate an id_token exactly as you would against real Entra ID. */
  async validateIdToken(idToken, { nonce } = {}) {
    const { issuer } = await this.metadata();
    return verifyJwt(idToken, {
      jwks: await this.jwks(),
      issuer,
      audience: this.clientId,
      nonce,
    });
  }

  /** Validate a token issued *for this app as an API* (audience = this app). */
  async validateAccessToken(accessToken, { audience } = {}) {
    const { issuer } = await this.metadata();
    return verifyJwt(accessToken, {
      jwks: await this.jwks(),
      issuer,
      audience: audience || this.clientId,
    });
  }

  async logoutUrl({ postLogoutRedirectUri, state } = {}) {
    const { end_session_endpoint: endpoint } = await this.metadata();
    const url = new URL(endpoint);
    if (postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
    if (state) url.searchParams.set('state', state);
    return url.toString();
  }

  static decode(token) {
    return decodeJwt(token);
  }
}

module.exports = { OidcClient };
