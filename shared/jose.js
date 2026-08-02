'use strict';

// Minimal JOSE helpers built on Node's crypto module.
// Only RS256 is supported, which is what Microsoft Entra ID uses for its
// id_tokens and for access tokens issued to custom (api://) audiences.

const crypto = require('node:crypto');

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

/**
 * Sign a JWT with RS256.
 * @param {object} payload claims
 * @param {import('node:crypto').KeyObject|string} privateKey
 * @param {object} header extra header fields (kid, x5t, ...)
 */
function signJwt(payload, privateKey, header = {}) {
  const head = { typ: 'JWT', alg: 'RS256', ...header };
  const signingInput = `${b64urlJson(head)}.${b64urlJson(payload)}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

/** Decode without verifying. Useful for logging/debugging only. */
function decodeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Not a JWS compact serialization');
  return {
    header: JSON.parse(b64urlDecode(parts[0]).toString('utf8')),
    payload: JSON.parse(b64urlDecode(parts[1]).toString('utf8')),
    signature: parts[2],
  };
}

/** Build a public JWK (RSA) from a PEM/KeyObject public key. */
function publicJwk(publicKey) {
  // Accept a public KeyObject, a private KeyObject, or PEM.
  const key =
    publicKey && publicKey.type === 'public' ? publicKey : crypto.createPublicKey(publicKey);
  const { n, e } = key.export({ format: 'jwk' });
  return { kty: 'RSA', n, e };
}

/** Turn a JWK back into a KeyObject so we can verify signatures with it. */
function jwkToKeyObject(jwk) {
  return crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
}

/**
 * Verify an RS256 JWT against a set of JWKS keys plus the usual OIDC checks.
 * This is deliberately written the same way you would validate a token issued
 * by the real login.microsoftonline.com, so the calling code does not change.
 *
 * @param {string} token
 * @param {object} opts
 * @param {Array} opts.jwks    keys array from the JWKS document
 * @param {string} opts.issuer expected `iss`
 * @param {string} opts.audience expected `aud`
 * @param {string} [opts.nonce] expected `nonce` (id_token from an auth code flow)
 * @param {number} [opts.clockSkewSec=300]
 * @param {number} [opts.now] unix seconds, for tests
 */
function verifyJwt(token, opts) {
  const { jwks, issuer, audience, nonce, clockSkewSec = 300 } = opts;
  const now = opts.now || Math.floor(Date.now() / 1000);

  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));

  if (header.alg !== 'RS256') throw new Error(`unexpected alg: ${header.alg}`);

  const candidates = (jwks || []).filter((k) => !header.kid || k.kid === header.kid);
  if (candidates.length === 0) throw new Error(`no signing key matches kid ${header.kid}`);

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = b64urlDecode(parts[2]);
  const ok = candidates.some((jwk) => {
    try {
      return crypto.verify('RSA-SHA256', signingInput, jwkToKeyObject(jwk), signature);
    } catch {
      return false;
    }
  });
  if (!ok) throw new Error('signature verification failed');

  if (issuer && payload.iss !== issuer) {
    throw new Error(`issuer mismatch: got ${payload.iss}, expected ${issuer}`);
  }
  if (audience) {
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(audience)) {
      throw new Error(`audience mismatch: got ${auds.join(',')}, expected ${audience}`);
    }
  }
  if (typeof payload.exp === 'number' && now > payload.exp + clockSkewSec) {
    throw new Error('token expired');
  }
  if (typeof payload.nbf === 'number' && now + clockSkewSec < payload.nbf) {
    throw new Error('token not yet valid');
  }
  if (nonce && payload.nonce !== nonce) throw new Error('nonce mismatch');

  return payload;
}

module.exports = { b64url, b64urlDecode, signJwt, decodeJwt, publicJwk, jwkToKeyObject, verifyJwt };
