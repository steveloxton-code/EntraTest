'use strict';

// In-memory state: sign-in sessions, authorization codes, refresh tokens,
// device codes and recorded consent. Everything is deliberately volatile -
// restarting the mock is the fastest way to reset a test run.

const crypto = require('node:crypto');

const TTL = {
  authCode: 10 * 60, // Entra authorization codes live ~10 minutes
  session: 8 * 60 * 60,
  refreshToken: 24 * 60 * 60 * 90,
  deviceCode: 15 * 60,
};

function now() {
  return Math.floor(Date.now() / 1000);
}

class Store {
  constructor() {
    this.sessions = new Map();
    this.codes = new Map();
    this.refreshTokens = new Map();
    this.deviceCodes = new Map();
    this.consents = new Map(); // `${userOid}|${clientId}` -> Set(scope)
    this.log = [];
  }

  // ---- sign-in sessions (the browser cookie) ----------------------------

  createSession(userOid, { amr = ['pwd'] } = {}) {
    const id = crypto.randomUUID();
    this.sessions.set(id, { id, userOid, amr, authTime: now(), expiresAt: now() + TTL.session });
    return id;
  }

  getSession(id) {
    const session = this.sessions.get(id);
    if (!session) return null;
    if (session.expiresAt < now()) {
      this.sessions.delete(id);
      return null;
    }
    return session;
  }

  endSession(id) {
    this.sessions.delete(id);
  }

  // ---- authorization codes ---------------------------------------------

  createCode(data) {
    for (const [old, entry] of this.codes) {
      if (entry.expiresAt < now()) this.codes.delete(old);
    }
    const code = `0.${crypto.randomBytes(48).toString('base64url')}`;
    this.codes.set(code, { ...data, expiresAt: now() + TTL.authCode, redeemed: false });
    return code;
  }

  /** Returns { entry } or { error: 'expired' | 'unknown' | 'redeemed' }. */
  takeCode(code) {
    const entry = this.codes.get(code);
    if (!entry) return { error: 'unknown' };
    if (entry.redeemed) return { error: 'redeemed' };
    if (entry.expiresAt < now()) {
      this.codes.delete(code);
      return { error: 'expired' };
    }
    // Keep the redeemed entry around briefly so a replay reports "already
    // redeemed" (AADSTS54005) rather than "unknown code", like Entra does.
    entry.redeemed = true;
    return { entry };
  }

  // ---- refresh tokens ---------------------------------------------------

  createRefreshToken(data) {
    const token = `0.${crypto.randomBytes(64).toString('base64url')}`;
    this.refreshTokens.set(token, { ...data, expiresAt: now() + TTL.refreshToken });
    return token;
  }

  takeRefreshToken(token) {
    const entry = this.refreshTokens.get(token);
    if (!entry) return { error: 'unknown' };
    if (entry.expiresAt < now()) {
      this.refreshTokens.delete(token);
      return { error: 'expired' };
    }
    this.refreshTokens.delete(token); // Entra rotates refresh tokens on use
    return { entry };
  }

  revokeRefreshTokensForUser(userOid) {
    for (const [token, entry] of this.refreshTokens) {
      if (entry.userOid === userOid) this.refreshTokens.delete(token);
    }
  }

  // ---- device code flow -------------------------------------------------

  createDeviceCode(data) {
    const deviceCode = crypto.randomBytes(32).toString('base64url');
    const alphabet = 'BCDFGHJKLMNPQRSTVWXZ';
    const userCode = Array.from({ length: 9 }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
    const entry = {
      ...data,
      deviceCode,
      userCode,
      status: 'pending', // pending | approved | denied
      expiresAt: now() + TTL.deviceCode,
    };
    this.deviceCodes.set(deviceCode, entry);
    return entry;
  }

  getDeviceCode(deviceCode) {
    const entry = this.deviceCodes.get(deviceCode);
    if (!entry) return null;
    if (entry.expiresAt < now()) {
      this.deviceCodes.delete(deviceCode);
      return null;
    }
    return entry;
  }

  getDeviceCodeByUserCode(userCode) {
    const needle = String(userCode || '').toUpperCase().replace(/[\s-]/g, '');
    for (const entry of this.deviceCodes.values()) {
      if (entry.userCode === needle && entry.expiresAt >= now()) return entry;
    }
    return null;
  }

  consumeDeviceCode(deviceCode) {
    this.deviceCodes.delete(deviceCode);
  }

  // ---- consent ----------------------------------------------------------

  grantConsent(userOid, clientId, scopes) {
    const key = `${userOid}|${clientId}`;
    const set = this.consents.get(key) || new Set();
    for (const scope of scopes) set.add(scope);
    this.consents.set(key, set);
  }

  hasConsent(userOid, clientId, scopes) {
    const set = this.consents.get(`${userOid}|${clientId}`);
    if (!set) return scopes.length === 0;
    return scopes.every((scope) => set.has(scope));
  }

  // ---- request log (surfaced in the dev console) ------------------------

  record(entry) {
    this.log.unshift({ at: new Date().toISOString(), ...entry });
    if (this.log.length > 200) this.log.pop();
  }
}

module.exports = { Store, TTL };
