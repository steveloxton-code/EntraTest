'use strict';

// Token signing key management.
//
// Entra publishes RSA public keys at the JWKS endpoint, each with a `kid` that
// equals the base64url SHA-1 thumbprint of the signing certificate (`x5t`), and
// an `x5c` chain. We reproduce that shape: if `openssl` is on PATH we mint a
// self-signed certificate so x5c/x5t are real; otherwise we fall back to a
// bare RSA JWK (kid derived from the public key) which every standard OIDC
// library still accepts.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { b64url, publicJwk } = require('../../shared/jose');

const KEY_DIR = process.env.MOCK_ENTRA_KEY_DIR || path.join(__dirname, '..', '.keys');
const KEY_FILE = path.join(KEY_DIR, 'signing.key.pem');
const CERT_FILE = path.join(KEY_DIR, 'signing.cert.pem');

function tryMakeSelfSignedCert(privatePem) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mock-entra-'));
  const keyPath = path.join(tmp, 'key.pem');
  const certPath = path.join(tmp, 'cert.pem');
  try {
    fs.writeFileSync(keyPath, privatePem, { mode: 0o600 });
    execFileSync('openssl', [
      'req', '-new', '-x509',
      '-key', keyPath,
      '-out', certPath,
      '-days', '3650',
      '-subj', '/CN=Mock Entra ID Token Signing',
      '-sha256',
    ], { stdio: 'ignore' });
    return fs.readFileSync(certPath, 'utf8');
  } catch {
    return null; // openssl missing or failed - JWKS just won't carry x5c/x5t
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function generate() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const cert = tryMakeSelfSignedCert(privatePem);
  return { privatePem, publicKey, cert };
}

function load() {
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });

  let privatePem;
  let cert = null;
  if (fs.existsSync(KEY_FILE)) {
    privatePem = fs.readFileSync(KEY_FILE, 'utf8');
    if (fs.existsSync(CERT_FILE)) cert = fs.readFileSync(CERT_FILE, 'utf8');
  } else {
    const generated = generate();
    privatePem = generated.privatePem;
    cert = generated.cert;
    fs.writeFileSync(KEY_FILE, privatePem, { mode: 0o600 });
    if (cert) fs.writeFileSync(CERT_FILE, cert, { mode: 0o600 });
  }

  const privateKey = crypto.createPrivateKey(privatePem);
  const publicKey = crypto.createPublicKey(privateKey);
  const jwk = publicJwk(publicKey);

  let kid;
  let x5t;
  let x5c;
  if (cert) {
    const der = Buffer.from(
      cert.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, ''),
      'base64',
    );
    x5t = b64url(crypto.createHash('sha1').update(der).digest());
    x5c = [der.toString('base64')];
    kid = x5t; // Entra uses the same value for kid and x5t
  } else {
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    kid = b64url(crypto.createHash('sha256').update(spki).digest()).slice(0, 27);
  }

  const jwks = { keys: [{ kty: 'RSA', use: 'sig', kid, ...(x5t ? { x5t } : {}), ...jwk, ...(x5c ? { x5c } : {}) }] };

  return { privateKey, publicKey, kid, x5t, jwks };
}

module.exports = { load, KEY_DIR };
