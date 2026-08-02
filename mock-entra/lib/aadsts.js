'use strict';

// Entra ID error responses have a very specific shape, and real client
// libraries (MSAL in particular) surface `error`, `error_codes` and the
// "AADSTSnnnnn" prefix to callers. Apps frequently branch on them - e.g.
// AADSTS50076 means "retry interactively for MFA" - so the mock reproduces
// them rather than inventing its own error format.

const crypto = require('node:crypto');

// code -> [oauth error, default message]
const CATALOG = {
  50011: ['invalid_request', "The redirect URI specified in the request does not match the redirect URIs configured for the application."],
  50034: ['invalid_grant', 'The user account does not exist in the directory.'],
  50053: ['invalid_grant', 'The account is locked because the user tried to sign in too many times with an incorrect user ID or password.'],
  50055: ['invalid_grant', 'The password is expired.'],
  50057: ['invalid_grant', 'The user account is disabled.'],
  50058: ['login_required', 'A silent sign-in request was sent but no user is signed in.'],
  50076: ['interaction_required', 'Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource.'],
  50105: ['invalid_grant', 'The signed in user is not assigned to a role for the application.'],
  50126: ['invalid_grant', 'Error validating credentials due to invalid username or password.'],
  50148: ['invalid_grant', 'The code_verifier does not match the code_challenge supplied in the authorization request.'],
  54005: ['invalid_grant', 'OAuth2 Authorization code was already redeemed, please retry with a new valid code or use an existing refresh token.'],
  65001: ['consent_required', 'The user or administrator has not consented to use the application.'],
  65004: ['access_denied', 'User declined to consent to access the app.'],
  70000: ['invalid_grant', 'Provided grant is invalid or malformed.'],
  70002: ['invalid_client', 'Error validating credentials. Invalid client secret is provided.'],
  70008: ['invalid_grant', 'The provided authorization code or refresh token has expired due to inactivity.'],
  70011: ['invalid_scope', 'The provided value for the input parameter scope is not valid.'],
  70016: ['authorization_pending', 'The end user has not yet finished authenticating. Continue polling.'],
  70018: ['invalid_grant', 'Invalid verification code due to an invalid, expired or already redeemed user code.'],
  70019: ['expired_token', 'Verification code expired. Have the user retry the sign-in.'],
  500011: ['invalid_resource', 'The resource principal named in the request was not found in the tenant. This can happen if the application has not been installed by the administrator of the tenant.'],
  700016: ['unauthorized_client', 'Application with identifier was not found in the directory.'],
  7000215: ['invalid_client', 'Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID.'],
  1002012: ['invalid_scope', 'The provided value for scope is not valid. Client credential flows must have a scope value with /.default suffixed to the resource identifier.'],
  700051: ['invalid_grant', 'The response_type is not enabled for the application.'],
  900144: ['invalid_request', 'The request body must contain the following parameter.'],
  900023: ['invalid_request', 'Specified tenant identifier is neither a valid DNS name, nor a valid external domain.'],
  9002313: ['invalid_request', 'Request is malformed or invalid.'],
};

function nowStamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

class AadError extends Error {
  /**
   * @param {number} code AADSTS numeric code
   * @param {string} [detail] appended to the catalog message for context
   * @param {object} [opts] { status, error, extra }
   */
  constructor(code, detail, opts = {}) {
    const [defaultError, defaultMessage] = CATALOG[code] || ['invalid_request', 'Request failed.'];
    const message = detail ? `${defaultMessage} ${detail}` : defaultMessage;
    super(`AADSTS${code}: ${message}`);
    this.name = 'AadError';
    this.code = code;
    this.oauthError = opts.error || defaultError;
    this.status = opts.status || (this.oauthError === 'invalid_client' ? 401 : 400);
    this.traceId = crypto.randomUUID();
    this.correlationId = opts.correlationId || crypto.randomUUID();
    this.timestamp = nowStamp();
    this.extra = opts.extra || {};
    this.description =
      `AADSTS${code}: ${message}\r\n` +
      `Trace ID: ${this.traceId}\r\n` +
      `Correlation ID: ${this.correlationId}\r\n` +
      `Timestamp: ${this.timestamp}`;
  }

  toJSON() {
    return {
      error: this.oauthError,
      error_description: this.description,
      error_codes: [this.code],
      timestamp: this.timestamp,
      trace_id: this.traceId,
      correlation_id: this.correlationId,
      error_uri: `https://login.microsoftonline.com/error?code=${this.code}`,
      ...this.extra,
    };
  }

  /** Query-string form used when redirecting an error back to the client. */
  toParams() {
    return {
      error: this.oauthError,
      error_description: this.description,
      error_uri: `https://login.microsoftonline.com/error?code=${this.code}`,
    };
  }
}

module.exports = { AadError, CATALOG };
