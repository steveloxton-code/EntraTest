# Parity with Entra ID: what is faithful, what is not

The mock aims to be indistinguishable from Entra ID at the points where an
application touches it — URLs, parameters, token claims, and error codes — and
makes no attempt to reproduce Microsoft's internals.

## Faithful

### Protocol surface

- v2.0 endpoint layout under `/{tenant}/…`, with `{tenant}` accepting the
  tenant GUID, the tenant domain, `common` or `organizations`. The `iss` claim
  always names the real tenant, as Entra does.
- OIDC discovery document with the same field set Entra returns, including
  `tenant_region_scope`, `cloud_instance_name` and `msgraph_host`.
- JWKS with `kty`/`use`/`kid`/`n`/`e`, and `x5t`/`x5c` when a certificate can be
  generated (`openssl` on PATH). `kid` equals `x5t`, as in Entra.
- `response_mode` of `query`, `fragment` and `form_post`, the last returned as
  an auto-submitting HTML form.
- `prompt` of `none`, `login`, `select_account` and `consent`; `login_hint`.
- Browser SSO: a sign-in session cookie means a second application gets a code
  without a second sign-in, and `prompt=none` succeeds.

### Grants

| Grant | Notes |
| --- | --- |
| `authorization_code` | PKCE `S256` and `plain`; PKCE mandatory for public clients and for any app with `requirePkce` |
| `refresh_token` | rotated on every use; the old token is immediately invalid; scope may narrow, never widen |
| `client_credentials` | requires a `<resource>/.default` scope; issues app-only tokens with `roles`, no `scp`, no refresh token, no id_token |
| `password` (ROPC) | supported for test automation; see the caveat in going-live.md |
| `device_code` | full poll cycle with `authorization_pending`, plus the user-code entry page |

### Tokens

- RS256 signatures over a persisted 2048-bit key.
- id_token claims: `aud`, `iss`, `iat`, `nbf`, `exp`, `auth_time`, `aio`, `rh`,
  `uti`, `ver`, `tid`, `oid`, `sub`, `name`, `preferred_username`, `nonce`,
  `email`, `given_name`, `family_name`, `roles`, `groups`.
- Access token claims: the above minus id-token-specific ones, plus `scp`,
  `azp`, `azpacr`; app-only tokens carry `idtyp: "app"` and `roles`.
- `sub` is pairwise: stable per (user, application), different for the same
  user in another application. `oid` is the cross-application user identifier.
- Audience follows Entra's rule: v2.0 tokens for a registered API carry the
  resource application's client ID; Graph tokens carry
  `https://graph.microsoft.com`.
- All scopes in one request must belong to a single resource, or the request is
  rejected.

### Errors

Entra's JSON shape, everywhere:

```json
{
  "error": "invalid_grant",
  "error_description": "AADSTS54005: OAuth2 Authorization code was already redeemed…\r\nTrace ID: …\r\nCorrelation ID: …\r\nTimestamp: …",
  "error_codes": [54005],
  "timestamp": "…", "trace_id": "…", "correlation_id": "…", "error_uri": "…"
}
```

Implemented codes include:

| Code | Condition |
| --- | --- |
| `AADSTS50011` | redirect URI not registered |
| `AADSTS50034` / `50057` / `50126` | no such user / disabled account / bad password |
| `AADSTS50058` | `prompt=none` with no signed-in user |
| `AADSTS50076` | MFA required |
| `AADSTS50105` | user not assigned to a required app role |
| `AADSTS50148` | PKCE `code_verifier` mismatch |
| `AADSTS54005` | authorization code replayed |
| `AADSTS65001` / `65004` | consent needed / consent declined |
| `AADSTS70008` | expired code or refresh token |
| `AADSTS70011` | invalid scope |
| `AADSTS70016` / `70018` / `70019` | device code pending / bad user code / expired |
| `AADSTS500011` | resource principal not found in the tenant |
| `AADSTS700016` | unknown `client_id` |
| `AADSTS700051` | grant not enabled for the application |
| `AADSTS7000215` | wrong client secret |
| `AADSTS1002012` | client credentials without `/.default` |
| `AADSTS900144` | missing required parameter |

Errors are only redirected to `redirect_uri` once that URI has been validated
against the registration; an unregistered URI or unknown client renders an
error page instead, exactly as Entra does.

### Security behaviours worth testing against

- Exact-match redirect URI validation, including trailing slashes.
- Authorization codes are single-use with a 10-minute lifetime; a replay is
  reported as "already redeemed" rather than "unknown".
- Client secrets are compared in constant time.
- Front-channel logout only redirects to a registered
  `post_logout_redirect_uri`.
- Mock Graph validates signature, issuer and audience, so a token minted for a
  different resource is rejected with Graph's `InvalidAuthenticationToken`.

## Not reproduced

Deliberate omissions — if your application depends on one of these, test it
against a real tenant.

- **Conditional access, risk evaluation and real MFA.** One user is flagged
  `requiresMfa` and fails with `AADSTS50076` so the retry path is testable, but
  there is no second factor to satisfy.
- **Federation and external identities.** No WS-Fed/SAML, no B2B guests, no
  home-realm discovery, no `domain_hint` behaviour beyond accepting the
  parameter.
- **Certificate and federated credential client authentication** —
  `client_assertion` (JWT bearer) and workload identity federation are not
  implemented; only client secrets.
- **On-behalf-of flow** (`urn:ietf:params:oauth:grant-type:jwt-bearer`), used by
  middle-tier APIs.
- **Implicit and hybrid flows.** `response_type=code` only; `id_token` and
  `token` response types are rejected with `unsupported_response_type`. The
  authorization code flow with PKCE is what Microsoft recommends for every
  client type.
- **v1.0 endpoints** (`/oauth2/authorize`, `/oauth2/token`,
  `sts.windows.net` issuers). Requests to them return an explanatory error.
- **Opaque Graph tokens.** The mock issues JWTs for every audience so tests can
  inspect them; real Graph tokens are opaque. Do not build on being able to
  read one.
- **Continuous access evaluation, token revocation lists and `xms_cc`.**
- **Most of Microsoft Graph.** Only `/v1.0/me`, `/v1.0/me/memberOf` and
  `/oidc/userinfo` exist.
- **Groups overage claims**, admin consent endpoints, app provisioning,
  entitlement management, and everything else in the directory that is not
  users, groups and app registrations.
- **Multiple tenants.** One tenant per running instance; start a second
  instance with a different `MOCK_ENTRA_DIRECTORY` if you need two.
- **Persistence.** Sessions, codes and refresh tokens are in memory. Restarting
  the mock resets all state; only the signing key persists (in
  `mock-entra/.keys/`, which is gitignored).

## Not a security boundary

The mock accepts test passwords from a plaintext JSON file, prints them on its
sign-in page, and issues tokens to anyone who asks correctly. Run it on
localhost or a trusted development network. It is a test double, not an
identity provider.
