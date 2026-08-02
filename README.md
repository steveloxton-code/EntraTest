# EntraTest — a local stand-in for Microsoft Entra ID

A mock identity provider that speaks the same protocol as
`login.microsoftonline.com`, plus a sample web app that authenticates against
it. Develop and test offline, then point the app at a real Entra tenant by
changing configuration — no code changes.

Zero dependencies: Node.js 20+ and nothing else.

```
mock-entra/    the mock identity provider (and a mock Microsoft Graph)
sample-app/    a web app protected by it, written against the OIDC contract
shared/        JWT/JOSE and HTTP helpers used by both
examples/      device code flow CLI
test/          end-to-end tests for every flow
docs/          going-live guide and a parity/limitations list
```

## Run it

```bash
npm start          # identity provider on :8080 and sample app on :3000
npm test           # 36 end-to-end tests across every supported flow
```

Then open <http://localhost:3000> and sign in as `alice@contoso.onmicrosoft.com`
with password `Passw0rd!`. <http://localhost:8080> is a dev console listing the
tenant, the app registrations, the test users and recent requests.

You can also run the two halves separately:

```bash
npm run start:idp        # just the identity provider
npm run start:app        # just the sample app
npm run device-demo      # device code flow in a terminal
```

## What the mock implements

| Endpoint | Path |
| --- | --- |
| Discovery | `/{tenant}/v2.0/.well-known/openid-configuration` |
| JWKS | `/{tenant}/discovery/v2.0/keys` |
| Authorize | `/{tenant}/oauth2/v2.0/authorize` |
| Token | `/{tenant}/oauth2/v2.0/token` |
| Logout | `/{tenant}/oauth2/v2.0/logout` |
| Device code | `/{tenant}/oauth2/v2.0/devicecode` |
| UserInfo | `/oidc/userinfo` |
| Graph (mock) | `/v1.0/me`, `/v1.0/me/memberOf` |

`{tenant}` accepts the tenant GUID, the tenant domain, `common` or
`organizations` — as with Entra, the `iss` claim always names the real tenant.

**Flows:** authorization code with PKCE (S256 and plain), refresh token with
rotation, client credentials, resource owner password credentials, device code.
**Response modes:** `query`, `fragment`, `form_post`.

**Faithful to Entra in the details that break integrations:**

- RS256-signed tokens with a real JWKS (`kid`/`x5t`/`x5c`), so signature and
  issuer validation exercise the same code path you will use in production.
- v2.0 claim sets: `oid`, `tid`, `preferred_username`, pairwise `sub`, `aio`,
  `rh`, `uti`, `ver`, `nonce`, `roles`, `groups`, `scp`, `azp`, `azpacr`,
  `idtyp`.
- Errors as `{error, error_description, error_codes, trace_id, correlation_id}`
  with real `AADSTSnnnnn` codes — `AADSTS50011` redirect URI mismatch,
  `AADSTS54005` code replay, `AADSTS50148` PKCE mismatch, `AADSTS7000215` bad
  secret, `AADSTS50076` MFA required, `AADSTS50058` silent sign-in failed, and
  others.
- Single-use authorization codes, rotating refresh tokens, exact redirect URI
  matching, PKCE enforcement for public clients, `/.default` required for
  client credentials, and app-only tokens that carry `roles` but no `scp`.

See [docs/parity.md](docs/parity.md) for the full list, including what the mock
deliberately does *not* do.

## Configure the tenant

Everything an app can see about the directory lives in
[`mock-entra/directory.json`](mock-entra/directory.json): the tenant, its users
and groups, and the app registrations (client IDs, secrets, redirect URIs,
allowed grants, app roles, exposed scopes). Edit it and restart.

Three registrations are seeded, matching the three shapes a real tenant has:

| App | Client ID | Type |
| --- | --- | --- |
| Sample Web App | `8f1e0b32-…6f70` | confidential (secret + PKCE) |
| Sample Public Client | `c4d5e6f7-…4e5f` | public (PKCE only) |
| Sample Daemon | `d10e5f60-…1122` | client credentials, application roles |

Four users are seeded, including one that fails with `AADSTS50076` (MFA
required) and one disabled account (`AADSTS50057`) so failure paths are
testable.

Server settings come from the environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MOCK_ENTRA_PORT` | `8080` | listen port |
| `MOCK_ENTRA_BASE_URL` | `http://localhost:<port>` | issuer and endpoint base |
| `MOCK_ENTRA_DIRECTORY` | `mock-entra/directory.json` | tenant definition |
| `MOCK_ENTRA_KEY_DIR` | `mock-entra/.keys` | where the signing key is kept |

## The sample app

`sample-app/` is an ordinary OIDC relying party: authorization code flow with
PKCE, `state` and `nonce` checks, id_token validation against the published
JWKS, a refresh, an app-role-gated page, and a Microsoft Graph call. Its
provider-specific values are all configuration:

| Variable | Default |
| --- | --- |
| `AUTH_AUTHORITY` | `http://localhost:8080/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb` |
| `AUTH_CLIENT_ID` | `8f1e0b32-6a1e-4c1e-9a11-2b3c4d5e6f70` |
| `AUTH_CLIENT_SECRET` | `super-secret-value-not-for-production` |
| `AUTH_SCOPES` | `openid profile email offline_access User.Read` |
| `GRAPH_BASE_URL` | `http://localhost:8080` |
| `APP_BASE_URL` | `http://localhost:3000` |

To run it against a real tenant, set those five to the real values — see
[docs/going-live.md](docs/going-live.md).

## Using the mock with your own app

Point your existing authentication library at the mock's authority:

```
authority = http://localhost:8080/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb
```

Anything that consumes the OIDC discovery document works: MSAL (Node, .NET,
Java, Python, JS), `openid-client`, ASP.NET Core's
`AddMicrosoftIdentityWebApp`, Spring Security, `passport-azure-ad`. Register
your app's redirect URI in `directory.json` first — the mock enforces exact
matching just as Entra does.

Two things to know when using MSAL specifically:

- MSAL validates that the authority is a known Microsoft cloud host unless you
  disable it: set `knownAuthorities` (msal-node/msal-browser) or
  `ValidateAuthority = false` (.NET). This is expected — the mock is not
  `login.microsoftonline.com`.
- The mock serves plain HTTP. Some libraries require HTTPS for non-localhost
  authorities; keep it on `localhost` or terminate TLS in front of it.

## Tests

`npm test` starts the mock on an ephemeral port and drives the real HTTP
surface: happy paths, replay attacks, PKCE mismatches, wrong secrets, unknown
clients, unregistered redirect URIs, silent SSO, scope widening, token audience
enforcement and logout. `test/sample-app.test.js` additionally boots the sample
app and walks a browser session end to end.
