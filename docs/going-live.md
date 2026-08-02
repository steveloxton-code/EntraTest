# Switching from the mock to a real Entra ID tenant

The application code does not change. What changes is configuration, plus the
app registration work that has to happen in Entra rather than in a JSON file.

## 1. Register the application in Entra

In the Microsoft Entra admin centre, **Identity → Applications → App
registrations → New registration**:

| Mock (`directory.json`) | Entra portal |
| --- | --- |
| `appId` | Application (client) ID, generated for you |
| `tenant.id` | Directory (tenant) ID |
| `redirectUris` | Authentication → Platform configurations → Web / SPA → Redirect URIs |
| `postLogoutRedirectUris` | Authentication → Front-channel logout URL |
| `clientSecrets` | Certificates & secrets → New client secret |
| `isPublicClient: true` | Authentication → "Allow public client flows" = Yes |
| `appRoles` | App roles → Create app role |
| `user.appRoles` | Enterprise applications → Users and groups → Assign |
| `exposedScopes` | Expose an API → Add a scope |
| `identifierUri` | Expose an API → Application ID URI |
| `requireUserAssignment` | Enterprise applications → Properties → Assignment required |
| `applicationRoles` (daemon) | API permissions → Application permissions → Grant admin consent |

Redirect URIs must match exactly, including scheme, port and trailing slash —
the mock enforces the same rule so this is one fewer surprise.

## 2. Repoint the configuration

```bash
AUTH_AUTHORITY=https://login.microsoftonline.com/<tenant-id>
AUTH_CLIENT_ID=<application-client-id>
AUTH_CLIENT_SECRET=<client-secret-value>     # the value, not the secret ID
AUTH_SCOPES="openid profile email offline_access User.Read"
GRAPH_BASE_URL=https://graph.microsoft.com
APP_BASE_URL=https://your-app.example.com
```

Everything else — discovery, JWKS, endpoints, issuer — is read from the
discovery document at `${AUTH_AUTHORITY}/v2.0/.well-known/openid-configuration`,
so it follows automatically.

Use `common` instead of the tenant ID for a multi-tenant app, `organizations`
for any work or school account, `consumers` for personal Microsoft accounts
(the mock accepts `common` and `organizations` for the same reason).

## 3. Expect these differences on the real thing

None of them require code changes if the app is written the way the sample app
is, but they are worth knowing before the first live run.

**Microsoft Graph access tokens are opaque.** Real Entra issues Graph tokens in
an internal format. Never decode or validate an access token you are only
passing to Graph — send it as a bearer token and let Graph validate it. Tokens
for *your own* API (`api://…` scopes) are ordinary JWTs you can and should
validate. The sample app decodes the token only to display it, and tolerates
failure.

**The `iss` claim is not always what you first assume.** For v2.0 tokens it is
`https://login.microsoftonline.com/{tid}/v2.0`. Multi-tenant apps using the
`common` authority must validate against the tenant in the token, not against
the literal string `common`, and should check `tid` against an allow-list.

**Signing keys rotate.** Cache the discovery document and JWKS (24 hours is
usual) but refresh on an unknown `kid`. The client in `sample-app/lib/oidc.js`
caches with a TTL and re-fetches when discovery is reloaded.

**Conditional access and MFA can interrupt any request.** A token request that
worked yesterday can come back with `interaction_required` /
`AADSTS50076`/`AADSTS50079`, or `consent_required` / `AADSTS65001`. The correct
response is to retry interactively (`prompt=login` or a fresh authorization
request), not to fail hard. The mock's `mfa@contoso.onmicrosoft.com` user
returns `AADSTS50076` so this path can be exercised.

**Consent is real.** Delegated permissions beyond the basic OIDC scopes need
user or admin consent; application permissions always need admin consent. Set
`requireConsent: true` on an app in `directory.json` to rehearse the consent
screen and the `AADSTS65004` decline path.

**Resource owner password credentials (`grant_type=password`) is blocked** for
most real tenants, and always fails for federated or MFA-enabled accounts.
Treat the mock's support for it as a convenience for automated tests, not as a
production pattern.

**Token lifetimes vary.** Access tokens are 60–90 minutes with deliberate
jitter; refresh tokens last up to 90 days but are revoked by password changes,
sign-out and risk events. Always honour `expires_in` rather than hard-coding a
lifetime, and handle a refresh that fails with `invalid_grant` by sending the
user back through interactive sign-in.

**Groups claims may be absent.** If a user is in more than ~150 groups (200 for
implicit flows) Entra omits `groups` and sends a `_claim_names` /
`_claim_sources` overage pointer instead, and the app has to call Graph
(`/me/memberOf`) to enumerate them. Prefer app roles over group membership for
authorization decisions where you can.

**HTTPS is mandatory.** Real Entra will not redirect to an `http://` URI other
than `http://localhost`.

## 4. A checklist for the switch

- [ ] App registered; client ID, tenant ID and secret recorded in your secret store
- [ ] Redirect URIs and front-channel logout URL registered, exactly matching
- [ ] App roles created and assigned; "Assignment required" set as intended
- [ ] API permissions added and admin consent granted where needed
- [ ] `AUTH_*` and `GRAPH_BASE_URL` repointed; no `localhost` left in config
- [ ] Token validation checks `iss`, `aud`, `exp`/`nbf`, signature and `tid`
- [ ] Interactive retry implemented for `interaction_required` and `consent_required`
- [ ] Client secret rotation scheduled (or, better, certificate or workload identity federation in use)
