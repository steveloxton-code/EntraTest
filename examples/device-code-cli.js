'use strict';

/**
 * Device code flow, the way a CLI or a device without a browser signs a user
 * in. Works unchanged against real Entra ID - only AUTH_AUTHORITY and
 * AUTH_CLIENT_ID change.
 *
 *   node examples/device-code-cli.js
 */

const { decodeJwt } = require('../shared/jose');

const authority = (process.env.AUTH_AUTHORITY
  || 'http://localhost:8080/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb').replace(/\/$/, '');
const clientId = process.env.AUTH_CLIENT_ID || 'c4d5e6f7-1234-4321-9876-0a1b2c3d4e5f';
const scope = process.env.AUTH_SCOPES || 'openid profile offline_access User.Read';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  const discovery = await (await fetch(`${authority}/v2.0/.well-known/openid-configuration`)).json();

  const startRes = await fetch(discovery.device_authorization_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, scope }),
  });
  const device = await startRes.json();
  if (!startRes.ok) {
    console.error(device.error_description || JSON.stringify(device, null, 2));
    process.exit(1);
  }

  console.log(`\n${device.message}\n`);

  const deadline = Date.now() + device.expires_in * 1000;
  while (Date.now() < deadline) {
    await sleep(device.interval * 1000);

    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: device.device_code,
      }),
    });
    const body = await res.json();

    if (res.ok) {
      const claims = decodeJwt(body.id_token).payload;
      console.log(`Signed in as ${claims.name} <${claims.preferred_username}>`);
      console.log(`  object id  ${claims.oid}`);
      console.log(`  tenant id  ${claims.tid}`);
      console.log(`  scopes     ${body.scope}`);
      console.log(`  expires in ${body.expires_in}s`);
      return;
    }
    // authorization_pending is the expected answer until the user finishes.
    if (body.error !== 'authorization_pending') {
      console.error(`\n${body.error_description || body.error}`);
      process.exit(1);
    }
    process.stdout.write('.');
  }

  console.error('\nTimed out waiting for the user to sign in.');
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
