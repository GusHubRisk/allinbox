import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deviceCodeLogin, refreshTokens, tenantFor, MsTokenCache, MS_SCOPE } from '../src/oauth.ts';
import { isMicrosoftHost, presetFor, presetForMx } from '../src/providers.ts';

type Call = { url: string; body: URLSearchParams };

/** A fake fetch that answers from a queue and records every request. */
function fakeFetch(replies: Record<string, unknown>[]) {
  const calls: Call[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), body: new URLSearchParams(String(init?.body)) });
    const next = replies.shift();
    if (!next) throw new Error('unexpected request');
    return { json: async () => next } as Response;
  }) as typeof fetch;
  return { f, calls };
}

test('tenantFor: personal Microsoft domains go to consumers, the rest to organizations', () => {
  assert.equal(tenantFor('gus@hotmail.com'), 'consumers');
  assert.equal(tenantFor('x@outlook.com.ar'), 'consumers');
  assert.equal(tenantFor('x@live.com'), 'consumers');
  assert.equal(tenantFor('x@university.edu.ar'), 'organizations');
});

test('Outlook, Hotmail and Microsoft 365 presets are routed to OAuth', () => {
  assert.ok(isMicrosoftHost(presetFor('gus@hotmail.com')!.host));
  assert.ok(isMicrosoftHost(presetForMx(['x.mail.protection.outlook.com.'])!.host));
  assert.ok(!isMicrosoftHost(presetFor('a@gmail.com')!.host));
});

test('deviceCodeLogin shows the code, waits through pending and slow_down, returns tokens', async () => {
  const { f, calls } = fakeFetch([
    { device_code: 'DC', user_code: 'ABCD-1234', verification_uri: 'https://microsoft.com/devicelogin', interval: 1, expires_in: 900 },
    { error: 'authorization_pending' },
    { error: 'slow_down' },
    { access_token: 'AT', refresh_token: 'RT', expires_in: 3600 },
  ]);
  const shown: string[] = [];
  const slept: number[] = [];
  const tokens = await deviceCodeLogin('cid', 'consumers', (p) => shown.push(p.userCode), f, async (ms) => {
    slept.push(ms);
  }, () => 1000);
  assert.deepEqual(shown, ['ABCD-1234']);
  assert.deepEqual(slept, [1000, 1000, 6000]); // slow_down adds 5 s
  assert.deepEqual(tokens, { accessToken: 'AT', refreshToken: 'RT', expiresAt: 1000 + 3600_000 });
  assert.match(calls[0].url, /\/consumers\/oauth2\/v2\.0\/devicecode$/);
  assert.equal(calls[0].body.get('scope'), MS_SCOPE);
  assert.equal(calls[1].body.get('device_code'), 'DC');
});

test('deviceCodeLogin surfaces Microsoft errors instead of looping', async () => {
  const { f } = fakeFetch([
    { device_code: 'DC', user_code: 'X', verification_uri: 'u', interval: 1 },
    { error: 'authorization_declined', error_description: 'The user declined' },
  ]);
  await assert.rejects(deviceCodeLogin('cid', 'consumers', () => {}, f, async () => {}), /declined/);
});

test('refreshTokens keeps the old refresh token when Microsoft does not rotate it', async () => {
  const { f, calls } = fakeFetch([{ access_token: 'AT2', expires_in: 60 }]);
  const t = await refreshTokens('cid', 'consumers', 'OLD', f, () => 0);
  assert.equal(t.refreshToken, 'OLD');
  assert.equal(calls[0].body.get('grant_type'), 'refresh_token');
});

test('MsTokenCache refreshes once, reuses the token, and stores a rotated refresh token', async () => {
  const stored: Record<string, string> = { a: 'RT1' };
  let clock = 0;
  const { f, calls } = fakeFetch([
    { access_token: 'AT1', refresh_token: 'RT2', expires_in: 3600 },
    { access_token: 'AT2', refresh_token: 'RT2', expires_in: 3600 },
  ]);
  const cache = new MsTokenCache((id) => stored[id], (id, rt) => (stored[id] = rt), f, () => clock);
  assert.equal(await cache.accessToken('a', 'gus@hotmail.com', 'cid'), 'AT1');
  assert.equal(await cache.accessToken('a', 'gus@hotmail.com', 'cid'), 'AT1'); // cached
  assert.equal(calls.length, 1);
  assert.equal(stored.a, 'RT2');
  clock = 3600_000; // inside the 5-minute margin: refresh with the rotated token
  assert.equal(await cache.accessToken('a', 'gus@hotmail.com', 'cid'), 'AT2');
  assert.equal(calls[1].body.get('refresh_token'), 'RT2');
});
