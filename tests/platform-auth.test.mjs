// The module's own referees. Hermetic: no network, no secrets, no application.
//
// Until 2026-09-16 this module had no tests of its own; every application that
// installs it tests the installed copy against its own use, which proves the
// pairing and not the module. These cover the module alone: what a token and a
// session carry, the rules that must never be hand-rolled (null means every
// page, every tool), the binding of a token to one application, and the 2.1.0
// additions: the name rides as stored, and `onSignIn` is called once per
// arrival and can never stop a sign-in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, sign as signWithKey } from 'node:crypto';
import { platformAuth, verifyHandoff, allows, holds, publicKeyFromRaw, CLIENT_VERSION } from '../platform-auth.mjs';

const SECRET = 'a-secret-that-is-long-enough-for-the-guard-ok';
const soon = () => Math.floor(Date.now() / 1000) + 60;

// A token the way the platform mints it, in both forms.
const mintHmac = (claims, secret = SECRET) => {
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
};
const keys = generateKeyPairSync('ed25519');
const publicRaw = keys.publicKey.export({ format: 'jwk' }).x;
const mintV2 = (claims) => {
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = signWithKey(null, Buffer.from(`v2.${body}`), keys.privateKey).toString('base64url');
  return `v2.${body}.${sig}`;
};

// A response object with just enough surface for `handoff` and `signOut`.
const fakeRes = () => ({
  cookies: {}, cleared: [], headers: {}, status(c) { this.code = c; return this; }, type() { return this; },
  send(b) { this.body = b; }, cookie(n, v) { this.cookies[n] = v; }, clearCookie(n) { this.cleared.push(n); },
  setHeader(k, v) { this.headers[k] = v; }, redirect(to) { this.to = to; },
});
const app = (extra = {}) => platformAuth({
  appId: 'content', secret: SECRET, platformUrl: 'https://hub.test', cookieName: 'c_session', ...extra,
});

test('the version is the one the README and the tag say', () => {
  assert.equal(CLIENT_VERSION, '2.1.0');
});

test('a session carries id, email, name, pages and apps, and reads back the same', () => {
  const auth = app();
  const user = auth.read(auth.issue({ userId: 'u1', email: 'a@x.test', name: 'Ada Lovelace', pages: ['finder'], apps: ['content'] }));
  assert.deepEqual(user, { id: 'u1', email: 'a@x.test', name: 'Ada Lovelace', pages: ['finder'], apps: ['content'] });
});

test('no name is an empty string, in a fresh session and in one from before names', () => {
  const auth = app();
  assert.equal(auth.read(auth.issue({ userId: 'u2', email: 'b@x.test' })).name, '');
  const old = mintHmac({ u: 'u3', e: 'c@x.test', a: 'content', exp: soon(), n: 'x' });
  assert.equal(auth.read(old).name, '');
  assert.equal(auth.read(old).email, 'c@x.test');
});

test('null means every page and every tool; an empty list means none', () => {
  const auth = app();
  const older = auth.read(mintHmac({ u: 'u', e: 'e@x.test', a: 'content', exp: soon(), n: 'n' }));
  assert.equal(older.pages, null);
  assert.equal(older.apps, null);
  assert.equal(allows(null, 'anything'), true);
  assert.equal(holds(undefined, 'anything'), true);
  assert.equal(allows([], 'finder'), false);
  assert.equal(holds([], 'brands'), false);
  assert.equal(allows(['finder'], 'finder'), true);
  assert.equal(holds(['content'], 'brands'), false);
});

test('a session is bound to the application it was minted for', () => {
  const here = app();
  const there = platformAuth({ appId: 'brands', secret: SECRET, platformUrl: 'https://hub.test', cookieName: 'b_session' });
  const value = here.issue({ userId: 'u', email: 'e@x.test' });
  assert.ok(here.read(value));
  assert.equal(there.read(value), null);
});

test('a tampered or expired session reads as nobody', () => {
  const auth = app();
  const value = auth.issue({ userId: 'u', email: 'e@x.test' });
  const [body, sig] = value.split('.');
  assert.equal(auth.read(`${body}.${sig.slice(0, -2)}xx`), null);
  const forged = Buffer.from(JSON.stringify({ u: 'admin', e: 'e@x.test', a: 'content', exp: soon(), n: 'n' })).toString('base64url');
  assert.equal(auth.read(`${forged}.${sig}`), null);
  assert.equal(auth.read(auth.issue({ userId: 'u', email: 'e@x.test', now: Date.now() - 13 * 3600 * 1000 })), null);
  assert.equal(auth.read(''), null);
  assert.equal(auth.read(null), null);
});

test('a secret that is missing or short fails at boot, loudly', () => {
  assert.throws(() => platformAuth({ appId: 'x', secret: 'short', platformUrl: 'https://hub.test', cookieName: 'c' }));
  assert.throws(() => platformAuth({ appId: 'x', platformUrl: 'https://hub.test', cookieName: 'c' }));
});

test('verifyHandoff reads the name as stored and refuses a token for another app', () => {
  const exp = soon();
  const tok = mintHmac({ u: 'u9', e: 'd@x.test', a: 'content', exp, n: 'n', nm: 'Dee Dee', p: ['finder'], t: ['content'] });
  const claims = verifyHandoff(tok, 'content', SECRET);
  assert.deepEqual(claims, { userId: 'u9', email: 'd@x.test', name: 'Dee Dee', appId: 'content', pages: ['finder'], apps: ['content'] });
  assert.equal(verifyHandoff(mintHmac({ u: 'u9', e: 'd@x.test', a: 'content', exp, n: 'n' }), 'content', SECRET).name, '');
  assert.equal(verifyHandoff(tok, 'brands', SECRET), null);
  assert.equal(verifyHandoff(tok, '', SECRET), null);
  assert.equal(verifyHandoff(tok, undefined, SECRET), null);
});

test('a key-signed token verifies against the public key and nothing else', () => {
  const exp = soon();
  const tok = mintV2({ u: 'u1', e: 'a@x.test', a: 'content', exp, n: 'n', nm: 'Ada' });
  assert.equal(verifyHandoff(tok, 'content', { publicKey: publicRaw, secret: SECRET }).name, 'Ada');
  assert.equal(verifyHandoff(tok, 'content', SECRET), null, 'the secret alone cannot open a v2 token');
  assert.equal(verifyHandoff(tok, 'content', { secret: SECRET }), null);
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;
  assert.equal(verifyHandoff(tok, 'content', { publicKey: other, secret: SECRET }), null, 'a different key refuses');
  assert.ok(publicKeyFromRaw(publicRaw));
  assert.throws(() => publicKeyFromRaw('not-a-key'));
});

test('an expired token is refused, even one second late', () => {
  const tok = mintHmac({ u: 'u', e: 'e@x.test', a: 'content', exp: Math.floor(Date.now() / 1000) - 1, n: 'n' });
  assert.equal(verifyHandoff(tok, 'content', SECRET), null);
});

test('handoff: verifies, calls onSignIn once with the person, sets the session, redirects clean', async () => {
  const seen = [];
  const auth = app({ onSignIn: (p) => { seen.push(p); } });
  const tok = mintHmac({ u: 'u9', e: 'd@x.test', a: 'content', exp: soon(), n: 'n', nm: 'Dee Dee', p: ['finder'], t: ['content'] });
  const res = fakeRes();
  await auth.handoff({ query: { token: tok }, headers: {}, secure: true }, res);
  assert.deepEqual(seen, [{ id: 'u9', email: 'd@x.test', name: 'Dee Dee', pages: ['finder'], apps: ['content'] }]);
  assert.equal(res.to, '/');
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(auth.read(res.cookies.c_session).name, 'Dee Dee');
});

test('handoff: a throwing onSignIn is logged and never stops the sign-in', async () => {
  const auth = app({ onSignIn: () => { throw new Error('ledger down'); } });
  const tok = mintHmac({ u: 'u9', e: 'd@x.test', a: 'content', exp: soon(), n: 'n' });
  const res = fakeRes();
  const quiet = console.error;
  const logged = [];
  console.error = (...args) => logged.push(args.join(' '));
  try { await auth.handoff({ query: { token: tok }, headers: {}, secure: true }, res); } finally { console.error = quiet; }
  assert.equal(res.to, '/');
  assert.ok(res.cookies.c_session);
  assert.ok(logged.some((l) => l.includes('ledger down')));
});

test('handoff: a bad token is a refusal with a door back through the platform, and no callback', async () => {
  const seen = [];
  const auth = app({ onSignIn: (p) => { seen.push(p); } });
  const res = fakeRes();
  await auth.handoff({ query: { token: 'nonsense' }, headers: {}, secure: true }, res);
  assert.equal(res.code, 401);
  assert.match(res.body, /go\/content/);
  assert.equal(seen.length, 0);
  assert.deepEqual(res.cookies, {});
});

test('required: a valid session passes, no session is sent to the platform with next=/go/<app>', () => {
  const auth = app();
  const value = auth.issue({ userId: 'u', email: 'e@x.test' });
  let passed = false;
  const req = { headers: { cookie: `c_session=${value}` }, accepts: () => true };
  auth.attach(req, null, () => {});
  auth.required(req, fakeRes(), () => { passed = true; });
  assert.equal(passed, true);
  const res = fakeRes();
  const stranger = { headers: {}, accepts: () => true };
  auth.attach(stranger, null, () => {});
  auth.required(stranger, res, () => { assert.fail('must not pass'); });
  assert.equal(res.to, 'https://hub.test/login?next=%2Fgo%2Fcontent');
});
