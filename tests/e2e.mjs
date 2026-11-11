// End-to-end test against a running install (local `php -S` with dev config).
// Signs with OpenPGP.js exactly like the browser does.
//   node tests/e2e.mjs http://127.0.0.1:8765 <setup_code>
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const openpgp = await import(pathToFileURL(resolve(here, '../src/assets/openpgp.min.mjs')).href);
const [base, code] = process.argv.slice(2);
const ID_URL = process.env.SID_URL || 'https://id.example.test';

let cookie = '';
let csrf = '';
let fails = 0;
const ok = (name, cond, extra = '') => { if (!cond) { fails++; console.log('FAIL', name, extra); } else console.log('  ok', name); };

async function req(path, opts = {}) {
  const r = await fetch(base + '/' + path, { ...opts, headers: { ...(opts.headers || {}), Cookie: cookie }, redirect: 'manual' });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return r;
}
async function page(path) {
  const r = await req(path);
  const html = await r.text();
  const m = html.match(/<script type="application\/json" id="sealid-data"[^>]*>(.*?)<\/script>/s);
  if (m) { const d = JSON.parse(m[1]); if (d.csrf) csrf = d.csrf; }
  return { status: r.status, html };
}
async function post(path, body) {
  const r = await req(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf }, body: JSON.stringify(body) });
  const t = await r.text();
  try { return { status: r.status, ...JSON.parse(t) }; } catch { return { status: r.status, ok: false, error: 'not JSON: ' + t.slice(0, 300) }; }
}

const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name: 'E2E' }], format: 'armored' });
const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
const sign = async p => openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(p) }), signingKeys: priv, detached: true });

let p = await page('index.php');
ok('index before setup', p.status === 200 && p.html.includes('Set up this Seal ID'));
p = await page('setup.php');
ok('setup page', p.status === 200 && csrf.length > 10);
ok('wrong code refused', (await post('setup.php?a=code', { code: 'nope' })).status === 403);
ok('setup code accepted', (await post('setup.php?a=code', { code })).ok);
let r = await post('setup.php?a=prepare', { url: ID_URL, name: 'E2E Tester', bio: 'Hello', key: publicKey });
ok('setup prepare', r.ok && r.payload.includes('"type":"eldest"'), r.error);
ok('private key refused in setup', !(await post('setup.php?a=prepare', { url: ID_URL, name: 'x', key: privateKey })).ok);
r = await post('setup.php?a=finish', { sig: await sign(r.payload), password: '' });
ok('setup finish', r.ok && r.fp === priv.getFingerprint().toUpperCase(), r.error);

// Bundle + public pages
let b = await (await req('.well-known/seal-id.json')).json().catch(() => null);
ok('static bundle', b && b.seal_id === 1 && b.chain.length === 1);
b = await (await req('api.php?a=bundle')).json();
ok('api bundle', b.url === ID_URL);
p = await page('index.php');
ok('profile page', p.status === 200 && p.html.includes('E2E Tester'));
const key = await (await req('api.php?a=key')).text();
ok('public key download', key.includes('PUBLIC KEY BLOCK'));

// Fresh session: sign in with the key
cookie = '';
p = await page('admin.php');
ok('admin shell not signed in', p.status === 200 && p.html.includes('"admin":false'));
r = await post('admin.php?a=state', {});
ok('state needs login', r.status === 401);
r = await post('admin.php?a=challenge', {});
ok('challenge', r.ok);
const bad = await post('admin.php?a=login', { sig: await sign(r.payload + 'x') });
ok('bad challenge signature refused', !bad.ok);
r = await post('admin.php?a=challenge', {});
r = await post('admin.php?a=login', { sig: await sign(r.payload) });
ok('login with key', r.ok, r.error);
if (r.csrf) csrf = r.csrf;
r = await post('admin.php?a=state', {});
ok('state', r.ok && r.identity.name === 'E2E Tester' && r.services.length === 10, r.error);

// Add a proof (x needs a locator)
r = await post('admin.php?a=prepare', { type: 'proof', service: 'x', handle: '@SomeOne' });
ok('prepare proof', r.ok && r.payload.includes('"handle":"SomeOne"'), r.error);
ok('unprepared payload refused', !(await post('admin.php?a=append', { payload: r.payload.replace('SomeOne', 'Other'), sig: 'x' })).ok);
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('append proof', r.ok && r.proof && r.proof.text.startsWith('Verifying my Seal ID ' + ID_URL + ' sid1:'), r.error);
const seq = r.seq;
ok('wrong locator refused', !(await post('admin.php?a=locator', { seq, url: 'https://x.com/other/status/123' })).ok);
r = await post('admin.php?a=locator', { seq, url: 'https://twitter.com/someone/status/1234567890' });
ok('locator saved + checked', r.ok && r.proofs[0].locator === 'https://x.com/SomeOne/status/1234567890', r.error);
console.log('     x check result:', r.proofs[0].status, '-', r.proofs[0].detail);

// Profile + revoke
r = await post('admin.php?a=prepare', { type: 'profile', name: 'E2E Renamed', bio: '' });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('profile update', r.ok && r.identity.name === 'E2E Renamed', r.error);
r = await post('admin.php?a=prepare', { type: 'revoke', seqs: [seq] });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('revoke', r.ok && r.proofs.length === 0, r.error);
r = await post('admin.php?a=prepare', { type: 'mirrors', urls: ['https://mirror.example.test/seal-id.json'] });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('mirrors', r.ok && r.mirrors.length === 1 && r.dns.value.includes('mirror='), r.error);
r = await post('admin.php?a=password', { password: 'correct horse battery' });
ok('set password', r.ok && r.has_password);
r = await post('admin.php?a=update_key', { key: publicKey });
ok('update key (same fp)', r.ok, r.error);

// Public API
r = await (await req('api.php?a=status')).json();
ok('status api', r.ok && Array.isArray(r.proofs));
r = await post('api.php?a=inbox', { from: 'https://localhost' });
ok('inbox rejects unreachable voucher', r.ok === false);

// Password login
cookie = '';
await page('admin.php');
ok('wrong password refused', !(await post('admin.php?a=login', { password: 'wrong' })).ok);
r = await post('admin.php?a=login', { password: 'correct horse battery' });
ok('password login', r.ok, r.error);

b = await (await req('.well-known/seal-id.json')).json();
ok('final bundle has 5 links', b.chain.length === 5, String(b.chain.length));

// Leave a few proofs in place for looking at the UI (DEMO=1)
if (process.env.DEMO) {
  for (const [service, handle] of [['dns', 'example.com'], ['github', 'octocat'], ['facebook', 'example.person']]) {
    r = await post('admin.php?a=prepare', { type: 'proof', service, handle });
    r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
    ok('demo proof ' + service, r.ok, r.error);
  }
  console.log('COOKIE ' + cookie);
}
console.log(fails ? `\n${fails} FAILED` : '\nall e2e checks passed');
process.exit(fails ? 1 : 0);
