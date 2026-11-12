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
ok('state', r.ok && r.identity.name === 'E2E Tester' && r.services.length === 11 && Array.isArray(r.addresses), r.error);

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

// Owner's order (1.3.0): a second proof is newest, so it comes first until the owner moves it
r = await post('admin.php?a=prepare', { type: 'proof', service: 'sealchat', handle: 'sealchat:' + 'a'.repeat(55) + 'd:' + priv.getFingerprint().toUpperCase() });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
const seq2 = r.seq;
ok('second proof', r.ok && r.proofs[0].seq === seq2, r.error);
r = await post('admin.php?a=order', { proofs: [seq, seq2, 999], aliases: ['not-mine.example'] });
ok('order saved (unknown entries dropped)', r.ok && r.proofs.map(p => p.seq).join() === [seq, seq2].join(), r.error);
p = await page('index.php');
ok('profile page follows the order', p.html.indexOf('data-seq="' + seq + '"') < p.html.indexOf('data-seq="' + seq2 + '"'));
ok('profile page shows icons', p.html.includes('icons.svg?v=') && p.html.includes('#x"') && p.html.includes('assets/sealchat.png'));
ok('Seal Chat ID shown short with the full ID on hover', /class="tip"[^>]*data-tip="sealchat:a{55}d:/.test(p.html));
b = await (await req('api.php?a=bundle')).json();
ok('bundle carries the order hint', b.order && b.order.proofs.join() === [seq, seq2].join() && b.order.aliases.length === 0);
ok('favicon only for own domains', (await req('api.php?a=favicon&d=example.com')).status === 404);
r = await post('admin.php?a=prepare', { type: 'revoke', seqs: [seq2] });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('second proof revoked', r.ok && r.proofs.length === 1, r.error);

// Profile picture (1.1.0)
const { deflateSync } = await import('node:zlib');
const { createHash } = await import('node:crypto');
function png(w, h) {   // tiny RGB PNG encoder: a green/blue gradient
  const crcT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = b => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (t, d) => { const l = Buffer.alloc(4); l.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t), d]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([l, td, c]); };
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const o = y * (w * 3 + 1) + 1 + x * 3; raw[o] = 60; raw[o + 1] = 120 + (x * 100 / w) | 0; raw[o + 2] = 145 + (y * 100 / h) | 0; }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
ok('garbage picture refused', !(await post('admin.php?a=avatar_upload', { image: 'data:image/png;base64,' + Buffer.from('not an image').toString('base64') })).ok);
r = await post('admin.php?a=avatar_upload', { image: 'data:image/png;base64,' + png(600, 400).toString('base64') });
ok('picture uploaded + cleaned', r.ok && /^[0-9a-f]{64}$/.test(r.sha) && /^data:image\/(webp|png);base64,/.test(r.data), r.error);
const avSha = r.sha;
ok('unknown picture hash refused', !(await post('admin.php?a=prepare', { type: 'profile', name: 'E2E Tester', bio: '', avatar: 'a'.repeat(64) })).ok);
r = await post('admin.php?a=prepare', { type: 'profile', name: 'E2E Tester', bio: 'Hello', avatar: avSha });
ok('profile with picture prepared', r.ok && r.payload.includes('"avatar":"' + avSha + '"'), r.error);
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('profile with picture signed', r.ok && r.identity.avatar === avSha && r.identity.avatar_url, r.error);
let img = await req('api.php?a=avatar&h=' + avSha.slice(0, 16));
let imgBytes = Buffer.from(await img.arrayBuffer());
ok('picture served, hash matches signed hash', img.status === 200 && /^image\/(webp|png)$/.test(img.headers.get('content-type')) && createHash('sha256').update(imgBytes).digest('hex') === avSha);
ok('picture is a square crop', (() => { const t = img.headers.get('content-type'); if (t === 'image/png') return imgBytes.readUInt32BE(16) === imgBytes.readUInt32BE(20); return imgBytes.slice(0, 4).toString() === 'RIFF'; })());
b = await (await req('api.php?a=bundle')).json();
ok('bundle names the picture', b.avatar && b.avatar.sha256 === avSha);
p = await page('index.php');
ok('profile page shows the picture', p.html.includes('avatar-img') && p.html.includes('api.php?a=avatar&amp;h=' + avSha.slice(0, 16)));
r = await post('admin.php?a=prepare', { type: 'profile', name: 'E2E Tester', bio: 'Hello', avatar: null });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
ok('picture removed', r.ok && !r.identity.avatar && (await req('api.php?a=avatar')).status === 404, r.error);
r = await post('admin.php?a=update_status', {});
ok('update status answers', r.ok && r.update && r.update.current, r.error);
console.log('     update check:', r.update.update ? 'update ' + r.update.update.version : 'no update', r.update.error ? '(' + r.update.error + ')' : '');

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

// ---- 1.2.0: Seal Chat proofs ----
const myFp = priv.getFingerprint().toUpperCase();
const onion = 'a'.repeat(55) + 'd';
r = await post('admin.php?a=prepare', { type: 'proof', service: 'sealchat', handle: `sealchat:${onion}:${myFp.toLowerCase()}` });
ok('sealchat handle normalised', r.ok && r.payload.includes(`"handle":"sealchat:${onion}:${myFp}"`), r.error);
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
let scp = r.proofs.find(p => p.service === 'sealchat');
ok('sealchat proof with the SAME key verifies by itself', scp && scp.status === 'verified', scp && scp.detail);
// a separate Seal Chat key
const sc = await openpgp.generateKey({ userIDs: [{ name: 'Seal Chat' }], format: 'armored' });
const scPriv = await openpgp.readPrivateKey({ armoredKey: sc.privateKey });
const scFp = scPriv.getFingerprint().toUpperCase();
const scHandle = `sealchat:${'b'.repeat(55)}d:${scFp}`;
r = await post('admin.php?a=prepare', { type: 'proof', service: 'sealchat', handle: scHandle });
r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
scp = r.proofs.find(p => p.handle === scHandle);
ok('sealchat proof with another key waits for its signature', scp && scp.status === 'pending', scp && scp.status);
const scText = 'Verifying my Seal ID ' + ID_URL + ' ' + scp.token;
const scSign = async (k, t) => openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(t) }), signingKeys: k, detached: true });
r = await post('api.php?a=attest', { sealchat: scHandle, key: sc.publicKey, sig: await scSign(scPriv, scText + ' x') });
ok('attestation over the wrong text refused', !r.ok && r.status === 422, r.error);
r = await post('api.php?a=attest', { sealchat: scHandle, key: publicKey, sig: await scSign(priv, scText) });
ok('attestation by a key other than the Seal Chat key refused', !r.ok, r.error);
r = await post('api.php?a=attest', { sealchat: `sealchat:${'c'.repeat(55)}d:${scFp}`, key: sc.publicKey, sig: await scSign(scPriv, scText) });
ok('attestation for an unclaimed Seal Chat ID refused', !r.ok && r.status === 404, r.error);
r = await post('api.php?a=attest', { sealchat: scHandle, key: sc.publicKey, sig: await scSign(scPriv, scText) });
ok('Seal Chat attestation accepted', r.ok, r.error);
r = await post('admin.php?a=state', {});
scp = r.proofs.find(p => p.handle === scHandle);
ok('sealchat proof with another key now verified', scp && scp.status === 'verified', scp && scp.detail);
b = await (await req('api.php?a=bundle')).json();
ok('bundle carries the attestation', b.attestations && b.attestations[String(scp.seq)] && b.attestations[String(scp.seq)].key.includes('PUBLIC KEY'));

// ---- 1.2.0: badge lookup ----
let cl = await (await req('api.php?a=claim&service=sealchat&handle=' + encodeURIComponent(scHandle))).json();
ok('claim: Seal Chat ID verified', cl.ok && cl.verified === true && cl.fp === myFp && cl.url === ID_URL, JSON.stringify(cl));
cl = await (await req('api.php?a=claim&domain=nowhere.example')).json();
ok('claim: unknown domain not verified', cl.ok && cl.verified === false && cl.status === 'none');

// ---- 1.2.0: encrypted key copy on the server (option B) ----
const { serverCopy } = await import(pathToFileURL(resolve(here, '../src/assets/keystore.js')).href);
ok('server copy needs 12+ char passphrase', await serverCopy.make(ID_URL, myFp, privateKey, 'short').then(() => false, () => true));
const blob = await serverCopy.make(ID_URL, myFp, privateKey, 'a long test passphrase');
ok('server copy refuses junk', !(await post('admin.php?a=keystore_put', { blob: { v: 1, fp: myFp } })).ok);
ok('server copy refuses weak KDF', !(await post('admin.php?a=keystore_put', { blob: { ...blob, iter: 1000 } })).ok);
r = await post('admin.php?a=keystore_put', { blob });
ok('server copy stored', r.ok && r.keystore, r.error);
r = await post('admin.php?a=keystore_get', {});
ok('server copy unlocks with the passphrase', (await serverCopy.open(ID_URL, r.blob, 'a long test passphrase')) === privateKey);
ok('server copy refuses a wrong passphrase', await serverCopy.open(ID_URL, r.blob, 'wrong passphrase!!').then(() => false, () => true));
ok('server copy bound to this Seal ID', await serverCopy.open('https://other.example', r.blob, 'a long test passphrase').then(() => false, () => true));
const raw = await (await req('.well-known/seal-id.json')).text();
ok('server copy NOT in the public bundle', !raw.includes(blob.ct.slice(0, 40)));
r = await post('admin.php?a=keystore_delete', {});
ok('server copy deleted', r.ok && !r.keystore);

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
ok('final bundle has 11 links', b.chain.length === 11, String(b.chain.length));

// 1.5.0: public checker (offline-safe: only inputs that need no outside lookups)
r = await post('admin.php?a=state', {});
ok('checker on by default', r.public_check === true, String(r.public_check));
p = await page('index.php');
ok('profile has the check form', p.html.includes('action="check.php"') && p.html.includes('Check a Seal ID'));
p = await page('check.php');
ok('check page loads', p.status === 200 && p.html.includes('name="q"'));
p = await page('check.php?q=' + encodeURIComponent('not a domain'));
ok('check page: bad input explained', p.html.includes('Not a valid address'));
const lk = await (await req('api.php?a=lookup&q=' + encodeURIComponent('<script>'))).json();
ok('lookup API: bad input', lk.verdict === 'bad_address' && !('fp' in lk), JSON.stringify(lk).slice(0, 200));
p = await page('check.php?q=' + encodeURIComponent('"><script>alert(1)</script>'));
ok('check page escapes the query', !p.html.includes('<script>alert(1)') && p.html.includes('&lt;script&gt;'));
r = await post('admin.php?a=settings', { public_check: false });
ok('checker turned off', r.ok && r.public_check === false, r.error);
const off = await req('api.php?a=lookup&q=example.com');
ok('lookup API refuses when off', off.status === 403, String(off.status));
p = await page('check.php?q=example.com');
ok('check page says it is off', p.html.includes('turned the public checker off') && !p.html.includes('name="q"'));
p = await page('index.php');
ok('profile hides the form when off', !p.html.includes('action="check.php"'));
r = await post('admin.php?a=settings', { public_check: true });
ok('checker back on', r.ok && r.public_check === true, r.error);

// Leave a few proofs in place for looking at the UI (DEMO=1)
if (process.env.DEMO) {
  for (const [service, handle] of [['dns', 'example.com'], ['github', 'octocat'], ['facebook', 'example.person']]) {
    r = await post('admin.php?a=prepare', { type: 'proof', service, handle });
    r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
    ok('demo proof ' + service, r.ok, r.error);
  }
  r = await post('admin.php?a=avatar_upload', { image: 'data:image/png;base64,' + png(500, 500).toString('base64') });
  r = await post('admin.php?a=prepare', { type: 'profile', name: 'E2E Renamed', bio: 'Demo identity', avatar: r.sha });
  r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
  ok('demo picture', r.ok, r.error);
  const ad = (r.addresses || []).find(a => a.domain === 'example.com');
  ok('addresses: unverified DNS domain listed as not an alias, with the reason', ad && ad.alias === false && /not verified/.test(ad.why), JSON.stringify(ad));
  console.log('COOKIE ' + cookie);
}
console.log(fails ? `\n${fails} FAILED` : '\nall e2e checks passed');
process.exit(fails ? 1 : 0);
