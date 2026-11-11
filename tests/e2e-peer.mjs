// Live two-installation test: A and B on real https addresses.
//   A publishes a real website proof, B checks A, vouches (auto + witnessed),
//   A's inbox receives it, B withdraws it, A notices.
// Usage: node tests/e2e-peer.mjs <A url> <A code> <B url> <B code> "<ssh command prefix to the host of both>"
//   (A at the host's ~/ID and B at ~/ID/peer-test: the script writes A's proof file and
//    renames B's files over SSH, so adjust the paths in sh(...) calls for another layout.)
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const openpgp = await import(pathToFileURL(resolve(here, '../src/assets/openpgp.min.mjs')).href);
const [A_URL, A_CODE, B_URL, B_CODE, SSH] = process.argv.slice(2);
const sh = (cmd, input) => execSync(SSH + ' "' + cmd + '"', { input: input || '' }).toString();
let fails = 0;
const ok = (name, cond, extra = '') => { if (!cond) { fails++; console.log('FAIL', name, extra); } else console.log('  ok', name); };

function client(base) {
  const c = { cookie: '', csrf: '' };
  c.page = async path => {
    const r = await fetch(base + '/' + path, { headers: { Cookie: c.cookie }, redirect: 'manual' });
    const sc = r.headers.get('set-cookie'); if (sc) c.cookie = sc.split(';')[0];
    const html = await r.text();
    const m = html.match(/<script type="application\/json" id="sealid-data"[^>]*>(.*?)<\/script>/s);
    if (m) { const d = JSON.parse(m[1]); if (d.csrf) c.csrf = d.csrf; }
    return { status: r.status, html };
  };
  c.post = async (path, body) => {
    const r = await fetch(base + '/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': c.csrf, Cookie: c.cookie }, body: JSON.stringify(body || {}), redirect: 'manual' });
    const sc = r.headers.get('set-cookie'); if (sc) c.cookie = sc.split(';')[0];
    const t = await r.text();
    try { return { status: r.status, ...JSON.parse(t) }; } catch { return { status: r.status, ok: false, error: 'not JSON: ' + t.slice(0, 200) }; }
  };
  return c;
}

async function newKey() {
  const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name: 'Peer test' }], format: 'armored' });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return { publicKey, sign: async p => openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(p) }), signingKeys: priv, detached: true }) };
}

async function setup(c, url, code, name, key) {
  await c.page('setup.php');
  ok(name + ' code', (await c.post('setup.php?a=code', { code })).ok);
  let r = await c.post('setup.php?a=prepare', { url, name, bio: 'Live test identity', key: key.publicKey });
  ok(name + ' prepare', r.ok, r.error);
  r = await c.post('setup.php?a=finish', { sig: await key.sign(r.payload) });
  ok(name + ' created', r.ok, r.error);
  if (r.bundle_error) console.log('     bundle error:', r.bundle_error);
}

async function signed(c, key, body) {
  const p = await c.post('admin.php?a=prepare', body);
  if (!p.ok) return p;
  return c.post('admin.php?a=append', { payload: p.payload, sig: await key.sign(p.payload) });
}

const A = client(A_URL), B = client(B_URL);
const ka = await newKey(), kb = await newKey();
await setup(A, A_URL, A_CODE, 'A', ka);
await setup(B, B_URL, B_CODE, 'B', kb);

// A: website proof for its own host, published for real
const host = new URL(A_URL).host;
let r = await signed(A, ka, { type: 'proof', service: 'web', handle: host });
ok('A web proof signed', r.ok, r.error);
const webSeq = r.seq;
sh('mkdir -p ID/.well-known && cat > ID/.well-known/seal-id.txt', r.proof.text + '\n');
let web;
for (let i = 0; i < 24; i++) {   // shared hosting can take a few seconds to serve a new file
  await new Promise(res => setTimeout(res, 2500));
  r = await A.post('admin.php?a=recheck', { seq: webSeq });
  web = r.proofs.find(p => p.seq === webSeq);
  if (web.status === 'verified') break;
}
ok('A web proof VERIFIED live', web.status === 'verified', web.status + ' ' + web.detail);
// A: a Facebook proof (witnessed) and an X proof pointing at someone else's post
r = await signed(A, ka, { type: 'proof', service: 'facebook', handle: 'seal.id.test' });
const fbSeq = r.seq;
r = await A.post('admin.php?a=locator', { seq: fbSeq, url: 'https://www.facebook.com/seal.id.test/posts/123456' });
ok('A facebook locator', r.ok, r.error);
r = await signed(A, ka, { type: 'proof', service: 'x', handle: 'jack' });
const xSeq = r.seq;
r = await A.post('admin.php?a=locator', { seq: xSeq, url: 'https://x.com/jack/status/20' });
const xp = r.proofs.find(p => p.seq === xSeq);
ok('A x proof checked live (token absent → failed)', xp.status === 'failed', xp.status + ' ' + xp.detail);

// B checks A
r = await B.post('admin.php?a=peer', { url: A_URL });
const rep = r.report;
ok('B verified A', rep && rep.ok, rep && rep.error);
ok('B sees A web proof verified', rep.proofs.find(p => p.seq === webSeq)?.status === 'verified');
ok('B sees A first time', rep.pin === 'new');
r = await B.post('admin.php?a=peer', { url: A_URL });
ok('B second look matches pin', r.report.pin === 'match');

// B vouches: web automatically, facebook witnessed, x refused as auto
const bad = await B.post('admin.php?a=prepare', { type: 'vouch', target: A_URL, proofs: { [xSeq]: 'auto' } });
ok('auto-vouch for a failed proof refused', !bad.ok);
r = await signed(B, kb, { type: 'vouch', target: A_URL, proofs: { [webSeq]: 'auto', [fbSeq]: 'witnessed' } });
ok('B vouch signed', r.ok, r.error);
ok('B vouch delivered to A inbox', r.notify && r.notify.ok, r.notify && r.notify.detail);
const vouchSeq = r.seq;

// A sees it
r = await A.post('admin.php?a=state', {});
ok('A received vouch from B', r.received.some(v => v.url === B_URL));
const fb = r.proofs.find(p => p.seq === fbSeq);
ok('A facebook proof now witnessed', fb.status === 'witnessed' && fb.witnesses.includes(B_URL), fb.status);
const prof = await A.page('');
ok('A public profile lists B', prof.html.includes(B_URL) && prof.html.includes('Witnessed'));
const bundle = await (await fetch(A_URL + '/.well-known/seal-id.json?t=' + Date.now())).json();
ok('A bundle carries vouched_by hint', bundle.vouched_by.some(v => v.url === B_URL));

// Reachability test: B asks A to fetch B
r = await B.post('admin.php?a=reach', { helper: A_URL });
ok('reach test via A', r.ok && r.result.ok, JSON.stringify(r.result || r.error));

// B withdraws; A re-imports and drops it
r = await signed(B, kb, { type: 'revoke', seqs: [vouchSeq] });
ok('B withdrew vouch', r.ok, r.error);
r = await A.post('admin.php?a=import_vouch', { url: B_URL });
ok('A import after withdrawal reports none', !r.ok);
r = await A.post('admin.php?a=state', {});
ok('A no longer lists B', !r.received.some(v => v.url === B_URL));

// Host blocked → mirror fallback
const M = A_URL + '/mirror-copy/b.json';
r = await signed(B, kb, { type: 'mirrors', urls: [M] });
ok('B signed mirror list', r.ok, r.error);
r = await A.post('admin.php?a=peer', { url: B_URL });
ok('A pinned B with mirror', r.report.ok && r.report.mirrors.includes(M), r.report.error);
sh('mkdir -p ID/mirror-copy && cp ID/peer-test/.well-known/seal-id.json ID/mirror-copy/b.json && mv ID/peer-test/api.php ID/peer-test/api.php.off && mv ID/peer-test/.well-known ID/peer-test/wk.off');
try {
  // Shared hosting: the web servers see the rename a little later than SSH does.
  for (let i = 0; i < 30; i++) {
    const s = (await fetch(B_URL + '/api.php?a=bundle&t=' + Date.now())).status;
    console.log('     B api status while down:', s);
    if (s === 404) break;
    await new Promise(res => setTimeout(res, 2000));
  }
  // …and the server's own view of the files can lag even longer: retry for up to a minute.
  for (let i = 0; i < 20; i++) {
    r = await A.post('admin.php?a=peer', { url: B_URL });
    if (!r.report || r.report.mirror || !r.report.ok) break;
    await new Promise(res => setTimeout(res, 3000));
  }
  ok('A verified B from the MIRROR while B was down', r.report && r.report.ok && r.report.mirror === true, JSON.stringify({ source: r.report && r.report.source, attempts: r.report && r.report.attempts }));
  ok('mirror use is flagged', (r.report.warnings || []).some(w => w.includes('mirror')));
} finally {
  sh('mv ID/peer-test/api.php.off ID/peer-test/api.php; mv ID/peer-test/wk.off ID/peer-test/.well-known; rm -rf ID/mirror-copy');
}

console.log(fails ? `\n${fails} FAILED` : '\nall live peer checks passed');
process.exit(fails ? 1 : 0);
