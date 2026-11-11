// Live alias test (1.2.0): a throwaway Seal ID proves a domain with a website
// proof, then that domain is looked up as an alias and must lead back to it.
// Also checks the badge lookup (api.php?a=claim).
//
//   node tests/e2e-alias.mjs <Seal ID url> <setup code> <alias domain> "<ssh prefix>" <alias docroot on the host>
//
// The script writes <docroot>/.well-known/seal-id.txt over SSH and deletes the
// .well-known folder again at the end — only use a docroot that has none.
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const openpgp = await import(pathToFileURL(resolve(here, '../src/assets/openpgp.min.mjs')).href);
const [URL_, CODE, ALIAS, SSH, DOCROOT] = process.argv.slice(2);
const sh = (cmd, input) => execSync(SSH + ' "' + cmd + '"', { input: input || '' }).toString();
let fails = 0;
const ok = (n, c, x = '') => { if (!c) { fails++; console.log('FAIL', n, x); } else console.log('  ok', n); };

const c = { cookie: '', csrf: '' };
const page = async p => { const r = await fetch(URL_ + '/' + p, { headers: { Cookie: c.cookie } }); const sc = r.headers.get('set-cookie'); if (sc) c.cookie = sc.split(';')[0]; const h = await r.text(); const m = h.match(/id="sealid-data"[^>]*>(.*?)<\/script>/s); if (m) c.csrf = JSON.parse(m[1]).csrf || c.csrf; };
const post = async (p, b) => { const r = await fetch(URL_ + '/' + p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': c.csrf, Cookie: c.cookie }, body: JSON.stringify(b || {}) }); const sc = r.headers.get('set-cookie'); if (sc) c.cookie = sc.split(';')[0]; return r.json().catch(() => ({ ok: false, error: 'not JSON' })); };
const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name: 'Alias test' }], format: 'armored' });
const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
const sign = async p => openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(p) }), signingKeys: priv, detached: true });

try {
  await page('setup.php');
  ok('setup code', (await post('setup.php?a=code', { code: CODE })).ok);
  let r = await post('setup.php?a=prepare', { url: URL_, name: 'Alias Test', bio: '', key: publicKey });
  r = await post('setup.php?a=finish', { sig: await sign(r.payload) });
  ok('identity created', r.ok, r.error);
  r = await post('admin.php?a=prepare', { type: 'proof', service: 'web', handle: ALIAS });
  r = await post('admin.php?a=append', { payload: r.payload, sig: await sign(r.payload) });
  ok('web proof signed', r.ok, r.error);
  const seq = r.seq;
  sh(`mkdir -p ${DOCROOT}/.well-known && cat > ${DOCROOT}/.well-known/seal-id.txt`, r.proof.text + '\n');
  let p;
  for (let i = 0; i < 30; i++) {
    await new Promise(res => setTimeout(res, 3000));
    r = await post('admin.php?a=recheck', { seq });
    p = r.proofs.find(x => x.seq === seq);
    if (p.status === 'verified') break;
  }
  ok('web proof verified', p.status === 'verified', p.status + ' ' + p.detail);
  r = await post('admin.php?a=state', {});
  ok('domain listed as an alias of this identity', r.proofs.find(x => x.seq === seq).alias === true);
  const cl = await (await fetch(URL_ + `/api.php?a=claim&domain=${ALIAS}&t=${Date.now()}`)).json();
  ok('badge lookup says verified', cl.verified === true && cl.url === URL_ && cl.name === 'Alias Test', JSON.stringify(cl));
  const prof = await (await fetch(URL_ + '/?t=' + Date.now())).text();
  ok('profile shows "Also: ' + ALIAS + '"', prof.includes('Also:') && prof.includes(ALIAS));
  // Look the alias up from a separate checker (the same identity's own admin can't vouch for itself, so use peer_lookup via PHP CLI)
  const base = DOCROOT.replace(/[^/]+$/, '') + 'sid-check';
  sh(`cat > ${base}/lookup.php`, "<?php require __DIR__ . '/site/lib/bootstrap.php'; $r = peer_lookup($argv[1], true); echo json_encode(['ok' => $r['ok'], 'url' => $r['url'] ?? null, 'alias' => $r['alias'] ?? null, 'error' => $r['error'] ?? null]);\n");
  const out = sh(`php85 ${base}/lookup.php ${ALIAS}`);
  const lk = JSON.parse(out);
  ok(`alias ${ALIAS} resolves to ${URL_}`, lk.ok && lk.url === URL_ && lk.alias === ALIAS, out);
  if (!lk.ok) {
    sh(`cat > ${base}/why.php`, "<?php require __DIR__ . '/site/lib/bootstrap.php'; $t = peer_alias_targets($argv[2]); $r = peer_verify($argv[1], true); echo json_encode(['targets' => $t, 'proofs' => array_map(fn($p) => [$p['service'], $p['handle'], $p['token'], $p['status'], $p['detail']], $r['proofs'] ?? []), 'error' => $r['error'] ?? null]);\n");
    console.log('     checker saw:', sh(`php85 ${base}/why.php ${URL_} ${ALIAS}`));
  }
} finally {
  sh(`rm -rf ${DOCROOT}/.well-known`);
  console.log('  (removed ' + DOCROOT + '/.well-known)');
}
console.log(fails ? `\n${fails} FAILED` : '\nall alias checks passed');
process.exit(fails ? 1 : 0);
