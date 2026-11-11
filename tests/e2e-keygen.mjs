// Browser test (1.4.0): create a key in setup, download the files, finish setup, then
// Admin → Settings → Back up your key. Uses headless Microsoft Edge (Windows path below).
// Run against a FRESH install (local php -S with 'dev' => true):
//   node tests/e2e-keygen.mjs <url> <setup_code> src/assets/openpgp.min.mjs <empty out dir with a dl/ folder> <the install's data dir>
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [base, code, opgp, out, dataDir] = process.argv.slice(2);
const openpgp = await import(pathToFileURL(opgp).href);
const PASS = 'correct horse battery staple';
let fails = 0;
const ok = (n, c, x = '') => { if (!c) { fails++; console.log('FAIL', n, x); } else console.log('  ok', n); };

const edge = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const proc = spawn(edge, ['--headless=new', '--disable-gpu', '--remote-debugging-port=19338', '--user-data-dir=' + process.env.TEMP + '/sealid-kg140', 'about:blank'], { stdio: 'ignore' });
setTimeout(() => { console.log('TIMEOUT'); proc.kill(); process.exit(2); }, 150000);
const wait = ms => new Promise(r => setTimeout(r, ms));
let ws;
for (let i = 0; i < 40 && !ws; i++) { try { const t = await (await fetch('http://127.0.0.1:19338/json')).json(); const p = t.find(x => x.type === 'page'); if (p) ws = new WebSocket(p.webSocketDebuggerUrl); } catch {} await wait(250); }
if (ws.readyState !== 1) await new Promise(r => ws.addEventListener('open', r));
let id = 0; const pend = new Map(); const errs = []; const posts = [];
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') errs.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  if (m.method === 'Network.requestWillBeSent') posts.push({ url: m.params.request.url, body: m.params.request.postData || '' });
});
const send = (method, params = {}) => new Promise(r => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async e => { const r = await send('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true }); return r.result?.result?.value; };
const shot = async name => { const s = await send('Page.captureScreenshot', { format: 'png' }); writeFileSync(out + '/' + name + '.png', Buffer.from(s.result.data, 'base64')); };
const until = async (expr, ms = 15000) => { for (let t = 0; t < ms; t += 200) { if (await ev(expr)) return true; await wait(200); } return false; };
const clickText = (sel, text) => ev(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(sel)})].find(x => x.textContent.trim() === ${JSON.stringify(text)}); if (!b) return false; b.click(); return true; })()`);
const setVal = (sel, v) => ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input')); return true; })()`);

await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: out.replace(/\//g, '\\') + '\\dl' });
await send('Emulation.setDeviceMetricsOverride', { width: 900, height: 1100, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/setup.php' });
await until(`!!document.querySelector('#app input[type=password]')`);
await setVal('#app input[type=password]', code);
await clickText('#app button', 'Continue');
ok('identity step', await until(`!!document.querySelector('#app input[type=url]')`));
await setVal('#app input[type=url]', 'https://id.example.test');
await setVal('#app input[type=text]', 'Alex Rivera');
await clickText('#app button', 'Continue');
ok('key step has "Create a new key"', await until(`[...document.querySelectorAll('.seg button')].some(b => b.textContent === 'Create a new key')`));
await clickText('.seg button', 'Create a new key');
await until(`!!document.querySelector('#app input[type=email]')`);
await shot('kg-1-form');
// mismatched / short passphrases are refused
await ev(`(() => { const p = document.querySelectorAll('#app input[type=password]'); p[0].value = 'short'; p[1].value = 'short'; return true; })()`);
await clickText('#app button', 'Create my key');
ok('short passphrase refused', await until(`/at least 10/.test(document.querySelector('.notice.bad:not(.hidden)')?.textContent || '')`, 3000));
await ev(`(() => { const p = document.querySelectorAll('#app input[type=password]'); p[0].value = ${JSON.stringify(PASS)}; p[1].value = ${JSON.stringify(PASS)}; document.querySelector('#app input[type=email]').value = 'alex@example.test'; return true; })()`);
await clickText('#app button', 'Create my key');
ok('save step', await until(`[...document.querySelectorAll('h1')].some(h => h.textContent === 'Save your new key')`));
ok('continue blocked before the private key is downloaded', await ev(`[...document.querySelectorAll('#app button')].find(b => b.textContent === 'Continue').disabled`));
await ev(`document.querySelector('label.check input').click()`);
ok('still blocked with only the box ticked', await ev(`[...document.querySelectorAll('#app button')].find(b => b.textContent === 'Continue').disabled`));
await clickText('#app button', 'Download private key');
await clickText('#app button', 'Download public key');
await clickText('#app button', 'Download revocation certificate');
ok('continue enabled after download + tick', await until(`![...document.querySelectorAll('#app button')].find(b => b.textContent === 'Continue').disabled`, 3000));
await shot('kg-2-save');
await wait(1500);
await clickText('#app button', 'Continue');
ok('sign step', await until(`[...document.querySelectorAll('h1')].some(h => h.textContent === 'Check and sign')`));
const fpShown = (await ev(`document.querySelector('dd.mono:nth-of-type(3)')?.textContent || [...document.querySelectorAll('dd.mono')][1]?.textContent`) || '').replace(/\s/g, '');
await clickText('#app button', 'Sign and create my Seal ID');
ok('sign dialog uses the new key', await until(`[...document.querySelectorAll('.modal button')].some(b => b.textContent === 'Sign with my loaded key')`));
await clickText('.modal button', 'Sign with my loaded key');
ok('Seal ID created', await until(`[...document.querySelectorAll('h1')].some(h => h.textContent === 'Your Seal ID is live')`));
await shot('kg-3-done');

// --- the downloaded files
const dl = out + '/dl';
const files = readdirSync(dl).filter(f => !f.endsWith('.crdownload'));
console.log('     downloads:', files.join(', '));
const priv = files.find(f => f.endsWith('-private.asc'));
const pub = files.find(f => f.endsWith('-public.asc'));
const rev = files.find(f => f.endsWith('-revocation.asc'));
ok('three files downloaded', priv && pub && rev);
const pk = await openpgp.readPrivateKey({ armoredKey: readFileSync(join(dl, priv), 'utf8') });
ok('private key file is locked', !pk.isDecrypted());
const unlocked = await openpgp.decryptKey({ privateKey: pk, passphrase: PASS }).catch(() => null);
ok('passphrase unlocks it', !!unlocked);
const fp = pk.getFingerprint().toUpperCase();
ok('file name carries the key ID', priv.includes(fp.slice(-16)));
ok('user ID has name + email', pk.getUserIDs()[0] === 'Alex Rivera <alex@example.test>', pk.getUserIDs()[0]);
ok('Ed25519', pk.getAlgorithmInfo().algorithm === 'eddsaLegacy');
const bundle = await (await fetch(base + '/api.php?a=bundle')).json();
ok('server identity uses this key', bundle.fp === fp && fpShown === fp, bundle.fp + ' / ' + fpShown);
const pubK = await openpgp.readKey({ armoredKey: readFileSync(join(dl, pub), 'utf8') });
ok('public key file matches', pubK.getFingerprint().toUpperCase() === fp && !pubK.isPrivate());
ok('revocation certificate', /BEGIN PGP PUBLIC KEY BLOCK/.test(readFileSync(join(dl, rev), 'utf8')));

// --- nothing secret left the browser or reached the server
const secretMarkers = ['PRIVATE KEY', PASS];
ok('no request carried the private key or passphrase', !posts.some(p => secretMarkers.some(s => p.body.includes(s))), posts.filter(p => p.body).map(p => p.url).join(' '));
const walk = d => readdirSync(d).flatMap(f => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const leaked = walk(dataDir).filter(f => { const t = readFileSync(f, 'latin1'); return secretMarkers.some(s => t.includes(s)); });
ok('no private key or passphrase in the server data', leaked.length === 0, leaked.join(' '));

// --- admin: Back up your key
await send('Page.navigate', { url: base + '/admin.php' });
await until(`[...document.querySelectorAll('.tab')].some(b => b.textContent === 'Settings')`);
await clickText('.tab', 'Settings');
ok('backup card', await until(`!!document.getElementById('keybackup')`));
ok('public key link', await ev(`document.querySelector('#keybackup a[download]').getAttribute('download').endsWith('-public.asc')`));
// load the key (as the unlock dialog would), then export it locked with a new passphrase
const res = await ev(`(async () => {
  const m = await import('./assets/sign.js');
  await m.signer.load(${JSON.stringify(readFileSync(join(dl, priv), 'utf8'))}, ${JSON.stringify(PASS)});
  let short = ''; try { await m.signer.exportLocked('short'); } catch (e) { short = e.message; }
  const a = await m.signer.exportLocked('a different passphrase 42');
  const stillOpen = !!(await m.signer.sign('x'));
  return JSON.stringify({ a, short, stillOpen });
})()`);
const r = JSON.parse(res || '{}');
const k2 = r.a ? await openpgp.readPrivateKey({ armoredKey: r.a }) : null;
ok('export refuses a short passphrase', /at least 10/.test(r.short || ''));
ok('exported key is locked', k2 && !k2.isDecrypted());
ok('exported key opens with the new passphrase', k2 && !!(await openpgp.decryptKey({ privateKey: k2, passphrase: 'a different passphrase 42' }).catch(() => null)));
ok('the key in the tab stays usable after export', r.stillOpen === true);
await clickText('.tab', 'Settings');
await until(`!!document.getElementById('keybackup')`);
await ev(`document.getElementById('keybackup').scrollIntoView()`);
await wait(300);
await shot('kg-4-admin');
ok('no script errors', errs.length === 0, errs.join(' | '));
console.log(fails ? fails + ' FAILED' : 'all keygen checks passed');
ws.close(); proc.kill(); process.exit(fails ? 1 : 0);
