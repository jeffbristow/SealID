// Generates tests/fixtures/openpgpjs.json: keys + signatures made by OpenPGP.js,
// the same library Seal Post, Seal Chat and the Seal ID admin page use.
// Usage: node tests/make-fixtures.mjs [path/to/openpgp.mjs]
import { writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const lib = process.argv[2] || resolve(here, '../src/assets/openpgp.min.mjs');
const openpgp = await import(pathToFileURL(lib).href);

const payload = '{"v":1,"seq":1,"prev":null,"ts":1762860000,"url":"https://id.example.test","fp":"X","type":"eldest","body":{"name":"Test","bio":""}}';
const enc = new TextEncoder();

async function make(name, opts, config = {}) {
  const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name: 'Test ' + name, email: name + '@example.test' }], format: 'armored', config, ...opts });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  const message = await openpgp.createMessage({ binary: enc.encode(payload) });
  const detached = await openpgp.sign({ message, signingKeys: priv, detached: true, config });
  const textMsg = await openpgp.createCleartextMessage({ text: payload });
  const clear = await openpgp.sign({ message: textMsg, signingKeys: priv, config });
  const wrong = await openpgp.sign({ message: await openpgp.createMessage({ binary: enc.encode(payload + ' ') }), signingKeys: priv, detached: true, config });
  return { name, publicKey, fp: priv.getFingerprint().toUpperCase(), detached, clear, wrong };
}

const out = { payload, keys: [] };
out.keys.push(await make('ecc-legacy', { type: 'ecc', curve: 'curve25519Legacy' }));
out.keys.push(await make('ed25519-v6', { type: 'curve25519' }, { v6Keys: true }));
out.keys.push(await make('rsa-3072', { type: 'rsa', rsaBits: 3072 }));
mkdirSync(resolve(here, 'fixtures'), { recursive: true });
writeFileSync(resolve(here, 'fixtures/openpgpjs.json'), JSON.stringify(out, null, 1));
console.log('wrote', out.keys.map(k => k.name + ' ' + k.fp).join('\n'));
