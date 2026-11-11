// Builds tests/chain-fixture.json: a complete Seal ID chain signed with
// OpenPGP.js — eldest, proof, profile, mirrors, revoke, rotate (to a v6 key),
// vouch — to test the PHP chain verifier.  node tests/make-chain.mjs
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const openpgp = await import(pathToFileURL(resolve(here, '../src/assets/openpgp.min.mjs')).href);
const url = 'https://id.example.test';

const gen = async (opts, config = {}) => {
  const { privateKey, publicKey } = await openpgp.generateKey({ userIDs: [{ name: 'Chain Test' }], format: 'armored', config, ...opts });
  return { priv: await openpgp.readPrivateKey({ armoredKey: privateKey }), pub: publicKey, config };
};
const k1 = await gen({ type: 'ecc', curve: 'curve25519Legacy' });
const k2 = await gen({ type: 'curve25519' }, { v6Keys: true });
const fp = k => k.priv.getFingerprint().toUpperCase();
const sign = async (k, payload) => openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(payload) }), signingKeys: k.priv, detached: true, config: k.config });

const links = [];
let prev = null, ts = Math.floor(Date.now() / 1000) - 1000, cur = k1;
async function add(type, body, extra) {
  const payload = JSON.stringify({ v: 1, seq: links.length + 1, prev, ts: ts++, url, fp: fp(cur), type, body });
  const link = { payload, sig: await sign(cur, payload) };
  if (extra) Object.assign(link, await extra(payload));
  links.push(link);
  prev = createHash('sha256').update(payload).digest('hex');
}
await add('eldest', { name: 'Chain Test', bio: 'hello' });
await add('proof', { service: 'web', handle: 'example.test' });
await add('proof', { service: 'github', handle: 'octo' });
await add('profile', { name: 'Chain Tester', bio: 'updated' });
await add('mirrors', { urls: ['https://mirror.example.test/seal-id.json'] });
await add('revoke', { seqs: [2] });
// rotation: signed by the old key (sig) and the new key (sig_new)
await add('rotate', { new_fp: fp(k2), new_key: k2.pub }, async p => ({ sig_new: await sign(k2, p) }));
cur = k2;
await add('vouch', { target: 'https://id.other.test', target_fp: 'A'.repeat(40), target_seq: 3, target_hash: 'b'.repeat(64), proofs: [{ seq: 2, service: 'x', handle: 'other', how: 'auto' }] });

writeFileSync(resolve(here, 'chain-fixture.json'), JSON.stringify({ url, keys: { [fp(k1)]: k1.pub }, links, fp1: fp(k1), fp2: fp(k2) }, null, 1));
console.log('chain with', links.length, 'links;', fp(k1), '->', fp(k2));
