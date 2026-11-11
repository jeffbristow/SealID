// Seal ID — build and sign a release package.
//
//   node tools/release.mjs [version]
//
// 1. checks that src/lib/bootstrap.php says that version and that tag v<version> exists,
// 2. builds dist/SealID-<version>.zip from the TAG (git archive of src/, one
//    "SealID-<version>/" folder — exactly what installs unpack),
// 3. signs it: dist/SealID-<version>.zip.sig = {"version","sha256","sig"} where sig is
//    Ed25519 over "sealid-update-v1|<version>|<sha256>",
// 4. checks the signature against UPDATE_PUBKEY in src/lib/update.php.
//
// The signing key is NEVER in this repository. Default location:
//   ~/.sealid/update-signing-key.pem   (or set SEALID_SIGNING_KEY=path)
// Then attach both files to the GitHub release v<version>:
//   gh release create v<version> dist/SealID-<version>.zip dist/SealID-<version>.zip.sig --title "Seal ID <version>" --notes-file notes.md
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { homedir } from 'node:os';
import { dirname, resolve, join } from 'node:path';

const root = resolve(dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
const git = (...a) => execFileSync('git', a, { cwd: root }).toString().trim();
const die = m => { console.error('release: ' + m); process.exit(1); };

const boot = readFileSync(join(root, 'src/lib/bootstrap.php'), 'utf8');
const inCode = (boot.match(/const SEALID_VERSION = '([0-9.]+)'/) || [])[1];
const ver = process.argv[2] || inCode;
if (!/^\d+\.\d+\.\d+$/.test(ver || '')) die('no version');
if (ver !== inCode) die(`src/lib/bootstrap.php says ${inCode}, not ${ver}`);
try { git('rev-parse', '--verify', `v${ver}^{commit}`); } catch { die(`tag v${ver} does not exist — commit and tag first`); }
const tagged = git('show', `v${ver}:src/lib/bootstrap.php`);
if (!tagged.includes(`const SEALID_VERSION = '${ver}'`)) die(`tag v${ver} does not contain version ${ver}`);

const keyPath = process.env.SEALID_SIGNING_KEY || join(homedir(), '.sealid', 'update-signing-key.pem');
if (!existsSync(keyPath)) die('signing key not found at ' + keyPath);
const priv = createPrivateKey(readFileSync(keyPath));

mkdirSync(join(root, 'dist'), { recursive: true });
const zipPath = join(root, 'dist', `SealID-${ver}.zip`);
git('archive', '--format=zip', `--prefix=SealID-${ver}/`, '-o', zipPath, `v${ver}:src`);
const zip = readFileSync(zipPath);
const sha = createHash('sha256').update(zip).digest('hex');
const text = `sealid-update-v1|${ver}|${sha}`;
const sig = sign(null, Buffer.from(text), priv).toString('base64');
writeFileSync(zipPath + '.sig', JSON.stringify({ version: ver, sha256: sha, sig }, null, 1) + '\n');

// Check against the public key the installs trust.
const pubB64 = (readFileSync(join(root, 'src/lib/update.php'), 'utf8').match(/UPDATE_PUBKEY = '([^']+)'/) || [])[1];
const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pubB64, 'base64')]);
const pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
if (!verify(null, Buffer.from(text), pub, Buffer.from(sig, 'base64'))) die('signature does NOT verify with UPDATE_PUBKEY — wrong signing key?');

console.log(`dist/SealID-${ver}.zip      ${(zip.length / 1024).toFixed(0)} KB  sha256 ${sha}`);
console.log(`dist/SealID-${ver}.zip.sig  signed, verified against UPDATE_PUBKEY`);
