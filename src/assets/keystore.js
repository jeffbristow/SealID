// Seal ID — saved signing key (1.2.0). Optional: the manual way (load the key
// file / paste a signature each time) always keeps working.
//
// A. On this device: the unlocked private key is encrypted with AES-256-GCM and
//    kept in this browser's IndexedDB. The AES key comes from
//      - a passkey (Windows Hello, Touch ID, a phone…) through the WebAuthn PRF
//        extension: unlocking is one tap and there is nothing to type, or
//      - a passphrase (PBKDF2-SHA256, 600,000 rounds).
//    It never leaves this device.
// B. Encrypted copy on the Seal ID server: the same, passphrase only, encrypted
//    HERE before upload; the server stores a blob it cannot open and returns it
//    only to a signed-in owner. For using the key on other devices.
//
// Plain-text key material only ever exists in this page's memory.

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
export const PBKDF2_ITER = 600000;

/* ---------- IndexedDB (one tiny object store) ---------- */
function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('sealid-keys', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error || new Error('This browser does not allow saving here (private window?).'));
  });
}
async function idb(mode, fn) {
  const d = await db();
  return new Promise((res, rej) => {
    const tx = d.transaction('keys', mode);
    const req = fn(tx.objectStore('keys'));
    tx.oncomplete = () => { d.close(); res(req && req.result); };
    tx.onerror = () => { d.close(); rej(tx.error); };
  });
}

/* ---------- crypto ---------- */
async function keyFromPassphrase(pass, salt, iter = PBKDF2_ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function keyFromPrf(prf, salt) {
  const base = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('sealid-key-v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(aes, text, aad) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, aes, enc.encode(text));
  return { iv: b64(iv), ct: b64(ct) };
}
async function open(aes, rec, aad) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv), additionalData: enc.encode(aad) }, aes, unb64(rec.ct));
    return dec.decode(pt);
  } catch { throw new Error(rec.method === 'passkey' ? 'The passkey did not unlock this key.' : 'Wrong passphrase.'); }
}

/* ---------- passkeys (WebAuthn PRF) ---------- */
export async function passkeySupported() {
  if (!window.PublicKeyCredential || !navigator.credentials) return false;
  try {
    if (PublicKeyCredential.getClientCapabilities) {
      const c = await PublicKeyCredential.getClientCapabilities();
      if ('extension:prf' in c) return !!c['extension:prf'];
    }
  } catch { /* fall through */ }
  return true;   // unknown: try it, and fall back if the passkey has no PRF
}

async function prfFrom(credId, salt) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rand(32), allowCredentials: [{ type: 'public-key', id: credId }], userVerification: 'required', timeout: 120000,
    extensions: { prf: { eval: { first: salt } } } } });
  const r = a.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) throw new Error('This passkey can’t unlock keys (no PRF support here). Use a passphrase instead.');
  return r.results.first;
}

async function createPasskey(label, salt) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'Seal ID' },
    user: { id: rand(16), name: label, displayName: label },
    challenge: rand(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -8 }],
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    timeout: 120000,
    extensions: { prf: { eval: { first: salt } } } } });
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error('Your browser or passkey provider doesn’t support unlocking keys with a passkey (WebAuthn PRF). Use a passphrase instead.');
  const id = new Uint8Array(cred.rawId);
  const prf = ext.results && ext.results.first ? ext.results.first : await prfFrom(id, salt);
  return { id, prf };
}

/* ---------- A. this device ---------- */
const aadFor = id => 'sealid-key-v1|' + id;

export const deviceKey = {
  /** {method, created} or null */
  async status(id) {
    try { const r = await idb('readonly', s => s.get(id)); return r ? { method: r.method, created: r.created } : null; }
    catch { return null; }
  },
  async save(id, armoredSecret, { method, passphrase, label }) {
    const salt = rand(32);
    let aes, extra = {};
    if (method === 'passkey') {
      const pk = await createPasskey(label || 'Seal ID signing key', salt);
      aes = await keyFromPrf(pk.prf, salt);
      extra.cred = b64(pk.id);
    } else {
      if (!passphrase || passphrase.length < 8) throw new Error('Use a passphrase of at least 8 characters.');
      aes = await keyFromPassphrase(passphrase, salt);
      extra.iter = PBKDF2_ITER;
    }
    const sealed = await seal(aes, armoredSecret, aadFor(id));
    await idb('readwrite', s => s.put({ v: 1, method, salt: b64(salt), ...extra, ...sealed, created: Date.now() }, id));
  },
  async unlock(id, passphrase) {
    const r = await idb('readonly', s => s.get(id));
    if (!r) throw new Error('No key is saved on this device.');
    const salt = unb64(r.salt);
    const aes = r.method === 'passkey'
      ? await keyFromPrf(await prfFrom(unb64(r.cred), salt), salt)
      : await keyFromPassphrase(passphrase || '', salt, r.iter || PBKDF2_ITER);
    return open(aes, r, aadFor(id));
  },
  async remove(id) { await idb('readwrite', s => s.delete(id)); },
};

/* ---------- B. encrypted copy for the server ---------- */
export const serverCopy = {
  async make(url, fp, armoredSecret, passphrase) {
    if (!passphrase || passphrase.length < 12) throw new Error('Use a passphrase of at least 12 characters for the server copy — it protects the key if your hosting is ever broken into.');
    const salt = rand(32);
    const aes = await keyFromPassphrase(passphrase, salt);
    const sealed = await seal(aes, armoredSecret, aadFor(url + '|' + fp + '|server'));
    return { v: 1, fp, kdf: 'pbkdf2-sha256', iter: PBKDF2_ITER, salt: b64(salt), ...sealed };
  },
  async open(url, blob, passphrase) {
    const aes = await keyFromPassphrase(passphrase || '', unb64(blob.salt), blob.iter);
    return open(aes, { ...blob, method: 'passphrase' }, aadFor(url + '|' + blob.fp + '|server'));
  },
};
