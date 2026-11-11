// Seal ID — signing in the browser.
//
// The private key is read and unlocked HERE, kept only in this tab's memory,
// and never sent anywhere. The server only ever receives signatures.
// Alternative: sign the statement elsewhere (gpg, Seal Post, …) and paste the
// signature back.
import * as openpgp from './openpgp.min.mjs';

let key = null;          // decrypted openpgp.PrivateKey
const listeners = new Set();

export const signer = {
  loaded: () => key !== null,
  fp: () => (key ? key.getFingerprint().toUpperCase() : null),
  publicArmored: () => (key ? key.toPublic().armor() : null),
  onChange(fn) { listeners.add(fn); },
  forget() { key = null; listeners.forEach(f => f()); },
  async load(text, passphrase) {
    let k;
    try {
      k = await openpgp.readPrivateKey(text.includes('-----BEGIN') ? { armoredKey: text } : { binaryKey: text });
    } catch (e) {
      if (/PUBLIC KEY/.test(text)) throw new Error('That is your PUBLIC key. To sign here you need the PRIVATE key (it stays in this browser tab).');
      throw new Error('Could not read that private key: ' + e.message);
    }
    if (!k.isDecrypted()) {
      if (!passphrase) throw new Error('This key is protected. Enter its passphrase.');
      try { k = await openpgp.decryptKey({ privateKey: k, passphrase }); }
      catch { throw new Error('Wrong passphrase.'); }
    }
    key = k;
    listeners.forEach(f => f());
    return signer.fp();
  },
  async sign(payload) {
    if (!key) throw new Error('No key loaded.');
    const message = await openpgp.createMessage({ binary: new TextEncoder().encode(payload) });
    return openpgp.sign({ message, signingKeys: key, detached: true });
  },
};

/* ------------------------------------------------------------------ *
 * Small DOM helpers (shared with admin.js / setup.js)
 * ------------------------------------------------------------------ */
export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) n.append(c.nodeType ? c : String(c));
  return n;
}

export function toast(msg, bad = false) {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const t = el('div', { class: 'toast' + (bad ? ' bad' : ''), role: 'status' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

export function copyBox(text) {
  const btn = el('button', { class: 'btn small', type: 'button' }, 'Copy');
  btn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; }
    catch { btn.textContent = 'Select it'; }
    setTimeout(() => (btn.textContent = 'Copy'), 1800);
  });
  return el('div', { class: 'copybox' }, el('pre', {}, text), btn);
}

export function fpGroups(fp) {
  return (fp || '').replace(/(.{4})/g, '$1 ').trim();
}

function download(name, text) {
  const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

/* ------------------------------------------------------------------ *
 * Key panel: load / forget the private key
 * ------------------------------------------------------------------ */
export function keyForm({ expectFp, onLoaded, compact = false }) {
  const ta = el('textarea', { placeholder: '-----BEGIN PGP PRIVATE KEY BLOCK-----', spellcheck: 'false', autocomplete: 'off' });
  const file = el('input', { type: 'file', accept: '.asc,.key,.gpg,.pgp,.txt' });
  const pass = el('input', { type: 'password', placeholder: 'Passphrase (if the key has one)', autocomplete: 'off' });
  const err = el('div', { class: 'notice bad hidden' });
  const go = el('button', { class: 'btn primary', type: 'button' }, 'Unlock key');
  file.addEventListener('change', async () => {
    const f = file.files[0];
    if (!f) return;
    const buf = new Uint8Array(await f.arrayBuffer());
    const txt = new TextDecoder().decode(buf);
    ta.value = txt.includes('-----BEGIN') ? txt : '';
    ta.dataset.binary = txt.includes('-----BEGIN') ? '' : '1';
    ta._bin = buf;
  });
  go.addEventListener('click', async () => {
    err.classList.add('hidden');
    go.disabled = true;
    go.textContent = 'Unlocking…';
    try {
      const src = ta.dataset.binary === '1' && ta._bin ? ta._bin : ta.value.trim();
      if (!src) throw new Error('Choose your private key file or paste it.');
      const fp = await signer.load(src, pass.value);
      if (expectFp && fp !== expectFp) {
        signer.forget();
        throw new Error('That key is ' + fpGroups(fp) + ', but this Seal ID uses ' + fpGroups(expectFp) + '.');
      }
      ta.value = ''; pass.value = '';
      onLoaded && onLoaded(fp);
    } catch (e) {
      err.textContent = e.message;
      err.classList.remove('hidden');
    } finally {
      go.disabled = false;
      go.textContent = 'Unlock key';
    }
  });
  return el('div', { class: 'stack' },
    compact ? null : el('p', { class: 'small muted' }, 'Your private key is read and unlocked in this browser tab only. It is never uploaded; it is forgotten when you close the tab or press “Forget key”.'),
    el('div', { class: 'field' }, el('label', {}, 'Private key file'), file),
    el('div', { class: 'field' }, el('label', {}, '…or paste it'), ta),
    el('div', { class: 'field' }, el('label', {}, 'Passphrase'), pass),
    err, go);
}

/* ------------------------------------------------------------------ *
 * The sign dialog: returns a Promise of the armored signature (or null)
 * ------------------------------------------------------------------ */
export function signDialog({ title, explain, payload, expectFp }) {
  return new Promise(resolve => {
    const done = v => { modal.remove(); resolve(v); };
    const body = el('div', { class: 'stack' });
    const box = el('div', { class: 'box', role: 'dialog', 'aria-modal': 'true' },
      el('div', { class: 'row between' }, el('h2', { class: 'mb0' }, title || 'Sign this statement'),
        el('button', { class: 'btn small ghost', type: 'button', onclick: () => done(null) }, 'Cancel')),
      explain ? el('p', { class: 'small muted mt' }, explain) : null,
      el('details', { class: 'mt' }, el('summary', { class: 'small muted' }, 'Show the exact statement'), el('pre', { class: 'payload' }, payload)),
      body);
    const modal = el('div', { class: 'modal' }, box);
    modal.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); });

    const sigErr = el('div', { class: 'notice bad hidden' });
    const fail = m => { sigErr.textContent = m; sigErr.classList.remove('hidden'); };

    const doSign = async btn => {
      btn.disabled = true;
      try { done(await signer.sign(payload)); }
      catch (e) { btn.disabled = false; fail(e.message); }
    };

    const render = mode => {
      body.replaceChildren();
      sigErr.classList.add('hidden');
      if (signer.loaded() && (!expectFp || signer.fp() === expectFp) && mode !== 'paste') {
        const b = el('button', { class: 'btn primary', type: 'button' }, 'Sign with my loaded key');
        b.addEventListener('click', () => doSign(b));
        body.append(
          el('div', { class: 'notice ok mt' }, 'Your key ', el('span', { class: 'mono' }, fpGroups(signer.fp()).slice(-19)), ' is unlocked in this tab.'),
          sigErr, el('div', { class: 'row wrapline' }, b, el('button', { class: 'link small', type: 'button', onclick: () => render('paste') }, 'Sign elsewhere instead')));
        setTimeout(() => b.focus(), 50);
        return;
      }
      const seg = el('div', { class: 'seg', role: 'group' },
        el('button', { type: 'button', 'aria-pressed': mode !== 'paste' ? 'true' : 'false', onclick: () => render('key') }, 'Use my key here'),
        el('button', { type: 'button', 'aria-pressed': mode === 'paste' ? 'true' : 'false', onclick: () => render('paste') }, 'Paste a signature'));
      body.append(seg);
      if (mode !== 'paste') {
        body.append(keyForm({ expectFp, onLoaded: () => render('key') }));
      } else {
        const ta = el('textarea', { placeholder: '-----BEGIN PGP SIGNATURE-----', spellcheck: 'false' });
        const use = el('button', { class: 'btn primary', type: 'button' }, 'Use this signature');
        use.addEventListener('click', () => {
          const v = ta.value.trim();
          if (!/-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----/.test(v)) return fail('Paste the whole signature, including the BEGIN and END lines.');
          done(v);
        });
        body.append(
          el('ol', { class: 'steps small' },
            el('li', {}, 'Save the statement exactly as it is — one line, no line break at the end: ',
              el('button', { class: 'link', type: 'button', onclick: () => download('statement.txt', payload) }, 'download statement.txt')),
            el('li', { html: 'Sign it with your key, e.g. <code>gpg --armor --detach-sign statement.txt</code> (or clear-sign it in Seal Post / your PGP app).' }),
            el('li', {}, 'Paste the signature (statement.txt.asc) here:')),
          copyBox(payload), ta, sigErr, use);
      }
    };
    render(signer.loaded() ? 'key' : 'key');
    document.body.append(modal);
  });
}
