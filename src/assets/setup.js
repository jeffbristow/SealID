// Seal ID — first-run setup.
import { signer, el, toast, keyForm, signDialog, fpGroups } from './sign.js';

const D = JSON.parse(document.getElementById('sealid-data').textContent);
const app = document.getElementById('app');

async function post(action, body) {
  const r = await fetch('setup.php?a=' + action, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': D.csrf }, body: JSON.stringify(body || {}),
  });
  let j = null;
  try { j = await r.json(); } catch { /* not JSON */ }
  if (!r.ok || !j || !j.ok) throw new Error((j && j.error) || ('Server error (HTTP ' + r.status + ')'));
  return j;
}

const state = { url: D.detected, name: D.reset ? D.reset.name : '', bio: '', publicKey: '' };

function card(title, ...kids) {
  return el('div', { class: 'card stack' }, el('h1', {}, title), ...kids);
}

function errBox() { return el('div', { class: 'notice bad hidden' }); }
function showErr(box, e) { box.textContent = e.message || String(e); box.classList.remove('hidden'); }

function checksBox() {
  const c = D.checks;
  const rows = [
    ['HTTPS', c.https, 'Seal ID must be served over https://'],
    ['PHP sodium (Ed25519)', c.sodium, 'Ask your host to enable the sodium extension'],
    ['PHP openssl (RSA)', c.openssl, 'Ask your host to enable openssl'],
    ['PHP curl (checking proofs)', c.curl, 'Ask your host to enable curl'],
    ['Data folder writable', c.data_dir, 'PHP must be able to write its data folder'],
    ['Can publish .well-known/seal-id.json', c.well_known, 'PHP must be able to write into the install folder'],
  ];
  const bad = rows.filter(r => !r[1]);
  return el('div', { class: 'notice ' + (bad.length ? 'warn' : 'ok') },
    bad.length ? el('div', {}, el('b', {}, 'Some requirements are missing:'), el('ul', {}, bad.map(r => el('li', {}, r[0] + ' — ' + r[2]))))
      : 'Server check passed: PHP ' + D.php + ', HTTPS, sodium, openssl, curl, writable folders.',
    c.data_outside ? null : el('div', { class: 'small mt' }, 'Note: the data folder is inside the web folder (protected by .htaccess). For best safety, set data_dir in config.php to a folder outside it.'));
}

function stepCode() {
  const inp = el('input', { type: 'password', autocomplete: 'off', placeholder: 'setup_code from config.php' });
  const err = errBox();
  const go = el('button', { class: 'btn primary', type: 'button' }, 'Continue');
  const submit = async () => {
    go.disabled = true;
    try { await post('code', { code: inp.value }); stepIdentity(); }
    catch (e) { showErr(err, e); go.disabled = false; }
  };
  go.addEventListener('click', submit);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  app.replaceChildren(card(D.reset ? 'Reset this Seal ID' : 'Set up Seal ID',
    el('img', { src: 'assets/seal-id.svg', alt: '', width: 88, height: 88 }),
    el('p', { class: 'muted' }, D.reset
      ? 'Resetting starts a new chain with a new key. Use this only if the old key is lost: people who checked you before will see that the identity was reset.'
      : 'Seal ID proves that you hold an OpenPGP key and own your website and social accounts — from your own server, checkable by anyone.'),
    checksBox(),
    el('div', { class: 'field' }, el('label', {}, 'Setup code'), inp), err, go));
  inp.focus();
}

function stepIdentity() {
  const url = el('input', { type: 'url', value: state.url });
  const name = el('input', { type: 'text', value: state.name, maxlength: 80, placeholder: 'e.g. Jeff Bristow' });
  const bio = el('textarea', { maxlength: 500, placeholder: 'Optional: one or two lines about you' });
  bio.value = state.bio;
  bio.classList.add('bio-input');
  const warn = el('div', { class: 'notice warn hidden' });
  const check = () => {
    const differs = url.value.replace(/\/+$/, '') !== D.detected;
    warn.textContent = 'This page is at ' + D.detected + '. Your Seal ID address should normally be the address of this installation.';
    warn.classList.toggle('hidden', !differs);
  };
  url.addEventListener('input', check);
  const go = el('button', { class: 'btn primary', type: 'button' }, 'Continue');
  go.addEventListener('click', () => {
    state.url = url.value.trim(); state.name = name.value.trim(); state.bio = bio.value.trim();
    if (!state.name) return toast('Enter a display name.', true);
    stepKey();
  });
  app.replaceChildren(card('Your identity',
    el('div', { class: 'field' }, el('label', {}, 'Seal ID address'), url,
      el('div', { class: 'tiny muted mt' }, 'This is your identity. Other Seal IDs find and check you here. It can’t be changed later without a reset.')),
    warn,
    el('div', { class: 'field' }, el('label', {}, 'Display name'), name),
    el('div', { class: 'field' }, el('label', {}, 'Bio'), bio),
    go));
  check();
}

function stepKey() {
  const err = errBox();
  const holder = el('div');
  const mode = m => {
    holder.replaceChildren();
    seg.querySelectorAll('button').forEach((b, i) => b.setAttribute('aria-pressed', String((i === 0) === (m === 'private'))));
    if (m === 'private') {
      holder.append(keyForm({ onLoaded: () => { state.publicKey = signer.publicArmored(); prepare(); } }));
    } else {
      const ta = el('textarea', { placeholder: '-----BEGIN PGP PUBLIC KEY BLOCK-----', spellcheck: 'false' });
      const go = el('button', { class: 'btn primary', type: 'button' }, 'Use this public key');
      go.addEventListener('click', () => { state.publicKey = ta.value.trim(); prepare(); });
      holder.append(el('p', { class: 'small muted' }, 'Paste your PUBLIC key. You will then sign one statement with your PGP app (gpg, Seal Post, …) and paste the signature.'), ta, go);
    }
  };
  const seg = el('div', { class: 'seg', role: 'group' },
    el('button', { type: 'button', onclick: () => mode('private') }, 'Unlock my key here'),
    el('button', { type: 'button', onclick: () => mode('public') }, 'Paste my public key'));

  async function prepare() {
    err.classList.add('hidden');
    try {
      const r = await post('prepare', { url: state.url, name: state.name, bio: state.bio, key: state.publicKey });
      stepSign(r);
    } catch (e) { showErr(err, e); }
  }

  app.replaceChildren(card('Your OpenPGP key',
    el('p', { class: 'muted' }, 'Seal ID is anchored on your OpenPGP key — the same kind of key Seal Post and Seal Chat use. Ed25519 and RSA keys work.'),
    seg, holder, err));
  mode('private');
}

function stepSign(r) {
  const err = errBox();
  const pw = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Optional fallback password' });
  const go = el('button', { class: 'btn primary', type: 'button' }, 'Sign and create my Seal ID');
  go.addEventListener('click', async () => {
    err.classList.add('hidden');
    const sig = await signDialog({
      title: 'Sign your first statement',
      explain: 'This “eldest” statement binds your key to ' + state.url + '. Everything later is chained to it.',
      payload: r.payload, expectFp: r.fp,
    });
    if (!sig) return;
    go.disabled = true;
    try {
      const done = await post('finish', { sig, password: pw.value });
      stepDone(done);
    } catch (e) { showErr(err, e); go.disabled = false; }
  });
  app.replaceChildren(card('Check and sign',
    el('dl', { class: 'kv' },
      el('dt', {}, 'Address'), el('dd', { class: 'mono' }, state.url),
      el('dt', {}, 'Name'), el('dd', {}, state.name),
      el('dt', {}, 'Key'), el('dd', { class: 'mono' }, fpGroups(r.fp)),
      el('dt', {}, 'Algorithm'), el('dd', {}, r.algo + (r.signing_subkeys ? ' (+ signing subkey)' : '')),
      el('dt', {}, 'User IDs'), el('dd', {}, (r.uids || []).join(', ') || '—')),
    r.reset_from ? el('div', { class: 'notice warn' }, 'This replaces the old key ' + fpGroups(r.reset_from) + '.') : null,
    el('div', { class: 'field' }, el('label', {}, 'Fallback password (optional)'), pw,
      el('div', { class: 'tiny muted mt' }, 'You normally sign in by signing a one-time challenge with your key. A password lets you sign in without the key — but anything that changes your identity still needs a signature.')),
    err, go));
}

function stepDone(r) {
  app.replaceChildren(card('Your Seal ID is live',
    el('img', { src: 'assets/seal-id.svg', alt: '', width: 88, height: 88 }),
    el('p', {}, 'Your identity ', el('b', { class: 'mono' }, r.url), ' is published.'),
    r.bundle_error ? el('div', { class: 'notice warn' }, 'Could not write .well-known/seal-id.json (' + r.bundle_error + '). Other Seal IDs will use api.php instead — fix the folder permissions when you can.') : null,
    el('p', { class: 'muted' }, 'Next: add proofs for your website and accounts, and vouch for people you know.'),
    el('div', { class: 'row wrapline' },
      el('a', { class: 'btn primary', href: 'admin.php' }, 'Open the admin page'),
      el('a', { class: 'btn', href: './' }, 'View my profile'))));
}

if (D.code_ok) stepIdentity(); else stepCode();
