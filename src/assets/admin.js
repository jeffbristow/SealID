// Seal ID — admin page.
import { signer, el, toast, copyBox, keyForm, signDialog, fpGroups, setSavedKeyProvider, savedKeyButtons } from './sign.js';
import { deviceKey, serverCopy, passkeySupported } from './keystore.js';

const D = JSON.parse(document.getElementById('sealid-data').textContent);
const app = document.getElementById('app');
let S = null;              // last admin state from the server
let tab = 'proofs';
let peerReport = null;     // last "check another Seal ID" report

/* Saved signing key (1.2.0, optional): offered wherever the key is needed. */
const KID = () => D.url + '|' + D.fp;
setSavedKeyProvider(async () => {
  const out = [];
  const st = await deviceKey.status(KID());
  if (st) out.push({
    short: 'this device', needsPassphrase: st.method !== 'passkey',
    label: st.method === 'passkey' ? 'Unlock with my passkey' : 'Unlock the key saved on this device',
    unlock: p => deviceKey.unlock(KID(), p),
  });
  if (D.admin && S && S.keystore) out.push({
    short: 'the server copy', needsPassphrase: true, label: 'Unlock the copy on my Seal ID server',
    unlock: async p => { const r = await api('keystore_get'); if (!r.blob) throw new Error('There is no server copy.'); return serverCopy.open(D.url, r.blob, p); },
  });
  return out;
});

/* ------------------------------------------------------------------ */
async function api(action, body) {
  const r = await fetch('admin.php?a=' + action, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF': D.csrf }, body: JSON.stringify(body || {}),
  });
  let j = null;
  try { j = await r.json(); } catch { /* not JSON */ }
  if (r.status === 401) { D.admin = false; renderLogin(); throw new Error('Please sign in again.'); }
  if (!r.ok || !j || !j.ok) throw new Error((j && j.error) || ('Server error (HTTP ' + r.status + ')'));
  if (j.identity) S = j;
  return j;
}

/** prepare → sign → append. Returns the append answer or null if cancelled. */
async function signStatement(body, title, explain) {
  const prep = await api('prepare', body);
  const sig = await signDialog({ title, explain, payload: prep.payload, expectFp: S.identity.fp });
  if (!sig) return null;
  return api('append', { payload: prep.payload, sig });
}

const busy = async (btn, fn) => {
  const t = btn.textContent;
  btn.disabled = true;
  btn.textContent = '…';
  try { return await fn(); }
  catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = t; }
};

function ago(ts) {
  if (!ts) return 'never';
  const d = Date.now() / 1000 - ts;
  if (d < 90) return 'just now';
  if (d < 5400) return Math.round(d / 60) + ' min ago';
  if (d < 129600) return Math.round(d / 3600) + ' h ago';
  if (d < 86400 * 45) return Math.round(d / 86400) + ' days ago';
  return new Date(ts * 1000).toLocaleDateString();
}

const LABELS = { verified: 'Verified', failed: 'Failed', unreachable: 'Not reachable right now', pending: 'Pending', witnessed: 'Witnessed', unsupported: 'Not supported here' };
const badge = (s, title) => el('span', { class: 'badge s-' + s, title: title || '' }, LABELS[s] || s);
const LETTERS = { web: 'W', dns: 'D', github: 'GH', x: 'X', mastodon: 'M', bluesky: 'B', hackernews: 'Y', reddit: 'R', youtube: 'YT', facebook: 'F', sealchat: 'SC' };
const avatarEl = (src, name, cls = 'avatar') => src
  ? el('img', { class: cls + ' avatar-img', src, alt: '' })
  : el('div', { class: cls, 'aria-hidden': 'true' }, (name || '?').slice(0, 1).toUpperCase());
const svc = id => el('div', { class: 'svc', 'aria-hidden': 'true' }, LETTERS[id] || id.slice(0, 1).toUpperCase());

/* ------------------------------------------------------------------ *
 * Sign-in
 * ------------------------------------------------------------------ */
function renderLogin() {
  const err = el('div', { class: 'notice bad hidden' });
  const fail = e => { err.textContent = e.message; err.classList.remove('hidden'); };
  const savedBox = el('div', { class: 'stack' });
  const keyBtn = el('button', { class: 'btn primary', type: 'button' }, 'Sign in with my key');
  keyBtn.addEventListener('click', () => busy(keyBtn, async () => {
    err.classList.add('hidden');
    const c = await api('challenge');
    const sig = await signDialog({ title: 'Sign in', explain: 'Sign this one-time challenge to prove you hold the key of ' + D.url + '.', payload: c.payload, expectFp: D.fp });
    if (!sig) return;
    try { const r = await api('login', { sig }); D.csrf = r.csrf || D.csrf; D.admin = true; await load(); }
    catch (e) { fail(e); }
  }));
  let pwBox = null;
  if (D.has_password) {
    const pw = el('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Fallback password' });
    const go = el('button', { class: 'btn', type: 'button' }, 'Sign in with password');
    const submit = () => busy(go, async () => {
      err.classList.add('hidden');
      try { const r = await api('login', { password: pw.value }); D.csrf = r.csrf || D.csrf; D.admin = true; await load(); }
      catch (e) { fail(e); }
    });
    go.addEventListener('click', submit);
    pw.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
    pwBox = el('div', { class: 'stack mt-lg' }, el('div', { class: 'small muted' }, 'or'), pw, go);
  }
  app.replaceChildren(el('div', { class: 'card stack narrow-card' },
    el('img', { src: 'assets/seal-id.svg', alt: '', width: 80, height: 80 }),
    el('h1', {}, 'Sign in'),
    el('p', { class: 'muted' }, 'Owner of ', el('span', { class: 'mono' }, D.url)),
    savedBox, err, keyBtn, pwBox));
  // 1.2.0: a key saved on this device signs the sign-in challenge in one step.
  savedKeyButtons({ expectFp: D.fp, onError: fail, onLoaded: async () => {
    try {
      const c = await api('challenge');
      const r = await api('login', { sig: await signer.sign(c.payload) });
      D.csrf = r.csrf || D.csrf; D.admin = true; await load();
    } catch (e) { fail(e); }
  } }).then(b => { if (b) savedBox.append(b, el('div', { class: 'small muted' }, 'or')); });
}

/* ------------------------------------------------------------------ *
 * Main layout
 * ------------------------------------------------------------------ */
async function load() {
  await api('state');
  render();
  // Ask GitHub (at most every 12 h, server-side) in the background; only redraw if something new appeared.
  api('update_status').then(r => {
    const had = S.update && S.update.update && S.update.update.version;
    S.update = r.update;
    if (r.update.update && r.update.update.version !== had) render();
  }).catch(() => {});
}

function keyBar() {
  const bar = el('div', { class: 'keybar' });
  const draw = () => {
    bar.replaceChildren();
    if (signer.loaded()) {
      bar.append(el('span', { class: 'row' }, el('span', { class: 'dot on' }), el('span', {}, 'Signing key unlocked in this tab: ', el('span', { class: 'mono' }, fpGroups(signer.fp()).slice(-19)))),
        el('button', { class: 'btn small right', type: 'button', onclick: () => signer.forget() }, 'Forget key'));
    } else {
      bar.append(el('span', { class: 'row' }, el('span', { class: 'dot' }), el('span', { class: 'muted' }, 'Signing key not loaded — you’ll be asked when something needs a signature.')),
        el('button', { class: 'btn small right', type: 'button', onclick: unlockModal }, 'Unlock key'));
    }
  };
  signer.onChange(draw);
  draw();
  return bar;
}

function unlockModal() {
  const modal = el('div', { class: 'modal' });
  const close = () => modal.remove();
  const done = () => { close(); toast('Key unlocked for this tab.'); };
  const saved = el('div', { class: 'stack' });
  modal.append(el('div', { class: 'box' },
    el('div', { class: 'row between' }, el('h2', { class: 'mb0' }, 'Unlock your key'), el('button', { class: 'btn small ghost', type: 'button', onclick: close }, 'Close')),
    saved,
    keyForm({ expectFp: S.identity.fp, onLoaded: done })));
  document.body.append(modal);
  savedKeyButtons({ expectFp: S.identity.fp, onLoaded: done }).then(b => { if (b) saved.append(b, el('div', { class: 'small muted mt' }, '…or load the key file:')); });
}

function render() {
  const I = S.identity;
  const tabs = [['proofs', 'Proofs'], ['vouch', 'Vouch'], ['profile', 'Profile'], ['settings', 'Settings']];
  const body = el('div');
  const tabBar = el('div', { class: 'tabs', role: 'tablist' }, tabs.map(([id, label]) =>
    el('button', { class: 'tab', role: 'tab', type: 'button', 'aria-selected': String(tab === id), onclick: () => { tab = id; render(); } }, label)));
  const up = S.update && S.update.update;
  const banner = up ? el('div', { class: 'notice ok update-banner' },
    el('span', { class: 'grow' }, el('b', {}, 'Seal ID ' + up.version + ' is available.'), ' You have ' + S.update.current + '.'),
    el('button', { class: 'btn small', type: 'button', onclick: () => { tab = 'settings'; render(); document.getElementById('updates')?.scrollIntoView({ behavior: 'smooth' }); } }, 'See what’s new')) : null;
  app.replaceChildren(
    el('div', { class: 'row between' },
      el('div', { class: 'row' }, avatarEl(I.avatar_url, I.name),
        el('div', {}, el('h1', { class: 'mb0' }, I.name || 'Seal ID'), el('div', { class: 'idurl' }, I.url))),
      el('button', { class: 'btn small ghost', type: 'button', onclick: async () => { await api('logout').catch(() => {}); signer.forget(); location.reload(); } }, 'Sign out')),
    el('div', { class: 'fp mt' }, fpGroups(I.fp), ' · ', I.algo, ' · ', I.seq + ' signed statements'),
    banner || "",
    el('div', { class: 'mt' }, keyBar()),
    tabBar, body);
  ({ proofs: renderProofs, vouch: renderVouch, profile: renderProfile, settings: renderSettings })[tab](body);
}

/* ------------------------------------------------------------------ *
 * Proofs tab
 * ------------------------------------------------------------------ */
function instructionsBox(ins, onSaved) {
  const box = el('div', { class: 'notice stack mt' });
  const steps = el('ol', { class: 'steps' });
  // The proof text goes under the first step that ends with a colon.
  let at = ins.steps.findIndex(s => s.replace(/<[^>]+>/g, '').trim().endsWith(':'));
  if (at < 0) at = 0;
  ins.steps.forEach((s, i) => {
    const li = el('li', { html: s });
    if (i === at) li.append(copyBox(ins.text));
    steps.append(li);
  });
  box.append(el('b', {}, 'Publish your ' + ins.label + ' proof'), steps);
  if (ins.needs_locator) {
    const inp = el('input', { type: 'url', placeholder: ins.locator_hint });
    const save = el('button', { class: 'btn primary small', type: 'button' }, 'Save address');
    save.addEventListener('click', () => busy(save, async () => {
      await api('locator', { seq: ins.seq, url: inp.value.trim() });
      toast('Saved.');
      onSaved && onSaved();
    }));
    box.append(el('div', { class: 'row wrapline' }, el('div', { class: 'grow' }, inp), save));
  }
  return box;
}

function renderProofs(root) {
  // Add a proof
  const sel = el('select', {}, S.services.map(s => el('option', { value: s.id }, s.label + (s.auto ? '' : ' (witnessed)'))));
  const handle = el('input', { type: 'text', placeholder: S.services[0].hint });
  sel.addEventListener('change', () => { handle.placeholder = S.services.find(s => s.id === sel.value).hint; });
  const add = el('button', { class: 'btn primary', type: 'button' }, 'Add proof');
  const result = el('div');
  add.addEventListener('click', () => busy(add, async () => {
    const r = await signStatement({ type: 'proof', service: sel.value, handle: handle.value }, 'Sign your claim',
      'You claim this account. Next you’ll publish the proof text on it, so anyone can see the account agrees.');
    if (!r) return;
    handle.value = '';
    render();
    const target = document.querySelector('.proof[data-seq="' + r.seq + '"]');
    if (target) target.querySelector('.grow').append(instructionsBox(r.proof, () => render()));
  }));
  root.append(el('div', { class: 'card' },
    el('h2', {}, 'Add a proof'),
    el('div', { class: 'grid2' }, el('div', { class: 'field' }, el('label', {}, 'Service'), sel), el('div', { class: 'field' }, el('label', {}, 'Account'), handle)),
    el('div', { class: 'mt' }, add), result));

  // List
  const list = el('ul', { class: 'proofs' });
  if (!S.proofs.length) list.append(el('li', { class: 'muted small' }, 'No proofs yet. Start with your website or a domain.'));
  for (const p of S.proofs) {
    const g = el('div', { class: 'grow' });
    const recheck = el('button', { class: 'btn small', type: 'button' }, 'Check now');
    recheck.addEventListener('click', () => busy(recheck, async () => { await api('recheck', { seq: p.seq }); render(); toast('Checked.'); }));
    const how = el('button', { class: 'btn small', type: 'button' }, p.needs_locator && !p.locator ? 'Finish this proof' : 'Instructions');
    how.addEventListener('click', () => busy(how, async () => {
      const r = await api('instructions', { seq: p.seq });
      g.querySelectorAll('.notice').forEach(n => n.remove());
      g.append(instructionsBox(r.proof, () => render()));
    }));
    const revoke = el('button', { class: 'btn small danger', type: 'button' }, 'Revoke');
    revoke.addEventListener('click', () => busy(revoke, async () => {
      const r = await signStatement({ type: 'revoke', seqs: [p.seq] }, 'Revoke this proof', 'Withdraw your claim to ' + p.label + ' ' + p.handle + '. The history stays in your chain, marked as revoked.');
      if (r) { render(); toast('Revoked.'); }
    }));
    g.append(
      el('div', { class: 'row wrapline gap-sm' }, el('span', { class: 'who' }, p.profile ? el('a', { href: p.profile, target: '_blank', rel: 'noopener' }, p.handle) : p.handle),
        el('span', { class: 'small muted' }, p.label), badge(p.status, p.detail)),
      el('div', { class: 'meta' }, p.detail, p.checked ? ' · checked ' + ago(p.checked) : '',
        p.locator ? [' · ', el('a', { href: p.locator, target: '_blank', rel: 'noopener' }, 'proof post')] : '',
        p.witnesses.length ? ' · witnessed by ' + p.witnesses.length : ''),
      el('div', { class: 'actions' }, p.auto ? recheck : null, how, revoke));
    list.append(el('li', { class: 'proof', 'data-seq': p.seq }, svc(p.service), g));
  }
  const all = el('button', { class: 'btn small', type: 'button' }, 'Re-check all');
  all.addEventListener('click', () => busy(all, async () => { await api('recheck', {}); render(); }));
  root.append(el('div', { class: 'card' }, el('div', { class: 'row between' }, el('h2', {}, 'Your proofs'), S.proofs.length ? all : null), list));
}

/* ------------------------------------------------------------------ *
 * Vouch tab
 * ------------------------------------------------------------------ */
function renderVouch(root) {
  const inp = el('input', { type: 'text', placeholder: 'id.example.com', value: peerReport ? peerReport.url : '' });
  const go = el('button', { class: 'btn primary', type: 'button' }, 'Check');
  const out = el('div');
  const run = () => busy(go, async () => {
    out.replaceChildren(el('p', { class: 'muted mt' }, 'Fetching and verifying — this re-checks every proof, so it can take a little while…'));
    const r = await api('peer', { url: inp.value.trim() });
    peerReport = r.report;
    drawReport(out, r.report);
  });
  go.addEventListener('click', run);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  root.append(el('div', { class: 'card' },
    el('h2', {}, 'Check and vouch for another Seal ID'),
    el('p', { class: 'small muted' }, 'Your server fetches their signed chain, verifies every signature and re-checks every proof itself. Then you choose what to vouch for.'),
    el('div', { class: 'row wrapline' }, el('div', { class: 'grow' }, inp), go), out));
  if (peerReport) drawReport(out, peerReport);

  // Given
  const gl = el('ul', { class: 'vlist' });
  if (!S.given.length) gl.append(el('li', { class: 'muted small' }, 'None yet.'));
  for (const v of S.given) {
    const resend = el('button', { class: 'btn small', type: 'button' }, 'Notify again');
    resend.addEventListener('click', () => busy(resend, async () => { const r = await api('notify', { seq: v.seq }); render(); toast(r.notify.detail, !r.notify.ok); }));
    const rev = el('button', { class: 'btn small danger', type: 'button' }, 'Withdraw');
    rev.addEventListener('click', () => busy(rev, async () => {
      const r = await signStatement({ type: 'revoke', seqs: [v.seq] }, 'Withdraw this vouch', 'You no longer vouch for ' + v.target + '.');
      if (r) { render(); toast('Withdrawn. They will notice on their next refresh.'); }
    }));
    gl.append(el('li', {},
      el('a', { href: v.target, target: '_blank', rel: 'noopener' }, v.target),
      el('div', { class: 'tiny muted' }, ago(v.ts) + ' · ' + v.proofs.length + ' proofs · key …' + v.target_fp.slice(-16)),
      v.notify ? el('div', { class: 'tiny ' + (v.notify.ok ? 'muted' : 'faint') }, v.notify.detail) : null,
      el('div', { class: 'actions row wrapline mt' }, v.notify && v.notify.ok ? null : resend, rev)));
  }

  // Received
  const rl = el('ul', { class: 'vlist' });
  if (!S.received.length) rl.append(el('li', { class: 'muted small' }, 'None yet.'));
  for (const v of S.received) {
    rl.append(el('li', {}, el('a', { href: v.url, target: '_blank', rel: 'noopener' }, v.name || v.url),
      el('div', { class: 'tiny muted' }, v.url + ' · ' + ago(v.ts) + ' · ' + v.proofs.map(p => p.service + (p.how === 'witnessed' ? ' (witnessed)' : '')).join(', '))));
  }
  const imp = el('input', { type: 'text', placeholder: 'Their Seal ID address' });
  const impBtn = el('button', { class: 'btn small', type: 'button' }, 'Import');
  impBtn.addEventListener('click', () => busy(impBtn, async () => { await api('import_vouch', { url: imp.value.trim() }); render(); toast('Imported.'); }));
  root.append(el('div', { class: 'grid2 section' },
    el('div', { class: 'card' }, el('h2', {}, 'You vouched for'), gl),
    el('div', { class: 'card' }, el('h2', {}, 'Vouched for you'), rl,
      el('div', { class: 'small muted mt' }, 'Someone vouched but it isn’t listed (their notification was blocked)? Import it:'),
      el('div', { class: 'row wrapline mt' }, el('div', { class: 'grow' }, imp), impBtn))));
}

function drawReport(out, r) {
  out.replaceChildren();
  const box = el('div', { class: 'stack mt-lg' });
  out.append(box);
  if (!r.ok) {
    box.append(el('div', { class: 'notice bad' }, r.error),
      r.attempts && r.attempts.length ? el('ul', { class: 'small muted' }, r.attempts.map(a => el('li', {}, a.source + ' — ' + a.result))) : '');
    return;
  }
  if (r.pin === 'changed') {
    const acc = el('button', { class: 'btn small danger', type: 'button' }, 'Forget what I saw before');
    acc.addEventListener('click', () => busy(acc, async () => { await api('peer_accept', { url: r.url }); toast('Forgotten. Check again.'); }));
    box.append(el('div', { class: 'notice bad stack' },
      el('b', {}, 'Warning: this identity changed in a way that does not extend what you saw before.'),
      el('div', {}, 'Before: key ' + fpGroups(r.pinned.fp) + ' with ' + r.pinned.seq + ' statements. Now: key ' + fpGroups(r.fp) + ' with ' + r.seq + '. This happens when someone resets a lost key — or when someone else took over the address. Confirm with the person another way before trusting it.'),
      acc));
  }
  r.warnings.forEach(w => box.append(el('div', { class: 'notice warn' }, w)));
  box.append(el('div', { class: 'peer-head' },
    avatarEl(r.avatar, r.name),
    el('div', {}, el('h3', { class: 'mb0' }, r.name || r.url), el('div', { class: 'idurl' }, r.url),
      el('div', { class: 'fp' }, fpGroups(r.fp) + ' · ' + r.algo),
      el('div', { class: 'tiny muted' }, r.seq + ' signed statements · ' + (r.pin === 'match' ? 'same identity as before' : r.pin === 'new' ? 'first time seen' : r.pin) + (r.dns && r.dns.fp === r.fp ? ' · key confirmed by DNS' : '')))));
  if (r.bio) box.append(el('p', { class: 'small muted' }, r.bio));

  const choices = {};
  const list = el('ul', { class: 'proofs' });
  if (!r.proofs.length) list.append(el('li', { class: 'muted small' }, 'This Seal ID has no proofs.'));
  for (const p of r.proofs) {
    const auto = el('input', { type: 'checkbox' });
    const wit = el('input', { type: 'checkbox' });
    const canAuto = p.status === 'verified';
    auto.checked = canAuto;
    auto.disabled = !canAuto;
    const sync = () => { choices[p.seq] = auto.checked ? 'auto' : (wit.checked ? 'witnessed' : null); };
    auto.addEventListener('change', () => { if (auto.checked) wit.checked = false; sync(); });
    wit.addEventListener('change', () => { if (wit.checked) auto.checked = false; sync(); });
    sync();
    const witnessText = 'Verifying my Seal ID ' + r.url + ' ' + p.token;
    list.append(el('li', { class: 'proof' }, svc(p.service), el('div', { class: 'grow' },
      el('div', { class: 'row wrapline gap-sm' }, el('span', { class: 'who' }, p.profile ? el('a', { href: p.profile, target: '_blank', rel: 'noopener' }, p.handle) : p.handle),
        el('span', { class: 'small muted' }, p.label), badge(p.status, p.detail)),
      el('div', { class: 'meta' }, p.detail, p.locator ? [' · ', el('a', { href: p.locator, target: '_blank', rel: 'noopener' }, 'open the proof post')] : ''),
      el('label', { class: 'check mt' }, auto, el('span', {}, canAuto ? 'Vouch: my server verified this' : 'My server could not verify this automatically')),
      el('label', { class: 'check' }, wit, el('span', {}, 'I witnessed it myself: I opened the account/post and saw ',
        el('code', {}, p.service === 'dns' ? p.token : witnessText), ' published by ', el('b', {}, p.handle))))));
  }
  const vouch = el('button', { class: 'btn primary', type: 'button' }, 'Sign my vouch for ' + (r.name || r.url));
  vouch.disabled = r.pin === 'changed';
  vouch.addEventListener('click', () => busy(vouch, async () => {
    const res = await signStatement({ type: 'vouch', target: r.url, proofs: choices }, 'Vouch for ' + (r.name || r.url),
      'Your signed statement says you checked ' + r.url + ' (key ' + fpGroups(r.fp).slice(-19) + ') and confirms the proofs you ticked.');
    if (!res) return;
    toast(res.notify ? res.notify.detail : 'Vouched.', res.notify && !res.notify.ok);
    peerReport = null;
    render();
  }));
  box.append(el('div', { class: 'card' }, list), el('div', {}, vouch));
}

/* ------------------------------------------------------------------ *
 * Profile tab
 * ------------------------------------------------------------------ */
/** Crop to a centred square and scale down in the browser before uploading. */
async function squareImage(file, size = 512) {
  const bmp = await createImageBitmap(file);
  const side = Math.min(bmp.width, bmp.height);
  const out = Math.min(size, side);
  const c = document.createElement('canvas');
  c.width = c.height = out;
  c.getContext('2d').drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, out, out);
  bmp.close && bmp.close();
  const webp = c.toDataURL('image/webp', 0.9);
  return webp.startsWith('data:image/webp') ? webp : c.toDataURL('image/png');
}

function renderProfile(root) {
  const I = S.identity;
  const name = el('input', { type: 'text', value: I.name, maxlength: 80 });
  const bio = el('textarea', { maxlength: 500 });
  bio.value = I.bio;
  // undefined = unchanged, null = removed, sha = newly uploaded
  let picture;
  const preview = el('div');
  const showPreview = src => preview.replaceChildren(avatarEl(src, name.value || I.name, 'avatar lg'));
  showPreview(I.avatar_url);
  const file = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif', class: 'hidden' });
  const choose = el('button', { class: 'btn small', type: 'button', onclick: () => file.click() }, I.avatar ? 'Change picture' : 'Add a picture');
  const remove = el('button', { class: 'btn small danger', type: 'button' }, 'Remove');
  remove.classList.toggle('hidden', !I.avatar);
  const note = el('div', { class: 'tiny muted' }, 'Square pictures work best; others are cropped to the centre. Saved as part of your signed profile.');
  file.addEventListener('change', () => busy(choose, async () => {
    const f = file.files[0];
    if (!f) return;
    let data;
    try { data = await squareImage(f); } catch { throw new Error('That picture could not be opened here. Try a PNG or JPEG.'); }
    const r = await api('avatar_upload', { image: data });
    picture = r.sha;
    showPreview(r.data);
    remove.classList.remove('hidden');
    note.textContent = 'New picture ready — press “Sign and save” to publish it.';
    file.value = '';
  }));
  remove.addEventListener('click', () => {
    picture = null;
    showPreview(null);
    remove.classList.add('hidden');
    note.textContent = 'The picture will be removed when you sign and save.';
  });
  const save = el('button', { class: 'btn primary', type: 'button' }, 'Sign and save');
  save.addEventListener('click', () => busy(save, async () => {
    const avatar = picture === undefined ? (I.avatar || null) : picture;
    const r = await signStatement({ type: 'profile', name: name.value, bio: bio.value, avatar }, 'Update your profile',
      avatar && avatar !== I.avatar ? 'Your signed profile will include the new picture’s fingerprint (SHA-256), so nobody can swap it.' : undefined);
    if (r) { render(); toast('Saved.'); }
  }));
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Profile'),
    el('div', { class: 'field' }, el('label', {}, 'Picture'),
      el('div', { class: 'avatar-edit' }, preview, el('div', { class: 'stack' }, el('div', { class: 'row wrapline' }, choose, remove), note)), file),
    el('div', { class: 'field' }, el('label', {}, 'Display name'), name),
    el('div', { class: 'field' }, el('label', {}, 'Bio'), bio), save));
}

/* ------------------------------------------------------------------ *
 * Settings tab
 * ------------------------------------------------------------------ */
function updatesCard() {
  const U = S.update || {};
  const box = el('div', { class: 'card stack', id: 'updates' }, el('h2', {}, 'Updates'));
  const redraw = u => { S.update = u; render(); };
  const check = el('button', { class: 'btn small', type: 'button' }, 'Check now');
  check.addEventListener('click', () => busy(check, async () => { const r = await api('update_check'); redraw(r.update); toast(r.update.update ? 'An update is available.' : 'You have the newest version.'); }));
  box.append(el('p', { class: 'small muted' },
    'This is Seal ID ' + U.current + '. ',
    U.checked ? 'Last checked ' + ago(U.checked) + (U.latest ? ' — newest release: ' + U.latest + '.' : '.') : 'Not checked yet.'),
    U.error && !U.latest ? el('div', { class: 'notice warn' }, 'Couldn’t check GitHub: ' + U.error) : '');
  if (U.update) {
    const go = el('button', { class: 'btn primary', type: 'button' }, 'Update to ' + U.update.version);
    go.addEventListener('click', () => busy(go, async () => {
      const r = await api('update_install');
      toast(r.message);
      setTimeout(() => location.reload(), 1200);   // load the new admin page
    }));
    box.append(el('div', { class: 'notice ok stack' },
      el('b', {}, 'Seal ID ' + U.update.version + ' is available.'),
      U.update.notes && U.update.notes.length ? el('ul', { class: 'notes' }, U.update.notes.map(n => el('li', {}, n))) : null,
      U.update.url ? el('a', { href: U.update.url, target: '_blank', rel: 'noopener', class: 'small' }, 'Release notes on GitHub') : null,
      U.blockers && U.blockers.length ? el('div', { class: 'notice bad' }, 'Can’t update here: ' + U.blockers.join('; ')) : el('div', { class: 'row wrapline' }, go,
        el('span', { class: 'tiny muted' }, 'Downloads the signed package from GitHub, checks its signature, keeps a backup. Your data and config.php are never touched.'))));
  }
  const row = el('div', { class: 'row wrapline' }, check);
  if (U.undo) {
    const undo = el('button', { class: 'btn small danger', type: 'button' }, 'Undo last update (back to ' + U.undo + ')');
    undo.addEventListener('click', () => busy(undo, async () => { const r = await api('update_undo'); toast(r.message); setTimeout(() => location.reload(), 1200); }));
    row.append(undo);
  }
  box.append(row);
  return box;
}

/** 1.2.0: optional saved signing key — on this device (A) and/or encrypted on this server (B). */
function keyStorageCard() {
  const box = el('div', { class: 'card stack', id: 'keystorage' }, el('h2', {}, 'Saved signing key (optional)'),
    el('p', { class: 'small muted' }, 'Normally you load your key file — or paste a signature from gpg or Seal Post — whenever something needs signing, and that keeps working. ' +
      'If you prefer, save the key encrypted so signing is a single tap. Your key is encrypted in this browser before it is stored anywhere; this server never sees it unencrypted.'));
  const dev = el('div', { class: 'stack' });
  const srv = el('div', { class: 'stack' });
  box.append(el('h3', { class: 'mt' }, 'On this device'), dev, el('h3', { class: 'mt' }, 'Encrypted copy on this server (for your other devices)'), srv);
  const needKey = () => {
    if (signer.loaded()) return true;
    unlockModal();
    toast('Unlock your key first (this once), then choose again.');
    return false;
  };
  const host = new URL(D.url).host;
  (async () => {
    const st = await deviceKey.status(KID());
    if (st) {
      const rm = el('button', { class: 'btn small danger', type: 'button' }, 'Remove from this device');
      rm.addEventListener('click', () => busy(rm, async () => { await deviceKey.remove(KID()); toast('Removed from this device.'); render(); }));
      dev.append(el('div', { class: 'notice ok' }, 'Saved on this device, unlocked with ' + (st.method === 'passkey' ? 'a passkey' : 'a passphrase') + ' (since ' + new Date(st.created).toLocaleDateString() + ').'), el('div', {}, rm));
    } else {
      const pk = await passkeySupported();
      const pass = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Passphrase (8+ characters)' });
      const withPk = el('button', { class: 'btn primary', type: 'button' }, 'Save with a passkey');
      withPk.addEventListener('click', () => busy(withPk, async () => {
        if (!needKey()) return;
        await deviceKey.save(KID(), signer.secretArmored(), { method: 'passkey', label: 'Seal ID · ' + host });
        toast('Saved. Next time, one tap unlocks it.');
        render();
      }));
      const withPass = el('button', { class: 'btn', type: 'button' }, 'Save with a passphrase');
      withPass.addEventListener('click', () => busy(withPass, async () => {
        if (!needKey()) return;
        await deviceKey.save(KID(), signer.secretArmored(), { method: 'passphrase', passphrase: pass.value });
        pass.value = '';
        toast('Saved on this device.');
        render();
      }));
      dev.append(
        el('p', { class: 'small muted' }, 'Kept only in this browser, encrypted. A passkey (Windows Hello, Touch ID, your phone) unlocks it with nothing to type; otherwise use a passphrase. Clearing this browser’s site data removes it.'),
        pk ? el('div', { class: 'row wrapline' }, withPk, el('span', { class: 'tiny muted' }, 'Needs a browser and passkey that support WebAuthn PRF.')) : '',
        el('div', { class: 'row wrapline' }, el('div', { class: 'grow' }, pass), withPass));
    }

    if (S.keystore) {
      const rm = el('button', { class: 'btn small danger', type: 'button' }, 'Delete the server copy');
      rm.addEventListener('click', () => busy(rm, async () => { await api('keystore_delete'); toast('Deleted.'); render(); }));
      srv.append(el('div', { class: 'notice ok' }, 'An encrypted copy is stored here (since ' + new Date(S.keystore.created * 1000).toLocaleDateString() + '). On another device: sign in with your fallback password, then unlock it with its passphrase.'), el('div', {}, rm));
    } else {
      const p1 = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Passphrase (12+ characters)' });
      const p2 = el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Same passphrase again' });
      const up = el('button', { class: 'btn', type: 'button' }, 'Encrypt and store on this server');
      up.addEventListener('click', () => busy(up, async () => {
        if (p1.value !== p2.value) throw new Error('The passphrases are different.');
        if (!needKey()) return;
        const blob = await serverCopy.make(D.url, S.identity.fp, signer.secretArmored(), p1.value);
        await api('keystore_put', { blob });
        p1.value = p2.value = '';
        toast('Stored (encrypted).');
        render();
      }));
      srv.append(
        el('p', { class: 'small muted' }, 'Use your key from any device. It is encrypted here with your passphrase before upload. The risk: if your hosting were ever broken into, someone could try to guess the passphrase, or change this page to capture it — so use a long, unique passphrase.'),
        S.has_password ? '' : el('div', { class: 'notice warn' }, 'Needs a fallback password (below): on a new device you sign in with it first.'),
        el('div', { class: 'grid2' }, p1, p2), el('div', {}, up));
    }
  })().catch(e => dev.append(el('div', { class: 'notice bad' }, e.message)));
  return box;
}

function renderSettings(root) {
  const I = S.identity;
  root.append(updatesCard(), keyStorageCard());

  // Reachability
  const reachOut = el('div');
  const reach = el('button', { class: 'btn', type: 'button' }, 'Test now');
  reach.addEventListener('click', () => busy(reach, async () => {
    const r = await api('reach', { helper: S.reach_helper });
    const res = r.result;
    reachOut.replaceChildren(res.ok
      ? el('div', { class: 'notice ok mt' }, (r.self ? 'This server' : r.helper) + ' fetched and verified your Seal ID' + (res.mirror ? ' (from a mirror)' : '') + '.')
      : el('div', { class: 'notice bad mt stack' }, el('div', {}, (r.self ? 'This server' : r.helper) + ' could NOT reach your Seal ID: ' + (res.error || 'unknown error')),
        res.blocked ? el('div', {}, 'Your host’s security system is blocking automated requests. Add a mirror below (e.g. a GitHub repository or GitHub Pages) so others can still verify you.') : null,
        el('ul', { class: 'small' }, (res.attempts || []).map(a => el('li', {}, a.source + ' — ' + a.result)))));
  }));
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Can other Seal IDs reach you?'),
    el('p', { class: 'small muted' }, 'Asks ' + S.reach_helper + ' to fetch and verify your Seal ID from the outside, the way any other installation would.'),
    reach, reachOut));

  // DNS
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'DNS key record (recommended)'),
    el('p', { class: 'small muted' }, 'A TXT record lets anyone confirm your key even if your web host blocks automated requests, and stops anyone from swapping your key unnoticed.'),
    el('dl', { class: 'kv' }, el('dt', {}, 'Name'), el('dd', { class: 'mono' }, S.dns.name), el('dt', {}, 'Type'), el('dd', {}, 'TXT')),
    copyBox(S.dns.value),
    el('div', { class: 'notice ' + (S.dns.ok ? 'ok' : 'warn') }, S.dns.ok ? 'Found and matches your key.' : (S.dns.current ? 'Found, but it does not match: ' + S.dns.current : 'Not found yet.'))));

  // Mirrors
  const mta = el('textarea', { placeholder: 'https://raw.githubusercontent.com/you/seal-id/main/seal-id.json' });
  mta.value = S.mirrors.join('\n');
  const msave = el('button', { class: 'btn primary', type: 'button' }, 'Sign mirror list');
  msave.addEventListener('click', () => busy(msave, async () => {
    const r = await signStatement({ type: 'mirrors', urls: mta.value.split(/\s+/).filter(Boolean) }, 'Update your mirrors');
    if (r) { render(); toast('Saved. Update your DNS record too.'); }
  }));
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Mirrors'),
    el('p', { class: 'small muted' }, 'Copies of your bundle somewhere else, used when your own site can’t be reached. Copies can’t be forged — everything in them is signed — but they must be refreshed by hand when your identity changes.'),
    el('div', { class: 'row wrapline' }, el('a', { class: 'btn small', href: '.well-known/seal-id.json', download: 'seal-id.json' }, 'Download bundle (seal-id.json)'),
      S.bundle_ok ? null : el('span', { class: 'small faint' }, 'Static file missing — check folder permissions.')),
    el('div', { class: 'field' }, el('label', {}, 'Mirror addresses (one per line)'), mta), msave));

  // Key
  const kta = el('textarea', { placeholder: '-----BEGIN PGP PUBLIC KEY BLOCK-----' });
  const ksave = el('button', { class: 'btn', type: 'button' }, 'Replace stored public key');
  ksave.addEventListener('click', () => busy(ksave, async () => { await api('update_key', { key: kta.value }); render(); toast('Key updated.'); }));
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Your key'),
    el('dl', { class: 'kv' }, el('dt', {}, 'Fingerprint'), el('dd', { class: 'mono' }, fpGroups(I.fp)), el('dt', {}, 'Algorithm'), el('dd', {}, I.algo),
      I.reset_from ? [el('dt', {}, 'Replaced key'), el('dd', { class: 'mono' }, fpGroups(I.reset_from))] : null),
    el('p', { class: 'small muted' }, 'After adding a subkey or extending the expiry date, paste the updated PUBLIC key here (same fingerprint).'),
    kta, ksave));

  // Password
  const pw = el('input', { type: 'password', autocomplete: 'new-password', placeholder: S.has_password ? 'New password (empty = remove)' : 'At least 10 characters' });
  const psave = el('button', { class: 'btn', type: 'button' }, S.has_password ? 'Change / remove password' : 'Set password');
  psave.addEventListener('click', () => busy(psave, async () => { await api('password', { password: pw.value }); pw.value = ''; render(); toast('Saved.'); }));
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Fallback password'),
    el('p', { class: 'small muted' }, S.has_password ? 'A fallback password is set.' : 'No password: you sign in with your key only.'),
    pw, psave));

  // Pins
  root.append(el('div', { class: 'card stack' }, el('h2', {}, 'Seal IDs you have seen'),
    S.pins.length ? el('ul', { class: 'vlist' }, S.pins.map(p => el('li', {}, el('a', { href: p.url, target: '_blank', rel: 'noopener' }, p.name || p.url),
      el('div', { class: 'tiny muted' }, p.url + ' · key …' + p.fp.slice(-16) + ' · ' + ago(p.last_seen))))) : el('p', { class: 'small muted' }, 'None yet.')));
}

/* ------------------------------------------------------------------ */
if (D.broken) app.replaceChildren(el('div', { class: 'notice bad' }, 'Your chain failed verification: ' + D.broken));
else if (!D.admin) renderLogin();
else load().catch(e => app.replaceChildren(el('div', { class: 'notice bad' }, e.message)));
