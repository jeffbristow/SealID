// Seal ID — public profile: ask the server to re-check stale proofs and
// update the badges in place (the page itself never waits for checks).
const badge = (status, label, detail) => {
  const s = document.createElement('span');
  s.className = 'badge s-' + status;
  s.title = detail || '';
  s.textContent = label;
  return s;
};

fetch('api.php?a=status', { headers: { Accept: 'application/json' } })
  .then(r => r.ok ? r.json() : null)
  .then(j => {
    if (!j || !j.proofs) return;
    for (const p of j.proofs) {
      const li = document.querySelector('.proof[data-seq="' + p.seq + '"]');
      if (!li) continue;
      const b = li.querySelector('.js-badge');
      if (b) b.replaceChildren(badge(p.status, p.label, p.detail));
      const d = li.querySelector('.js-detail');
      if (d) d.textContent = p.detail;
    }
  })
  .catch(() => {});
