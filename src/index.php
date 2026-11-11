<?php
/**
 * Seal ID — public profile page.
 */
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';

if (!is_installed()) {
    page_start('Seal ID', ['noindex' => true]);
    echo '<main class="wrap section"><div class="card stack narrow-card">'
        . '<img src="assets/seal-id.svg" alt="" width="96" height="96">'
        . '<h1>Seal ID is installed</h1>'
        . '<p class="muted">This identity has not been set up yet.</p>';
    if (has_config()) {
        echo '<p><a class="btn primary" href="setup.php">Set up this Seal ID</a></p>';
    } else {
        echo '<div class="notice warn">Copy <code>config.example.php</code> to <code>config.php</code>, change the <code>setup_code</code> in it, then reload this page.</div>';
    }
    echo '</div></main>';
    page_end();
    exit;
}

$st = Chain::state();
if (!empty($st['broken'])) {
    page_start('Seal ID', ['noindex' => true]);
    echo '<main class="wrap section"><div class="notice bad">This Seal ID’s chain failed verification: ' . h($st['broken']) . '</div></main>';
    page_end();
    exit;
}

$proofs = own_proofs();
$received = jread('vouches.json', []);
$given = array_reverse(array_values($st['vouches']));
$name = $st['name'] !== '' ? $st['name'] : parse_url($st['url'], PHP_URL_HOST);
$verifiedCount = count(array_filter($proofs, fn($p) => in_array($p['status'], ['verified', 'witnessed'], true)));

page_start($name . ' — Seal ID', [
    'description' => $name . ' on Seal ID: ' . $verifiedCount . ' verified proofs, key ' . substr($st['fp'], -16) . '.',
    'head' => '<link rel="alternate" type="application/json" href=".well-known/seal-id.json">',
    'nav' => '<a href="api.php?a=key">Public key</a><a href="admin.php" class="btn small ghost">Owner</a>',
]);
?>
<main>
<section class="hero">
  <div class="wrap">
    <div class="idcard">
      <?= avatar_html(avatar_url(), $name) ?>
      <div class="grow">
        <h1><?= h($name) ?></h1>
        <div class="idurl"><?= h($st['url']) ?></div>
        <?php if ($aliases = own_aliases()): ?><div class="small muted aliases">Also: <?= implode(' · ', array_map(fn($d) => '<a href="https://' . h($d) . '" rel="me noopener" target="_blank">' . (($fi = favicon_url($d)) ? '<img class="alias-ico" src="' . h($fi) . '" alt="">' : '') . h($d) . '</a>', $aliases)) ?></div><?php endif; ?>
        <?php if ($st['bio'] !== ''): ?><p class="muted bio"><?= nl2br(h($st['bio'])) ?></p><?php endif; ?>
      </div>
    </div>
    <div class="keyrow">
      <span class="badge s-verified">OpenPGP key</span>
      <?= fp_html($st['fp']) ?>
      <span class="small faint"><?= h(Pgp::algoName($st['parsed_key']['primary'])) ?></span>
      <a class="small" href="api.php?a=key">Download</a>
    </div>
  </div>
</section>

<div class="wrap">
  <div class="card section">
    <div class="row between"><h2>Proofs</h2><span class="small faint" id="checked-note">Each proof is re-checked regularly by this server — and by anyone else’s Seal ID.</span></div>
    <?php if (!$proofs): ?>
      <p class="muted">No proofs yet.</p>
    <?php else: ?>
    <ul class="proofs">
      <?php foreach ($proofs as $p): ?>
      <li class="proof" data-seq="<?= (int)$p['seq'] ?>">
        <div class="svc svc-<?= h($p['service']) ?>" title="<?= h($p['label']) ?>"><?= service_icon($p['service'], $p['favicon'] ?? null) ?></div>
        <div class="grow">
          <div class="row wrapline gap-sm">
            <span class="who"><?php if ($p['service'] === 'sealchat'): ?><?= sealchat_handle_html($p['handle']) ?><?php elseif ($p['profile']): ?><a href="<?= h($p['profile']) ?>" target="_blank" rel="noopener nofollow"><?= h($p['handle']) ?></a><?php else: ?><?= h($p['handle']) ?><?php endif; ?></span>
            <span class="small muted"><?= h($p['label']) ?></span>
            <span class="js-badge"><?= status_badge($p['status'], $p['detail']) ?></span>
          </div>
          <div class="meta">
            <span class="js-detail"><?= h($p['detail']) ?></span>
            <?php if ($p['locator']): ?> · <a href="<?= h($p['locator']) ?>" target="_blank" rel="noopener nofollow">proof post</a><?php endif; ?>
            <?php if ($p['witnesses']): ?> · witnessed by <?= count($p['witnesses']) ?> Seal ID<?= count($p['witnesses']) === 1 ? '' : 's' ?><?php endif; ?>
            <?php if ($p['vouchers']): ?> · vouched for by <?= count($p['vouchers']) ?><?php endif; ?>
          </div>
        </div>
      </li>
      <?php endforeach; ?>
    </ul>
    <?php endif; ?>
  </div>

  <div class="grid2 section">
    <div class="card">
      <h2>Verified by</h2>
      <?php if (!$received): ?>
        <p class="muted small">No other Seal IDs have vouched for this one yet.</p>
      <?php else: ?>
      <ul class="vlist">
        <?php foreach ($received as $v): ?>
        <li class="row">
          <?= avatar_html($v['avatar'] ?? null, (string)($v['name'] ?? ''), 'avatar sm') ?>
          <div class="grow">
            <a href="<?= h($v['url']) ?>" target="_blank" rel="noopener"><?= h($v['name'] !== '' ? $v['name'] : $v['url']) ?></a>
            <div class="tiny muted"><?= h($v['url']) ?> · <?= h(ago((int)$v['ts'])) ?> · confirmed <?= count($v['proofs']) ?> proof<?= count($v['proofs']) === 1 ? '' : 's' ?></div>
          </div>
        </li>
        <?php endforeach; ?>
      </ul>
      <?php endif; ?>
    </div>
    <div class="card">
      <h2>Has verified</h2>
      <?php if (!$given): ?>
        <p class="muted small">This Seal ID hasn’t vouched for anyone yet.</p>
      <?php else: ?>
      <ul class="vlist">
        <?php foreach ($given as $v): ?>
        <li>
          <a href="<?= h($v['target']) ?>" target="_blank" rel="noopener"><?= h($v['target']) ?></a>
          <div class="tiny muted"><?= h(ago((int)$v['ts'])) ?> · <?= count($v['proofs']) ?> proof<?= count($v['proofs']) === 1 ? '' : 's' ?> confirmed · key <?= h(substr($v['target_fp'], -16)) ?></div>
        </li>
        <?php endforeach; ?>
      </ul>
      <?php endif; ?>
    </div>
  </div>

  <div class="card section">
    <h2>Check this yourself</h2>
    <p class="muted small">Nothing on this page has to be taken on trust. Every claim is a statement signed by the key above, in an append-only chain:
      <a href=".well-known/seal-id.json"><code>.well-known/seal-id.json</code></a> (<?= (int)$st['seq'] ?> signed statements, last <?= h(ago((int)$st['updated'])) ?>).</p>
    <p class="muted small">If you run your own Seal ID, open its admin page, choose <b>Vouch</b> and enter <code><?= h($st['url']) ?></code>: your server will verify the signatures and re-check every proof itself.</p>
  </div>
</div>
</main>
<?php
page_end(['profile.js']);
