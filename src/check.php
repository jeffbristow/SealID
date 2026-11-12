<?php
/**
 * Seal ID — public checker (1.5.0).
 *   check.php?q=example.com       whose Seal ID is this domain?
 *   check.php?q=https://id.x.com  is this a valid Seal ID, and what does it prove?
 * Works without JavaScript (a plain GET form); results are shareable links.
 * The work is done by lib/check.php (cache + rate limits) and peer_lookup().
 */
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';

if (!is_installed()) { header('Location: ./'); exit; }
$st = Chain::state();
$q = trim((string)($_GET['q'] ?? ''));
$on = check_enabled();
$res = ($q !== '' && $on) ? check_lookup($q) : null;
if ($res && $res['verdict'] === 'busy') http_response_code(429);

$owner = $st['name'] !== '' ? $st['name'] : parse_url($st['url'], PHP_URL_HOST);
page_start($q !== '' ? 'Check ' . $q . ' — Seal ID' : 'Check a Seal ID', [
    'noindex' => $q !== '',
    'description' => 'Check whether a domain or Seal ID page address is a valid Seal ID, and whose it is.',
    'nav' => '<a href="./">' . h($owner) . '’s Seal ID</a>',
]);

/** The symbol and colour class for a verdict. */
function verdict_style(string $v): array
{
    return match ($v) {
        'valid' => ['✔', 'ok'],
        'not_confirmed', 'invalid' => ['⛔', 'bad'],
        'unreachable', 'busy' => ['⚠', 'warn'],
        default => ['–', 'none'],
    };
}
?>
<main class="wrap section">
  <div class="card stack check-card">
    <h1>Check a Seal ID</h1>
    <p class="muted">Type a domain (like <code>example.com</code>) or the address of someone’s Seal ID page (like <code>id.example.com</code>). This server fetches it, checks every signature and re-checks its proofs, then tells you whose Seal ID it is or whether something is wrong.</p>
    <?php if (!$on): ?>
      <div class="notice warn">The owner of this Seal ID has turned the public checker off.</div>
    <?php else: ?>
    <form class="check-form" method="get" action="check.php" role="search">
      <label for="q" class="sr-only">Domain or Seal ID page address</label>
      <input type="text" id="q" name="q" value="<?= h($q) ?>" placeholder="example.com or id.example.com" autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="url" maxlength="200" required>
      <button class="btn primary" type="submit">Check</button>
    </form>
    <p class="tiny faint">Checks can take a few seconds. Results are kept for up to 10 minutes.</p>
    <?php endif; ?>
  </div>

<?php if ($res): [$sym, $cls] = verdict_style($res['verdict']); ?>
  <section class="card stack section verdict verdict-<?= h($cls) ?>" aria-live="polite">
    <div class="verdict-head">
      <span class="verdict-sym" aria-hidden="true"><?= $sym ?></span>
      <div class="grow">
        <h2><?= h($res['title']) ?></h2>
        <div class="small muted">for <b><?= h($res['query']) ?></b><?= $res['checked_url'] && $res['checked_url'] !== 'https://' . $res['query'] ? ' (' . h($res['checked_url']) . ')' : '' ?></div>
      </div>
    </div>
    <?php if ($res['message'] !== ''): ?><p><?= h($res['message']) ?></p><?php endif; ?>

    <?php if ($res['verdict'] === 'valid'): $who = $res['name'] !== '' ? $res['name'] : parse_url($res['url'], PHP_URL_HOST); ?>
      <div class="idcard check-id">
        <?= avatar_html($res['avatar'], $who) ?>
        <div class="grow">
          <div class="who-name"><?= h($who) ?></div>
          <a class="idurl" href="<?= h($res['url']) ?>/" target="_blank" rel="noopener nofollow"><?= h($res['url']) ?></a>
          <?php if ($res['alias']): ?><div class="small muted">Linked domain: <b><?= h($res['alias']) ?></b> — <?= $res['alias_how'] === 'dns' ? 'DNS record' : 'proof file on the website' ?>, confirmed by the Seal ID</div><?php endif; ?>
          <?php if ($res['bio'] !== ''): ?><p class="small muted bio"><?= nl2br(h($res['bio'])) ?></p><?php endif; ?>
        </div>
      </div>
      <div class="keyrow"><span class="small muted">OpenPGP key</span> <?= fp_html($res['fp']) ?> <span class="small faint"><?= h($res['algo']) ?></span></div>

      <?php foreach ($res['warnings'] as $w): ?><div class="notice warn"><?= h($w) ?></div><?php endforeach; ?>

      <h3><?= (int)$res['verified_count'] ?> of <?= count($res['proofs']) ?> proof<?= count($res['proofs']) === 1 ? '' : 's' ?> verified</h3>
      <?php if ($res['proofs']): ?>
      <ul class="proofs">
        <?php foreach ($res['proofs'] as $p): ?>
        <li class="proof">
          <div class="svc svc-<?= h($p['service']) ?>" title="<?= h($p['label']) ?>"><?= service_icon($p['service']) ?></div>
          <div class="grow">
            <div class="row wrapline gap-sm">
              <span class="who"><?php if ($p['service'] === 'sealchat'): ?><?= sealchat_handle_html($p['handle']) ?><?php elseif ($p['profile']): ?><a href="<?= h($p['profile']) ?>" target="_blank" rel="noopener nofollow"><?= h($p['handle']) ?></a><?php else: ?><?= h($p['handle']) ?><?php endif; ?></span>
              <span class="small muted"><?= h($p['label']) ?></span>
              <?= status_badge($p['status'], $p['detail']) ?>
            </div>
            <div class="meta"><?= h($p['detail']) ?></div>
          </div>
        </li>
        <?php endforeach; ?>
      </ul>
      <?php endif; ?>
      <p class="tiny faint">A valid Seal ID proves that one OpenPGP key controls this address and every verified account above. It doesn’t prove a legal name.</p>

    <?php elseif ($res['verdict'] === 'not_confirmed'): ?>
      <div class="notice bad">Someone may be pretending to be that Seal ID’s owner. Don’t rely on <b><?= h($res['query']) ?></b> as proof of who you’re dealing with.<?php if (!empty($res['claimed'])): ?> It claims: <?= implode(', ', array_map(fn($u) => '<code>' . h($u) . '</code>', $res['claimed'])) ?>.<?php endif; ?></div>
    <?php elseif ($res['verdict'] === 'invalid'): ?>
      <div class="notice bad">A Seal ID answered, but its signatures or key don’t check out. It may have been tampered with. Don’t trust it until the owner fixes it.</div>
    <?php elseif ($res['verdict'] === 'unreachable'): ?>
      <div class="notice warn">This doesn’t mean it’s fake: the website blocked or didn’t answer this server. Try again later, or check from another Seal ID.</div>
    <?php elseif ($res['verdict'] === 'none'): ?>
      <p class="small muted">No Seal ID lives at this address, and the domain doesn’t point to one (no proof file and no <code>_seal-id</code> DNS record).</p>
    <?php endif; ?>

    <p class="tiny faint">Checked <?= !empty($res['cached']) ? h(ago((int)$res['checked'])) : 'just now' ?> by <?= h($st['url']) ?>. For a fully independent check, use your own Seal ID or Seal Chat.</p>
  </section>
<?php endif; ?>
</main>
<?php
page_end();
