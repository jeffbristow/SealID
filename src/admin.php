<?php
/**
 * Seal ID — the owner's admin page. The page is a shell; admin.js talks to
 * the JSON actions below (?a=…, POST, X-CSRF header).
 *
 * Anything that changes the identity is a statement the owner signs; the
 * server builds the exact payload ("prepare"), keeps it in the session and
 * appends it only when a valid signature comes back ("append").
 */
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';
start_session();

if (!is_installed()) {
    header('Location: setup.php');
    exit;
}
if (!is_https() && !is_local_dev()) {
    header('Location: https://' . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '/'));
    exit;
}

$st = Chain::state();
$isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';

if ($isPost) {
    csrf_check();
    $a = (string)($_GET['a'] ?? '');
    $b = body_json($a === 'avatar_upload' ? 8 * 1048576 : 262144);
    try {
        if (!empty($st['broken'])) fail(500, 'Your chain failed verification: ' . $st['broken']);

        // ---------------- Sign-in (no session needed) ----------------
        if ($a === 'challenge') {
            $payload = json_encode(['seal_id_login' => $st['url'], 'nonce' => bin2hex(random_bytes(16)), 'ts' => time()], JSON_UNESCAPED_SLASHES);
            $_SESSION['challenge'] = ['payload' => $payload, 'at' => time()];
            json_out(['ok' => true, 'payload' => $payload, 'fp' => $st['fp']]);
        }
        if ($a === 'login') {
            if (!rate_limit('login', 10, 900)) fail(429, 'Too many attempts. Wait 15 minutes.');
            $ok = false;
            if (isset($b['sig'])) {
                $c = $_SESSION['challenge'] ?? null;
                unset($_SESSION['challenge']);
                if (!$c || time() - $c['at'] > 600) fail(400, 'The sign-in challenge expired. Try again.');
                $v = Pgp::verifyAny($c['payload'], (string)$b['sig'], $st['parsed_key']);
                if (!$v['ok']) fail(403, 'Signature not accepted: ' . $v['error']);
                $ok = true;
            } elseif (isset($b['password'])) {
                $auth = jread('auth.json', []);
                if (empty($auth['password'])) fail(403, 'No fallback password is set. Sign in with your key.');
                $ok = password_verify((string)$b['password'], $auth['password']);
                if (!$ok) fail(403, 'Wrong password.');
            }
            if (!$ok) fail(400, 'Nothing to sign in with.');
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            $_SESSION['admin_fp'] = $st['fp'];
            json_out(['ok' => true, 'csrf' => csrf_token()]);
        }

        if (!is_admin()) fail(401, 'Please sign in again.');

        switch ($a) {
            case 'logout':
                $_SESSION = [];
                session_destroy();
                json_out(['ok' => true]);

            case 'state':
                json_out(['ok' => true] + admin_state());

            // ---------------- Signed statements ----------------
            case 'prepare':
                $payload = admin_prepare($b, $st);
                $_SESSION['pending'][Chain::hash($payload)] = $payload;
                if (count($_SESSION['pending']) > 20) $_SESSION['pending'] = array_slice($_SESSION['pending'], -20, null, true);
                json_out(['ok' => true, 'payload' => $payload, 'fp' => $st['fp']]);

            case 'append':
                $payload = (string)($b['payload'] ?? '');
                if (!isset($_SESSION['pending'][Chain::hash($payload)])) fail(400, 'That statement was not prepared here (or expired). Start again.');
                try {
                    $new = Chain::append($payload, (string)($b['sig'] ?? ''));
                } catch (ChainError $e) {
                    fail(400, preg_replace('/^Link \d+: /', '', $e->getMessage()));
                }
                unset($_SESSION['pending'][Chain::hash($payload)]);
                $p = json_decode($payload, true);
                $extra = [];
                if ($p['type'] === 'vouch') {
                    if (isset($_SESSION['peer'][$p['body']['target']])) peer_pin_save($_SESSION['peer'][$p['body']['target']]);
                    $extra['notify'] = vouch_notify($p['body']['target'], $p['seq']);
                }
                if ($p['type'] === 'profile') {
                    avatar_commit($p['body']['avatar'] ?? null);
                    Chain::writeBundle();
                }
                if ($p['type'] === 'proof') {
                    $extra['proof'] = admin_instructions($p['seq']);
                    if (!proof_service($p['body']['service'])::LOCATOR) own_recheck(1, true, $p['seq']);
                }
                json_out(['ok' => true, 'seq' => $p['seq'], 'type' => $p['type']] + $extra + admin_state());

            // ---------------- Proof helpers ----------------
            case 'instructions':
                json_out(['ok' => true, 'proof' => admin_instructions((int)($b['seq'] ?? 0))]);

            case 'locator':
                $seq = (int)($b['seq'] ?? 0);
                $p = $st['proofs'][$seq] ?? null;
                if (!$p) fail(404, 'No such proof.');
                $cls = proof_service($p['service']);
                $u = $cls ? $cls::locatorOk($p['handle'], (string)($b['url'] ?? '')) : null;
                if ($u === null) fail(400, 'That address is not a ' . ($cls ? $cls::LABEL : '') . ' post by ' . $p['handle'] . '. Expected something like ' . ($cls ? $cls::locatorHint($p['handle']) : '') . '.');
                with_lock(function () use ($seq, $u) {
                    $l = jread('locators.json', []);
                    $l[(string)$seq] = $u;
                    jwrite('locators.json', $l);
                });
                if ($cls::AUTO) own_recheck(1, true, $seq); else Chain::writeBundle();
                json_out(['ok' => true] + admin_state());

            case 'recheck':
                $seq = isset($b['seq']) ? (int)$b['seq'] : null;
                own_recheck($seq ? 1 : 20, true, $seq);
                json_out(['ok' => true] + admin_state());

            // ---------------- Other Seal IDs ----------------
            case 'peer':
                $url = Chain::normUrl((string)($b['url'] ?? ''));
                if ($url === null) fail(400, 'Enter a Seal ID address, e.g. id.example.com');
                if ($url === $st['url']) fail(400, 'That is your own Seal ID.');
                if (!rate_limit('peer', 30, 3600)) fail(429, 'Too many checks. Wait a while.');
                $r = peer_lookup($url, true);           // 1.2.0: also accepts verified alias domains
                if ($r['ok'] && $r['url'] === $st['url']) fail(400, 'That domain is an alias of your own Seal ID.');
                if ($r['ok']) {
                    $_SESSION['peer'][$r['url']] = $r;
                    if ($r['pin'] === 'new' || $r['pin'] === 'match') peer_pin_save($r);
                }
                json_out(['ok' => true, 'report' => $r]);

            case 'peer_accept':
                $url = Chain::normUrl((string)($b['url'] ?? ''));
                if ($url === null) fail(400, 'Bad address.');
                @unlink(data_dir() . '/' . peer_pin_file($url));
                json_out(['ok' => true]);

            case 'import_vouch':
                $r = vouch_import((string)($b['url'] ?? ''));
                if (!$r['ok']) fail(422, $r['error']);
                json_out(['ok' => true] + admin_state());

            case 'notify':
                $seq = (int)($b['seq'] ?? 0);
                $v = $st['vouches'][$seq] ?? null;
                if (!$v) fail(404, 'No such vouch.');
                json_out(['ok' => true, 'notify' => vouch_notify($v['target'], $seq)] + admin_state());

            // ---------------- Profile picture ----------------
            case 'avatar_upload':
                if (!preg_match('#^data:image/[a-z+.-]+;base64,(.+)$#s', (string)($b['image'] ?? ''), $m)) fail(400, 'Choose a picture.');
                $bytes = base64_decode($m[1], true);
                if ($bytes === false) fail(400, 'That picture could not be read.');
                try { $r = avatar_store_pending($bytes); } catch (RuntimeException $e) { fail(400, $e->getMessage()); }
                json_out(['ok' => true] + $r);

            // ---------------- Saved key: encrypted copy on this server (1.2.0, option B) ----------------
            // The browser encrypts the private key (PBKDF2-SHA256 600k + AES-256-GCM) before
            // sending it; the server only stores and returns that blob, to a signed-in owner.
            case 'keystore_get':
                json_out(['ok' => true, 'blob' => jread('keystore.json', null)]);

            case 'keystore_put':
                $blob = $b['blob'] ?? null;
                $b64 = fn($v, $min, $max) => is_string($v) && strlen($v) >= $min && strlen($v) <= $max && base64_decode($v, true) !== false;
                if (!is_array($blob) || ($blob['v'] ?? 0) !== 1 || ($blob['fp'] ?? '') !== $st['fp'] || ($blob['kdf'] ?? '') !== 'pbkdf2-sha256'
                    || !is_int($blob['iter'] ?? null) || $blob['iter'] < 600000 || $blob['iter'] > 10000000
                    || !$b64($blob['salt'] ?? null, 16, 64) || !$b64($blob['iv'] ?? null, 16, 32) || !$b64($blob['ct'] ?? null, 100, 400000)) {
                    fail(400, 'That is not an encrypted key copy made by this page.');
                }
                if (empty(jread('auth.json', [])['password'])) fail(400, 'Set a fallback password first (below): on a new device you sign in with it, then unlock the copy with its passphrase.');
                jwrite('keystore.json', ['v' => 1, 'fp' => $blob['fp'], 'kdf' => 'pbkdf2-sha256', 'iter' => $blob['iter'],
                    'salt' => $blob['salt'], 'iv' => $blob['iv'], 'ct' => $blob['ct'], 'created' => time()]);
                json_out(['ok' => true] + admin_state());

            case 'keystore_delete':
                @unlink(data_dir() . '/keystore.json');
                json_out(['ok' => true] + admin_state());

            // ---------------- Updates ----------------
            case 'update_status':
                json_out(['ok' => true, 'update' => up_state(up_check(false))]);

            case 'update_check':
                $c = jread('update/check.json', []);
                json_out(['ok' => true, 'update' => up_state(up_check(time() - (int)($c['checked'] ?? 0) >= 60))]);

            case 'update_install':
                [$ok, $msg] = up_install();
                if (!$ok) json_out(['ok' => false, 'error' => $msg, 'update' => up_state()], 409);
                json_out(['ok' => true, 'message' => $msg, 'update' => up_state()]);

            case 'update_undo':
                [$ok, $msg] = up_restore();
                if (!$ok) json_out(['ok' => false, 'error' => $msg, 'update' => up_state()], 409);
                json_out(['ok' => true, 'message' => $msg, 'update' => up_state()]);

            // ---------------- Settings ----------------
            case 'update_key':
                try { Chain::updateKey((string)($b['key'] ?? '')); } catch (ChainError | PgpError $e) { fail(400, $e->getMessage()); }
                json_out(['ok' => true] + admin_state());

            case 'password':
                $pw = (string)($b['password'] ?? '');
                if ($pw !== '' && strlen($pw) < 10) fail(400, 'Use at least 10 characters.');
                jwrite('auth.json', $pw !== '' ? ['password' => password_hash($pw, PASSWORD_DEFAULT)] : []);
                json_out(['ok' => true] + admin_state());

            case 'reach':
                $helper = Chain::normUrl((string)($b['helper'] ?? cfg('reach_helper', 'https://id.bristow.ch')));
                if ($helper === null) fail(400, 'Bad helper address.');
                if ($helper === $st['url']) {
                    $r = peer_verify($st['url'], false);
                    json_out(['ok' => true, 'self' => true, 'result' => ['ok' => $r['ok'], 'error' => $r['error'], 'attempts' => $r['attempts'], 'blocked' => $r['blocked'], 'source' => $r['source'] ?? null]]);
                }
                $r = http_fetch($helper . '/api.php?a=reach', ['method' => 'POST', 'body' => json_encode(['url' => $st['url']]), 'headers' => ['Content-Type: application/json'], 'timeout' => 40]);
                $j = json_decode($r['body'] ?? '', true);
                if (!is_array($j)) fail(502, 'The helper ' . $helper . ' did not answer (' . ($r['status'] ? 'HTTP ' . $r['status'] : $r['error']) . ').');
                json_out(['ok' => true, 'helper' => $helper, 'result' => $j]);

            default:
                fail(400, 'Unknown action.');
        }
    } catch (Throwable $e) {
        error_log('Seal ID admin: ' . $e->getMessage() . ' @' . $e->getFile() . ':' . $e->getLine());
        fail(500, 'Server error: ' . $e->getMessage());
    }
}

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

function admin_prepare(array $b, array $st): string
{
    $type = (string)($b['type'] ?? '');
    switch ($type) {
        case 'profile':
            $name = trim((string)($b['name'] ?? ''));
            $bio = trim((string)($b['bio'] ?? ''));
            if ($name === '' || mb_strlen($name) > 80) fail(400, 'Enter a display name (up to 80 characters).');
            if (mb_strlen($bio) > 500) fail(400, 'The bio can be up to 500 characters.');
            $body = ['name' => $name, 'bio' => $bio];
            $av = $b['avatar'] ?? null;
            if ($av !== null) {
                if (!is_string($av) || !preg_match('/^[0-9a-f]{64}$/', $av) || !avatar_known($av)) fail(400, 'Upload the picture again.');
                $body['avatar'] = $av;
            }
            return Chain::nextPayload('profile', $body);

        case 'proof':
            $cls = proof_service((string)($b['service'] ?? ''));
            if (!$cls) fail(400, 'Choose a service.');
            $handle = $cls::normalize((string)($b['handle'] ?? ''));
            if ($handle === null) fail(400, 'That doesn’t look like a ' . $cls::LABEL . ' name. Example: ' . $cls::HANDLE_HINT);
            foreach ($st['proofs'] as $p) {
                if ($p['service'] === $cls::ID && strcasecmp($p['handle'], $handle) === 0) fail(400, 'You already have a proof for ' . $handle . '. Revoke it first to make a new one.');
            }
            return Chain::nextPayload('proof', ['service' => $cls::ID, 'handle' => $handle]);

        case 'revoke':
            $seqs = array_values(array_unique(array_map('intval', (array)($b['seqs'] ?? []))));
            foreach ($seqs as $s) {
                if (!isset($st['proofs'][$s]) && !isset($st['vouches'][$s]) && ($st['mirrors_seq'] ?? 0) !== $s) fail(400, 'Nothing to revoke at #' . $s . '.');
            }
            if (!$seqs) fail(400, 'Nothing selected.');
            return Chain::nextPayload('revoke', ['seqs' => $seqs]);

        case 'mirrors':
            $urls = [];
            foreach ((array)($b['urls'] ?? []) as $u) {
                $u = trim((string)$u);
                if ($u === '') continue;
                if (!preg_match('#^https://[^\s]{4,300}$#', $u)) fail(400, 'Mirror addresses must start with https:// — ' . $u);
                $urls[] = $u;
            }
            if (count($urls) > 10) fail(400, 'Up to 10 mirrors.');
            return Chain::nextPayload('mirrors', ['urls' => array_values(array_unique($urls))]);

        case 'vouch':
            $target = Chain::normUrl((string)($b['target'] ?? ''));
            $r = $_SESSION['peer'][$target] ?? null;
            if (!$target || !$r) fail(400, 'Check that Seal ID first.');
            if ($r['pin'] === 'changed') fail(400, 'That identity changed since you last saw it. Accept the change first.');
            $chosen = [];
            $how = (array)($b['proofs'] ?? []);
            foreach ($r['proofs'] as $p) {
                $h = $how[(string)$p['seq']] ?? null;
                if ($h === 'auto' && $p['status'] !== 'verified') fail(400, $p['label'] . ' ' . $p['handle'] . ' did not verify automatically — only vouch for it if you witnessed it yourself.');
                if ($h === 'auto' || $h === 'witnessed') $chosen[] = ['seq' => $p['seq'], 'service' => $p['service'], 'handle' => $p['handle'], 'how' => $h];
            }
            return Chain::nextPayload('vouch', [
                'target' => $target, 'target_fp' => $r['fp'], 'target_seq' => $r['seq'], 'target_hash' => $r['hash'], 'proofs' => $chosen,
            ]);
    }
    fail(400, 'Unknown statement type.');
}

function admin_instructions(int $seq): array
{
    $st = Chain::state();
    $p = $st['proofs'][$seq] ?? null;
    if (!$p) fail(404, 'No such proof.');
    $cls = proof_service($p['service']);
    $text = Chain::proofText($st['url'], $p['token']);
    $publish = $cls ? $cls::publishText($text, $p['token']) : $text;
    return [
        'seq' => $seq,
        'service' => $p['service'],
        'label' => $cls ? $cls::LABEL : $p['service'],
        'handle' => $p['handle'],
        'token' => $p['token'],
        'text' => $publish,
        'steps' => $cls ? $cls::steps($p['handle'], $publish, $p['token']) : [],
        'needs_locator' => $cls ? $cls::LOCATOR : false,
        'locator_hint' => $cls ? $cls::locatorHint($p['handle']) : '',
    ];
}

function admin_state(): array
{
    $st = Chain::state(true);
    $services = [];
    foreach (proof_services() as $id => $cls) {
        $services[] = ['id' => $id, 'label' => $cls::LABEL, 'hint' => $cls::HANDLE_HINT, 'auto' => $cls::AUTO, 'locator' => $cls::LOCATOR];
    }
    $outbox = jread('outbox.json', []);
    $given = [];
    foreach (array_reverse($st['vouches'], true) as $seq => $v) {
        $given[] = $v + ['notify' => $outbox[(string)$seq] ?? null];
    }
    $host = parse_url($st['url'], PHP_URL_HOST);
    $dnsVal = 'v=sealid1; id=' . $st['url'] . '; fp=' . $st['fp'] . implode('', array_map(fn($m) => '; mirror=' . $m, $st['mirrors']));
    $dnsNow = peer_dns($st['url']);
    $auth = jread('auth.json', []);
    return [
        'identity' => [
            'url' => $st['url'], 'name' => $st['name'], 'bio' => $st['bio'], 'fp' => $st['fp'],
            'avatar' => $st['avatar'] ?? null, 'avatar_url' => avatar_url(),
            'algo' => Pgp::algoName($st['parsed_key']['primary']), 'seq' => $st['seq'], 'created' => $st['created'],
            'reset_from' => $st['reset_from'], 'fps' => $st['fps'],
        ],
        'proofs' => own_proofs(),
        'services' => $services,
        'given' => $given,
        'received' => jread('vouches.json', []),
        'mirrors' => $st['mirrors'],
        'mirrors_seq' => $st['mirrors_seq'] ?? 0,
        'pins' => array_map(fn($p) => ['url' => $p['url'], 'name' => $p['name'] ?? '', 'fp' => $p['fp'], 'last_seen' => $p['last_seen'] ?? 0], peer_pins()),
        'dns' => ['name' => '_seal-id.' . $host, 'value' => $dnsVal, 'current' => $dnsNow['raw'] ?? null, 'ok' => ($dnsNow['fp'] ?? null) === $st['fp']],
        'has_password' => !empty($auth['password']),
        'keystore' => ($ks = jread('keystore.json', null)) ? ['created' => $ks['created'] ?? 0, 'fp' => $ks['fp'] ?? null] : null,
        'reach_helper' => cfg('reach_helper', 'https://id.bristow.ch'),
        'bundle_ok' => is_file(SEALID_ROOT . '/.well-known/seal-id.json'),
        'version' => up_current(),
        'update' => up_state(),
    ];
}

/* -------------------------------------------------------------------------
 * Page shell
 * ------------------------------------------------------------------------- */
page_start('Seal ID admin', ['noindex' => true, 'wasm' => true, 'nav' => '<a href="./">View profile</a>']);
echo '<main class="wrap section"><div id="app"><p class="muted">Loading…</p></div></main>';
page_end(['admin.js'], [
    'csrf' => csrf_token(),
    'admin' => is_admin(),
    'url' => $st['url'] ?? null,
    'fp' => $st['fp'] ?? null,
    'name' => $st['name'] ?? '',
    'has_password' => !empty(jread('auth.json', [])['password']),
    'broken' => $st['broken'] ?? null,
]);
