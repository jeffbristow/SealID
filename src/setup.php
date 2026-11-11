<?php
/**
 * Seal ID — first-run setup (and reset after a lost key, when allowed in config.php).
 * Protected by the setup code in config.php.
 */
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';
start_session();

$resetAllowed = cfg('allow_reset', false) === true;
$code = (string)cfg('setup_code', '');
$codeOk = strlen($code) >= 8 && !str_starts_with($code, 'change-me');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    csrf_check();
    if (is_installed() && !$resetAllowed) fail(403, 'This Seal ID is already set up.');
    if (!$codeOk) fail(403, 'Set a setup_code (8+ characters) in config.php first.');
    $b = body_json();
    try {
        switch ($_GET['a'] ?? '') {
            case 'code':
                if (!rate_limit('setup', 10, 3600)) fail(429, 'Too many attempts. Try again in an hour.');
                if (!hash_equals($code, (string)($b['code'] ?? ''))) fail(403, 'That is not the setup code from config.php.');
                $_SESSION['setup_ok'] = true;
                json_out(['ok' => true]);

            case 'prepare':
                if (empty($_SESSION['setup_ok'])) fail(403, 'Enter the setup code first.');
                $url = Chain::normUrl((string)($b['url'] ?? ''));
                if ($url === null) fail(400, 'That is not a valid https:// address.');
                $name = trim((string)($b['name'] ?? ''));
                $bio = trim((string)($b['bio'] ?? ''));
                if ($name === '' || mb_strlen($name) > 80) fail(400, 'Enter a display name (up to 80 characters).');
                if (mb_strlen($bio) > 500) fail(400, 'The bio can be up to 500 characters.');
                try { $k = Pgp::readKey((string)($b['key'] ?? '')); } catch (PgpError $e) { fail(400, $e->getMessage()); }
                if ($k['revoked']) fail(400, 'That key has been revoked.');
                $body = ['name' => $name, 'bio' => $bio];
                $old = is_installed() ? Chain::state() : [];
                if (!empty($old['fp']) && $old['fp'] !== $k['fp']) $body['reset_from'] = $old['fp'];
                $payload = Chain::nextPayload('eldest', $body, [], $url, $k['fp']);
                $_SESSION['setup_pending'] = ['url' => $url, 'key' => (string)$b['key'], 'payload' => $payload];
                json_out(['ok' => true, 'payload' => $payload, 'fp' => $k['fp'], 'algo' => Pgp::algoName($k['primary']), 'uids' => $k['uids'],
                    'signing_subkeys' => count($k['signers']) - 1, 'reset_from' => $body['reset_from'] ?? null]);

            case 'finish':
                $p = $_SESSION['setup_pending'] ?? null;
                if (empty($_SESSION['setup_ok']) || !$p) fail(403, 'Start again from the beginning.');
                try {
                    $st = Chain::create($p['url'], $p['key'], $p['payload'], (string)($b['sig'] ?? ''));
                } catch (ChainError | PgpError $e) {
                    fail(400, $e->getMessage());
                }
                $pw = (string)($b['password'] ?? '');
                jwrite('auth.json', $pw !== '' ? ['password' => password_hash($pw, PASSWORD_DEFAULT)] : []);
                foreach (['checks.json', 'locators.json', 'vouches.json', 'outbox.json'] as $f) jwrite($f, []);
                unset($_SESSION['setup_pending'], $_SESSION['setup_ok']);
                session_regenerate_id(true);
                $_SESSION['admin'] = true;
                $_SESSION['admin_fp'] = $st['fp'];
                $bundleErr = Chain::writeBundle();
                json_out(['ok' => true, 'url' => $st['url'], 'fp' => $st['fp'], 'bundle_error' => $bundleErr]);

            default:
                fail(400, 'Unknown action.');
        }
    } catch (Throwable $e) {
        error_log('Seal ID setup: ' . $e->getMessage());
        fail(500, 'Server error: ' . $e->getMessage());
    }
}

if (is_installed() && !$resetAllowed) {
    header('Location: admin.php');
    exit;
}

page_start('Set up Seal ID', ['noindex' => true, 'wasm' => true]);
echo '<main class="wrap section"><div class="narrow-card"><div id="app" class="stack">';
if (!has_config() || !$codeOk) {
    echo '<div class="card stack"><h1>Set up Seal ID</h1>'
        . '<div class="notice warn">Before setup: copy <code>config.example.php</code> to <code>config.php</code> on your server and change <code>setup_code</code> to a secret of at least 8 characters. Then reload this page.</div></div>';
}
echo '</div></div></main>';
$old = is_installed() ? Chain::state() : [];
page_end($codeOk ? ['setup.js'] : [], [
    'csrf' => csrf_token(),
    'detected' => detected_base_url(),
    'code_ok' => !empty($_SESSION['setup_ok']),
    'reset' => !empty($old['fp']) ? ['fp' => $old['fp'], 'url' => $old['url'], 'name' => $old['name'] ?? ''] : null,
    'php' => PHP_VERSION,
    'checks' => [
        'sodium' => function_exists('sodium_crypto_sign_verify_detached'),
        'openssl' => function_exists('openssl_verify'),
        'curl' => function_exists('curl_init'),
        'data_dir' => is_writable(data_dir()),
        'well_known' => is_writable(SEALID_ROOT) || is_writable(SEALID_ROOT . '/.well-known'),
        'https' => is_https(),
        'data_outside' => !str_starts_with(realpath(data_dir()) ?: '', realpath(SEALID_ROOT) ?: '-'),
    ],
]);
