<?php
/**
 * Seal ID — bootstrap: config, data directory, JSON storage, security
 * headers, CSP nonce, sessions, CSRF, rate limiting.
 */
declare(strict_types=1);

const SEALID_VERSION = '1.5.2';
const SEALID_REPO = 'https://github.com/jeffbristow/SealID';
define('SEALID_ROOT', dirname(__DIR__));

error_reporting(E_ALL);
ini_set('display_errors', '0');

$GLOBALS['SEALID_CONFIG'] = is_file(SEALID_ROOT . '/config.php') ? (require SEALID_ROOT . '/config.php') : [];
if (!is_array($GLOBALS['SEALID_CONFIG'])) $GLOBALS['SEALID_CONFIG'] = [];

require_once __DIR__ . '/openpgp.php';
require_once __DIR__ . '/http.php';
require_once __DIR__ . '/chain.php';
require_once __DIR__ . '/proofs.php';
require_once __DIR__ . '/peers.php';
require_once __DIR__ . '/view.php';
require_once __DIR__ . '/avatar.php';
require_once __DIR__ . '/update.php';
require_once __DIR__ . '/favicon.php';
require_once __DIR__ . '/check.php';

function cfg(string $key, mixed $default = null): mixed
{
    return $GLOBALS['SEALID_CONFIG'][$key] ?? $default;
}

function has_config(): bool
{
    return is_file(SEALID_ROOT . '/config.php');
}

/* ---------------------------------------------------------------------
 * Data directory (outside the web root by default)
 * --------------------------------------------------------------------- */

/**
 * 1.5.2: two Seal IDs on one hosting account must never share a data folder
 * (one would show, and could change, the other's identity). Each data folder
 * records which install folder owns it in install.json.
 *
 *  - Default folder (no data_dir in config.php): "<parent>/.sealid-data". If
 *    another install already owns it, this install quietly uses
 *    "<parent>/.sealid-data-<install folder name>" instead.
 *  - data_dir set in config.php but owned by another install: stop with an
 *    error (never silently use someone else's data).
 */
function data_dir(): string
{
    static $dir = null;
    if ($dir !== null) return $dir;
    $set = cfg('data_dir');
    if ($set) {
        $d = (string)$set;
        if (data_dir_owner_conflict($d)) {
            data_dir_fatal('The data folder set in config.php (data_dir) belongs to another Seal ID on this account. Give this Seal ID its own data_dir.');
        }
    } else {
        $d = dirname(SEALID_ROOT) . '/.sealid-data';
        if (data_dir_owner_conflict($d)) {
            $own = preg_replace('/[^A-Za-z0-9._-]/', '_', basename(SEALID_ROOT));
            $d = dirname(SEALID_ROOT) . '/.sealid-data-' . ($own !== '' ? $own : 'install');
            if (data_dir_owner_conflict($d)) {
                data_dir_fatal('This Seal ID can’t find a data folder of its own. Set data_dir in config.php to a new folder.');
            }
        }
    }
    if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
        // Fallback inside the install, protected by .htaccess.
        $d = SEALID_ROOT . '/data';
        if (!is_dir($d)) @mkdir($d, 0700, true);
    }
    if (str_starts_with(realpath($d) ?: $d, realpath(SEALID_ROOT) ?: SEALID_ROOT)) {
        if (!is_file("$d/.htaccess")) @file_put_contents("$d/.htaccess", "Require all denied\n");
    }
    foreach (['peers', 'rl'] as $sub) if (!is_dir("$d/$sub")) @mkdir("$d/$sub", 0700);
    data_dir_claim($d);
    return $dir = $d;
}

/** This install's folder, as stored in install.json. */
function install_root(): string
{
    return str_replace('\\', '/', realpath(SEALID_ROOT) ?: SEALID_ROOT);
}

/**
 * Does $d belong to a different Seal ID install?
 *  - install.json names another folder that still holds a Seal ID → yes.
 *    (If that folder is gone, the install was moved: the data is ours.)
 *  - No install.json yet (data from before 1.5.2) but an identity whose
 *    address isn't the site being visited → yes, it's someone else's.
 */
function data_dir_owner_conflict(string $d): bool
{
    if (!is_dir($d)) return false;
    $m = is_file("$d/install.json") ? json_decode((string)@file_get_contents("$d/install.json"), true) : null;
    if (is_array($m) && is_string($m['root'] ?? null) && $m['root'] !== '') {
        if ($m['root'] === install_root() || same_folder($m['root'], SEALID_ROOT)) return false;
        return is_file($m['root'] . '/lib/bootstrap.php');
    }
    if (!is_file("$d/chain.json")) return false;
    $host = strtolower(preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? '')));
    if ($host === '') return false;                                  // command line: can't tell, trust it
    $c = json_decode((string)@file_get_contents("$d/chain.json"), true);
    $owner = strtolower((string)parse_url((string)($c['url'] ?? ''), PHP_URL_HOST));
    return $owner !== '' && $owner !== $host;
}

/** The same folder under two names (symlinks, web vs. SSH paths)? */
function same_folder(string $a, string $b): bool
{
    $x = @stat($a);
    $y = @stat($b);
    return $x && $y && $x['ino'] !== 0 && $x['dev'] === $y['dev'] && $x['ino'] === $y['ino'];
}

/** Mark $d as this install's data folder. */
function data_dir_claim(string $d): void
{
    $m = is_file("$d/install.json") ? json_decode((string)@file_get_contents("$d/install.json"), true) : null;
    $root = is_array($m) ? (string)($m['root'] ?? '') : '';
    if ($root !== '' && ($root === install_root() || same_folder($root, SEALID_ROOT))) return;
    $j = json_encode(['root' => install_root(), 'claimed' => time()], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    @file_put_contents("$d/install.json", $j, LOCK_EX);
}

function data_dir_fatal(string $msg): never
{
    if (PHP_SAPI === 'cli') { fwrite(STDERR, $msg . "\n"); exit(1); }
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Seal ID can't start.\n\n" . $msg . "\n";
    exit;
}

function jread(string $name, mixed $default = []): mixed
{
    $f = data_dir() . '/' . $name;
    if (!is_file($f)) return $default;
    $j = json_decode((string)file_get_contents($f), true);
    return $j ?? $default;
}

function jwrite(string $name, mixed $data): void
{
    $f = data_dir() . '/' . $name;
    atomic_write($f, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function atomic_write(string $file, string $content): void
{
    $tmp = $file . '.tmp' . bin2hex(random_bytes(4));
    if (file_put_contents($tmp, $content) === false) throw new RuntimeException('Cannot write ' . basename($file) . ' — check folder permissions.');
    @chmod($tmp, 0644);
    if (!rename($tmp, $file)) { @unlink($tmp); throw new RuntimeException('Cannot replace ' . basename($file) . '.'); }
}

/** Run $fn while holding the global write lock. */
function with_lock(callable $fn): mixed
{
    $h = fopen(data_dir() . '/.lock', 'c');
    if ($h === false) return $fn();
    flock($h, LOCK_EX);
    try { return $fn(); }
    finally { flock($h, LOCK_UN); fclose($h); }
}

function is_installed(): bool
{
    return is_file(data_dir() . '/chain.json');
}

/* ---------------------------------------------------------------------
 * Request helpers
 * --------------------------------------------------------------------- */

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function client_ip(): string
{
    return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ($_SERVER['SERVER_PORT'] ?? '') === '443'
        || strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}

function is_local_dev(): bool
{
    $host = strtolower(explode(':', $_SERVER['HTTP_HOST'] ?? '')[0]);
    return in_array($host, ['localhost', '127.0.0.1'], true) && cfg('dev', false) === true;
}

/** The URL this install is being visited at (used to suggest the identity address in setup). */
function detected_base_url(): string
{
    $host = strtolower($_SERVER['HTTP_HOST'] ?? 'localhost');
    $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    return 'https://' . $host . $dir;
}

function body_json(int $max = 262144): array
{
    $raw = file_get_contents('php://input', false, null, 0, $max);
    $j = json_decode((string)$raw, true);
    return is_array($j) ? $j : [];
}

function json_out(mixed $data, int $code = 200, bool $cors = false): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    if ($cors) header('Access-Control-Allow-Origin: *');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(int $code, string $message): never
{
    json_out(['ok' => false, 'error' => $message], $code);
}

/* ---------------------------------------------------------------------
 * Security headers + CSP nonce
 * --------------------------------------------------------------------- */

function csp_nonce(): string
{
    static $n = null;
    return $n ??= base64_encode(random_bytes(16));
}

function send_page_headers(bool $wasm = false): void
{
    $n = csp_nonce();
    $script = "'self' 'nonce-$n'" . ($wasm ? " 'wasm-unsafe-eval'" : '');
    header("Content-Security-Policy: default-src 'self'; script-src $script; style-src 'self' 'nonce-$n'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('X-Frame-Options: DENY');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header('Content-Type: text/html; charset=utf-8');
}

/* ---------------------------------------------------------------------
 * Sessions (admin) + CSRF
 * --------------------------------------------------------------------- */

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $path = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/') . '/';
    session_name('sealid');
    session_set_cookie_params(['lifetime' => 0, 'path' => $path, 'secure' => !is_local_dev(), 'httponly' => true, 'samesite' => 'Strict']);
    session_start();
    if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

function csrf_token(): string
{
    start_session();
    return $_SESSION['csrf'];
}

function csrf_check(): void
{
    start_session();
    $t = $_SERVER['HTTP_X_CSRF'] ?? '';
    if (!is_string($t) || !hash_equals($_SESSION['csrf'], $t)) fail(403, 'Your session expired. Reload the page.');
}

function is_admin(): bool
{
    start_session();
    return !empty($_SESSION['admin']) && ($_SESSION['admin_fp'] ?? '') === (Chain::state()['fp'] ?? '-');
}

/* ---------------------------------------------------------------------
 * Rate limiting (file based, per IP + bucket)
 * --------------------------------------------------------------------- */

function rate_limit(string $bucket, int $max, int $windowSeconds): bool
{
    $f = data_dir() . '/rl/' . substr(hash('sha256', $bucket . '|' . client_ip()), 0, 32) . '.json';
    $now = time();
    $hits = is_file($f) ? (json_decode((string)file_get_contents($f), true) ?: []) : [];
    $hits = array_values(array_filter($hits, fn($t) => $t > $now - $windowSeconds));
    if (count($hits) >= $max) return false;
    $hits[] = $now;
    @file_put_contents($f, json_encode($hits));
    if (random_int(1, 200) === 1) rate_limit_gc();
    return true;
}

function rate_limit_gc(): void
{
    foreach (glob(data_dir() . '/rl/*.json') ?: [] as $f) {
        if (filemtime($f) < time() - 86400) @unlink($f);
    }
}
