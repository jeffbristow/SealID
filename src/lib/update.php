<?php
/**
 * Seal ID — one-click updates from GitHub releases (added 1.1.0).
 *
 * Where: the newest release of github.com/jeffbristow/SealID. It must carry
 *   SealID-<version>.zip       the files of src/ inside one "SealID-<version>/" folder
 *   SealID-<version>.zip.sig   {"version", "sha256", "sig"}: Ed25519 signature of
 *                              "sealid-update-v1|<version>|<sha256>"
 * Before anything is installed:
 *   - the signature must verify with Seal ID's update key (only the PUBLIC key
 *     is here — it can check signatures, not make them),
 *   - the zip's SHA-256 must be the signed one,
 *   - the zip may only contain ordinary file names in that one folder, and its
 *     lib/bootstrap.php must say that version.
 * Never touched: config.php, .well-known/ (generated), the data folder.
 * Replaced files are kept in <data>/update/backup so "Undo" can put them back.
 * GitHub is asked at most every 12 hours by itself.
 */
declare(strict_types=1);

const UPDATE_REPO = 'jeffbristow/SealID';
const UPDATE_PUBKEY = 'CBLb361Y0VI9pLxUaHC53GBZZaIWBloHQeZpnriMNzI=';   // Ed25519, base64
const UPDATE_EVERY = 12 * 3600;
const UPDATE_MAX_ZIP = 20 * 1048576;

function up_dir(string $sub = ''): string
{
    $d = data_dir() . '/update' . ($sub !== '' ? '/' . $sub : '');
    if (!is_dir($d)) @mkdir($d, 0700, true);
    return $d;
}

function up_signed_text(string $version, string $sha256): string
{
    return 'sealid-update-v1|' . $version . '|' . strtolower($sha256);
}

function up_rm_tree(string $dir): void
{
    if (!is_dir($dir)) return;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
}

function up_why(): string
{
    $e = error_get_last();
    return $e ? '(' . preg_replace('/^\w+\(\S*\): /', '', (string)$e['message']) . ')' : '';
}

/** Never replaced or removed by an update. */
function up_keep(string $rel): bool
{
    if ($rel === 'config.php' || $rel === '.well-known' || str_starts_with($rel, '.well-known/')) return true;
    if ($rel === 'data' || str_starts_with($rel, 'data/')) return true;
    $data = str_replace('\\', '/', (string)realpath(data_dir()));
    $here = str_replace('\\', '/', (string)realpath(SEALID_ROOT));
    if ($data !== '' && $here !== '' && str_starts_with($data . '/', $here . '/')) {
        $inside = ltrim(substr($data, strlen($here)), '/');
        if ($inside !== '' && ($rel === $inside || str_starts_with($rel, $inside . '/'))) return true;
    }
    return false;
}

function up_rel_ok(string $rel): bool
{
    return (bool)preg_match('~^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$~', $rel) && !preg_match('~(^|/)\.\.?(/|$)~', $rel);
}

/** The installed version, read from disk (right even in the request that just updated). */
function up_current(): string
{
    $f = SEALID_ROOT . '/lib/bootstrap.php';
    clearstatcache(true, $f);
    return preg_match("/const SEALID_VERSION = '([0-9.]+)'/", (string)@file_get_contents($f), $m) ? $m[1] : SEALID_VERSION;
}

/** Ask GitHub for the newest release. ['version','zip','sig','note','published'] or null (+ $why). */
function up_ask(?string &$why = null): ?array
{
    $r = http_json('https://api.github.com/repos/' . UPDATE_REPO . '/releases/latest', ['accept' => 'application/vnd.github+json', 'timeout' => 15]);
    if ($r['status'] !== 200 || !is_array($r['json'])) {
        // 1.2.1: shared hosting shares one IP with many sites, and GitHub's API allows only 60
        // anonymous requests an hour per IP — often used up by the neighbours. The web
        // address /releases/latest is not limited that way: it redirects to the newest tag.
        $w = up_ask_web($why2);
        if ($w) return $w;
        $why = ($r['status'] ? 'GitHub answered HTTP ' . $r['status'] : (string)$r['error']) . ($why2 ? "; $why2" : '');
        return null;
    }
    $j = $r['json'];
    if (!empty($j['draft']) || !empty($j['prerelease'])) { $why = 'no published release'; return null; }
    if (!preg_match('/^v?(\d+\.\d+\.\d+)$/', (string)($j['tag_name'] ?? ''), $m)) { $why = 'unexpected release tag'; return null; }
    $ver = $m[1];
    $zip = $sig = null;
    $size = 0;
    foreach (($j['assets'] ?? []) as $a) {
        $n = (string)($a['name'] ?? '');
        $u = (string)($a['browser_download_url'] ?? '');
        if (!str_starts_with($u, 'https://github.com/')) continue;
        if ($n === "SealID-$ver.zip") { $zip = $u; $size = (int)($a['size'] ?? 0); }
        if ($n === "SealID-$ver.zip.sig") $sig = $u;
    }
    if (!$zip || !$sig) { $why = "release $ver has no signed package"; return null; }
    // Release notes: the bullets under "New in Seal ID x.y.z", shortened.
    $notes = [];
    foreach (preg_split('/\R/', (string)($j['body'] ?? '')) as $line) {
        if (preg_match('/^\s*[-*]\s+(.+)$/', $line, $mm)) $notes[] = mb_substr(strip_tags($mm[1]), 0, 200);
        if (count($notes) >= 8) break;
    }
    return ['version' => $ver, 'zip' => $zip, 'sig' => $sig, 'size' => $size, 'notes' => $notes,
            'url' => (string)($j['html_url'] ?? ''), 'published' => (string)($j['published_at'] ?? '')];
}

/**
 * The newest release without the GitHub API: follow github.com/<repo>/releases/latest to its
 * tag, use the standard download addresses, and read the notes from the .sig file (1.2.1).
 */
function up_ask_web(?string &$why = null): ?array
{
    $r = http_fetch('https://github.com/' . UPDATE_REPO . '/releases/latest', ['no_follow' => true, 'accept' => 'text/html', 'timeout' => 15]);
    if (!preg_match('#^https://github\.com/' . preg_quote(UPDATE_REPO, '#') . '/releases/tag/v?(\d+\.\d+\.\d+)$#', (string)($r['location'] ?? ''), $m)) {
        $why = 'github.com did not name a release' . ($r['status'] ? ' (HTTP ' . $r['status'] . ')' : '');
        return null;
    }
    $ver = $m[1];
    $base = 'https://github.com/' . UPDATE_REPO . "/releases/download/v$ver/SealID-$ver.zip";
    $s = http_fetch($base . '.sig', ['max_bytes' => 65536, 'timeout' => 20, 'redirects' => 5, 'accept' => 'application/octet-stream']);
    $sig = $s['status'] === 200 ? json_decode($s['body'], true) : null;
    if (!is_array($sig) || ($sig['version'] ?? '') !== $ver) {
        $why = "release $ver has no signed package";
        return null;
    }
    $notes = [];
    foreach ((array)($sig['notes'] ?? []) as $n) if (is_string($n) && count($notes) < 8) $notes[] = mb_substr(strip_tags($n), 0, 200);
    return ['version' => $ver, 'zip' => $base, 'sig' => $base . '.sig', 'size' => 0, 'notes' => $notes,
            'url' => 'https://github.com/' . UPDATE_REPO . "/releases/tag/v$ver", 'published' => ''];
}

/** The newest known release: { checked, latest|null, error } — asked again after 12 h, or now with $force. */
function up_check(bool $force = false): array
{
    $c = jread('update/check.json', []);
    if (!$force && !empty($c['checked']) && time() - (int)$c['checked'] < UPDATE_EVERY) return $c;
    up_dir();
    $why = '';
    $l = up_ask($why);
    $out = ['checked' => time(), 'latest' => $l ?? ($c['latest'] ?? null), 'error' => $l ? '' : $why];
    jwrite('update/check.json', $out);
    return $out;
}

function up_available(?array $c = null): ?array
{
    $c ??= jread('update/check.json', []);
    $l = $c['latest'] ?? null;
    return (is_array($l) && version_compare((string)$l['version'], up_current(), '>')) ? $l : null;
}

/** What would stop an update here. Empty = fine. */
function up_blockers(): array
{
    $bad = [];
    if (!is_writable(SEALID_ROOT)) $bad[] = 'the Seal ID folder is not writable by PHP';
    foreach (['index.php', 'admin.php', 'api.php', 'lib', 'lib/bootstrap.php', 'assets'] as $f) {
        if (file_exists(SEALID_ROOT . '/' . $f) && !is_writable(SEALID_ROOT . '/' . $f)) $bad[] = $f . ' is not writable by PHP';
    }
    if (!class_exists('ZipArchive')) $bad[] = 'PHP "zip" is not available';
    if (!function_exists('sodium_crypto_sign_verify_detached')) $bad[] = 'PHP "sodium" is not available';
    return $bad;
}

function up_backup(): ?array
{
    $b = jread('update/backup.json', []);
    return !empty($b['version']) && is_dir(up_dir('backup')) ? $b : null;
}

/** Everything the update panel shows. */
function up_state(?array $c = null): array
{
    $c ??= jread('update/check.json', []);
    $n = up_available($c);
    $b = up_backup();
    return [
        'current' => up_current(),
        'checked' => (int)($c['checked'] ?? 0),
        'latest' => $c['latest']['version'] ?? null,
        'update' => $n ? ['version' => $n['version'], 'size' => $n['size'], 'notes' => $n['notes'], 'url' => $n['url']] : null,
        'error' => (string)($c['error'] ?? ''),
        'blockers' => up_blockers(),
        'undo' => $b ? $b['version'] : null,
    ];
}

/** Download, check and install the newest release. Returns [ok, message]. */
function up_install(): array
{
    if ($bad = up_blockers()) return [false, 'Can’t update here: ' . implode('; ', $bad) . '.'];
    $work = up_dir('work');
    $lock = @fopen($work . '/.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) return [false, 'An update is already running — try again in a minute.'];
    @set_time_limit(300);
    try {
        $c = up_check(true);
        $want = up_available($c);
        if (!$want) return [false, $c['error'] && empty($c['latest']) ? 'Couldn’t check for updates: ' . $c['error'] : 'Seal ID ' . up_current() . ' is already the newest.'];
        // 1. download the package and its signature
        $s = http_fetch($want['sig'], ['max_bytes' => 65536, 'timeout' => 30, 'redirects' => 5, 'accept' => 'application/octet-stream']);
        if ($s['status'] !== 200) return [false, 'Couldn’t download the signature: ' . ($s['error'] ?? 'HTTP ' . $s['status'])];
        $z = http_fetch($want['zip'], ['max_bytes' => UPDATE_MAX_ZIP, 'timeout' => 240, 'redirects' => 5, 'accept' => 'application/octet-stream']);
        if ($z['status'] !== 200) return [false, 'Couldn’t download the update: ' . ($z['error'] ?? 'HTTP ' . $z['status'])];
        return up_install_package($want['version'], $z['body'], $s['body']);
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/**
 * Check and install a downloaded package (zip bytes + .sig JSON) for $ver.
 * Separate from the download so tests can feed it packages directly.
 * Returns [ok, message].
 */
function up_install_package(string $ver, string $zipBytes, string $sigJson): array
{
    {
        if (!preg_match('/^\d+\.\d+\.\d+$/', $ver)) return [false, 'Refused: bad version.'];
        if (!version_compare($ver, up_current(), '>')) return [false, "Refused: $ver is not newer than " . up_current() . '.'];
        $work = up_dir('work');
        $top = "SealID-$ver/";
        $zipFile = $work . '/package.zip';
        file_put_contents($zipFile, $zipBytes);
        $sha = hash('sha256', $zipBytes);
        unset($zipBytes);

        // 2. signature + checksum
        $sig = json_decode($sigJson, true);
        if (!is_array($sig) || ($sig['version'] ?? '') !== $ver || !is_string($sig['sig'] ?? null)) return [false, "Refused: the signature file is not for version $ver. Nothing was changed."];
        if (!hash_equals(strtolower((string)($sig['sha256'] ?? '')), $sha)) return [false, 'Refused: the download does not match its signature (damaged or changed). Nothing was changed.'];
        $raw = base64_decode($sig['sig'], true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($raw, up_signed_text($ver, $sha), base64_decode(UPDATE_PUBKEY))) {
            return [false, 'Refused: the update is NOT signed by Seal ID. Nothing was changed.'];
        }

        // 3. list the zip (nothing written into the site yet)
        $za = new ZipArchive();
        if ($za->open($zipFile) !== true) return [false, 'Refused: the package is not a readable zip.'];
        if ($za->numFiles > 1000) { $za->close(); return [false, 'Refused: too many files in the package.']; }
        $files = [];
        $total = 0;
        for ($i = 0; $i < $za->numFiles; $i++) {
            $st = $za->statIndex($i);
            $name = (string)$st['name'];
            if (!str_starts_with($name, $top)) { $za->close(); return [false, 'Refused: unexpected file in the package (' . $name . ').']; }
            $rel = substr($name, strlen($top));
            if ($rel === '' || str_ends_with($rel, '/')) continue;
            if (!up_rel_ok($rel)) { $za->close(); return [false, 'Refused: unsafe file name in the package (' . $rel . ').']; }
            $total += (int)$st['size'];
            if ($total > 3 * UPDATE_MAX_ZIP) { $za->close(); return [false, 'Refused: the package unpacks too big.']; }
            if (up_keep($rel)) continue;
            $files[$rel] = $i;
        }
        $boot = isset($files['lib/bootstrap.php']) ? (string)$za->getFromIndex($files['lib/bootstrap.php']) : '';
        if (!preg_match("/const SEALID_VERSION = '" . preg_quote($ver, '/') . "'/", $boot) || !isset($files['index.php'], $files['admin.php'], $files['api.php'])) {
            $za->close();
            return [false, "Refused: the package is not Seal ID $ver."];
        }

        // 4. unpack into the data folder first; only new or changed files
        $stage = $work . '/stage';
        up_rm_tree($stage);
        @mkdir($stage, 0700, true);
        $changed = [];
        foreach ($files as $rel => $i) {
            $data = $za->getFromIndex($i);
            if ($data === false) { $za->close(); return [false, "Couldn’t read $rel from the package — nothing was changed."]; }
            $dst = SEALID_ROOT . '/' . $rel;
            if (is_file($dst) && hash_file('sha256', $dst) === hash('sha256', $data)) continue;
            $stf = $stage . '/' . $rel;
            if (!is_dir(dirname($stf))) @mkdir(dirname($stf), 0700, true);
            if (@file_put_contents($stf, $data) === false) { $za->close(); return [false, "Couldn’t unpack $rel — nothing was changed. " . up_why()]; }
            $changed[] = $rel;
        }
        $za->close();

        // 5. back up what will be replaced (one backup: the version before this update)
        $bk = up_dir() . '/backup';
        up_rm_tree($bk);
        @mkdir($bk . '/files', 0700, true);
        $replaced = [];
        $added = [];
        foreach ($changed as $rel) {
            $dst = SEALID_ROOT . '/' . $rel;
            if (is_file($dst)) {
                if (!is_dir(dirname($bk . '/files/' . $rel))) @mkdir(dirname($bk . '/files/' . $rel), 0700, true);
                if (!@copy($dst, $bk . '/files/' . $rel)) return [false, "Couldn’t back up $rel — nothing was changed. " . up_why()];
                $replaced[] = $rel;
            } else {
                $added[] = $rel;
            }
        }
        $from = up_current();
        jwrite('update/backup.json', ['version' => $from, 'to' => $ver, 'made' => date('c'), 'replaced' => $replaced, 'added' => $added]);

        // 6. put each file in place (bootstrap.php last, so the version only changes when everything is in)
        usort($changed, fn($a, $b) => ($a === 'lib/bootstrap.php') <=> ($b === 'lib/bootstrap.php'));
        $done = [];
        foreach ($changed as $rel) {
            $dst = SEALID_ROOT . '/' . $rel;
            $ok = (is_dir(dirname($dst)) || @mkdir(dirname($dst), 0755, true));
            if ($ok) {
                $tmp = $dst . '.sid-new';
                $ok = @copy($stage . '/' . $rel, $tmp) && @chmod($tmp, 0644) && @rename($tmp, $dst);
                if (!$ok) { @unlink($tmp); $ok = @copy($stage . '/' . $rel, $dst); }
            }
            if (!$ok) {
                $why = up_why();
                up_put_back($done, $bk);
                return [false, "Couldn’t install $rel $why — everything was put back to $from."];
            }
            $done[] = $rel;
        }
        up_opcache_forget($changed);
        up_rm_tree($stage);
        @unlink($zipFile);
        return [true, "Updated to Seal ID $ver."];
    }
}

/** Put backed-up files back (after a failed install, or for Undo). */
function up_put_back(array $rels, string $bk): void
{
    $b = jread('update/backup.json', []);
    foreach ($rels as $rel) {
        $dst = SEALID_ROOT . '/' . $rel;
        if (is_file($bk . '/files/' . $rel)) @copy($bk . '/files/' . $rel, $dst);
        elseif (in_array($rel, $b['added'] ?? [], true)) @unlink($dst);
    }
    up_opcache_forget($rels);
}

/** Go back to the version before the last update. Returns [ok, message]. */
function up_restore(): array
{
    $b = up_backup();
    if (!$b) return [false, 'There is no earlier version to go back to.'];
    $bk = up_dir() . '/backup';
    $rels = array_merge($b['replaced'] ?? [], $b['added'] ?? []);
    // bootstrap.php last again
    usort($rels, fn($x, $y) => ($x === 'lib/bootstrap.php') <=> ($y === 'lib/bootstrap.php'));
    up_put_back($rels, $bk);
    up_rm_tree($bk);
    @unlink(data_dir() . '/update/backup.json');
    return [true, 'Back to Seal ID ' . $b['version'] . '.'];
}

function up_opcache_forget(array $rels): void
{
    if (!function_exists('opcache_invalidate')) return;
    foreach ($rels as $rel) if (str_ends_with($rel, '.php')) @opcache_invalidate(SEALID_ROOT . '/' . $rel, true);
}
