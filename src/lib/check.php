<?php
/**
 * Seal ID — public checker (1.5.0): "who owns this domain / Seal ID?"
 *
 * Anyone can type a domain (jeffbristow.com) or a Seal ID address
 * (https://id.example.com) on check.php or ask api.php?a=lookup&q=…; this
 * server fetches that Seal ID, verifies every signature and re-checks its
 * proofs (peer_lookup), and answers with a plain verdict.
 *
 * Nothing is saved about the Seal IDs looked up (no pins, no vouches):
 * only a short-lived cache of the public answer, so a busy page or a
 * shared link doesn't make this server fetch the same thing again.
 */
declare(strict_types=1);

const CHECK_CACHE_OK = 600;          // seconds a result is reused
const CHECK_CACHE_FAIL = 120;        // shorter for failures (a host may come back)
const CHECK_PER_IP = [10, 60];       // lookups per visitor: 10 a minute …
const CHECK_GLOBAL = [60, 600];      // … and fresh (uncached) lookups for everyone: 60 per 10 minutes

/** Owner switch (Admin → Settings). On unless turned off. */
function check_enabled(): bool
{
    $s = jread('settings.json', []);
    return (bool)($s['public_check'] ?? cfg('public_check', true));
}

/** What the visitor typed → a Seal ID / domain address, or null. */
function check_normalize(string $q): ?string
{
    $q = trim($q);
    if ($q === '' || strlen($q) > 200) return null;
    $q = preg_replace('#^http://#i', 'https://', $q);
    $q = preg_replace('#^(https://)?www\.#i', '$1', $q);     // www.example.com → example.com
    return Chain::normUrl($q);
}

/** The cached public answer for $url, or null. */
function check_cache_get(string $url): ?array
{
    $r = jread('check/' . substr(hash('sha256', $url), 0, 32) . '.json', null);
    if (!is_array($r) || !isset($r['checked'])) return null;
    $ttl = $r['verdict'] === 'valid' ? CHECK_CACHE_OK : CHECK_CACHE_FAIL;
    return $r['checked'] > time() - $ttl ? $r : null;
}

function check_cache_put(string $url, array $r): void
{
    @mkdir(data_dir() . '/check', 0700, true);
    try { jwrite('check/' . substr(hash('sha256', $url), 0, 32) . '.json', $r); } catch (Throwable) { return; }
    if (random_int(1, 50) === 1) {
        foreach (glob(data_dir() . '/check/*.json') ?: [] as $f) {
            if (filemtime($f) < time() - 86400) @unlink($f);
        }
    }
}

/** One rate-limit bucket shared by every visitor (rate_limit() is per IP). */
function check_global_ok(): bool
{
    $f = data_dir() . '/rl/check-global.json';
    [$max, $win] = CHECK_GLOBAL;
    return (bool)with_lock(function () use ($f, $max, $win) {
        $now = time();
        $hits = is_file($f) ? (json_decode((string)file_get_contents($f), true) ?: []) : [];
        $hits = array_values(array_filter($hits, fn($t) => $t > $now - $win));
        if (count($hits) >= $max) return false;
        $hits[] = $now;
        @file_put_contents($f, json_encode($hits));
        return true;
    });
}

/**
 * Check $q. Returns the public answer (see check_result) plus 'cached'.
 * $limits = false skips the rate limits (CLI / tests).
 */
function check_lookup(string $q, bool $limits = true): array
{
    $url = check_normalize($q);
    if ($url === null) return check_result($q, null, ['ok' => false, 'code' => 'bad_address', 'error' => 'Type a domain such as example.com or a Seal ID address such as https://id.example.com.']);
    if ($limits && !rate_limit('check', CHECK_PER_IP[0], CHECK_PER_IP[1])) {
        return check_result($q, $url, ['ok' => false, 'code' => 'busy', 'error' => 'Too many checks from your connection. Wait a minute and try again.']) + ['cached' => false];
    }
    if ($c = check_cache_get($url)) return $c + ['cached' => true];
    if ($limits && !check_global_ok()) {
        return check_result($q, $url, ['ok' => false, 'code' => 'busy', 'error' => 'This checker is busy right now. Try again in a few minutes.']) + ['cached' => false];
    }
    $res = check_result($q, $url, peer_lookup($url, true), Chain::state()['url'] ?? null);
    if ($res['verdict'] !== 'busy') check_cache_put($url, $res);
    return $res + ['cached' => false];
}

/** Verdicts, in the words the page uses. */
const CHECK_VERDICTS = [
    'valid'         => 'Valid Seal ID',
    'not_confirmed' => 'Not confirmed: possible impersonation',
    'invalid'       => 'Invalid Seal ID',
    'unreachable'   => 'Couldn’t be checked',
    'none'          => 'No Seal ID found',
    'bad_address'   => 'Not a valid address',
    'busy'          => 'Try again later',
];

/**
 * Turn a peer_lookup() report into the public answer. Pure (no I/O) so it can be tested.
 * verdict: valid | not_confirmed | invalid | unreachable | none | bad_address | busy
 */
function check_result(string $query, ?string $url, array $r, ?string $by = null): array
{
    $code = (string)($r['code'] ?? ($r['ok'] ?? false ? 'ok' : 'not_found'));
    $verdict = match ($code) {
        'ok' => 'valid',
        'not_confirmed' => 'not_confirmed',
        'invalid', 'dns_mismatch' => 'invalid',
        'blocked' => 'unreachable',
        'bad_address' => 'bad_address',
        'busy' => 'busy',
        default => 'none',
    };
    $out = [
        'ok' => true,
        'query' => $query,
        'checked_url' => $url,
        'verdict' => $verdict,
        'title' => CHECK_VERDICTS[$verdict],
        'message' => '',
        'checked' => time(),
        'checked_by' => $by,
    ];
    if ($verdict !== 'valid') {
        $out['message'] = (string)($r['error'] ?? '');
        if ($verdict === 'not_confirmed' && !empty($r['claimed'])) $out['claimed'] = array_values($r['claimed']);
        return $out;
    }
    $host = $url ? (string)parse_url($url, PHP_URL_HOST) : '';
    $alias = $r['alias'] ?? null;
    $proofs = [];
    foreach ($r['proofs'] ?? [] as $p) {
        $proofs[] = [
            'service' => $p['service'],
            'label' => $p['label'],
            'handle' => $p['handle'],
            'status' => $p['status'],
            'detail' => $p['detail'],
            'profile' => $p['profile'] ?? null,
        ];
    }
    // Verified first, then the rest in chain order (usort is stable)
    $rank = fn($s) => in_array($s, ['verified', 'witnessed'], true) ? 0 : 1;
    usort($proofs, fn($a, $b) => $rank($a['status']) <=> $rank($b['status']));
    $warnings = array_values(array_filter($r['warnings'] ?? [], fn($w) => !str_contains($w, 'is a verified alias of this Seal ID')));
    if (($r['pin'] ?? '') === 'changed') {
        $warnings[] = 'This Seal ID’s history is different from the copy this server saw before. That happens after an identity reset; if you didn’t expect one, ask the owner.';
    }
    $verified = count(array_filter($proofs, fn($p) => in_array($p['status'], ['verified', 'witnessed'], true)));
    $name = (string)($r['name'] ?? '');
    $out += [
        'url' => $r['url'],
        'name' => $name,
        'bio' => (string)($r['bio'] ?? ''),
        'avatar' => $r['avatar'] ?? null,
        'fp' => $r['fp'],
        'algo' => $r['algo'] ?? '',
        'created' => $r['created'] ?? null,
        'alias' => $alias,
        'alias_how' => $alias ? ($r['alias_how'] ?? null) : null,
        'proofs' => $proofs,
        'verified_count' => $verified,
        'warnings' => $warnings,
    ];
    $who = $name !== '' ? $name : (string)parse_url($r['url'], PHP_URL_HOST);
    $out['message'] = $alias
        ? "$alias belongs to the Seal ID of $who ({$r['url']}). The domain points to it, and the Seal ID confirms the domain with a verified proof."
        : ($host !== '' && $r['url'] === $url
            ? "$url is the Seal ID of $who. Its signatures check out" . ($verified ? " and $verified proof" . ($verified === 1 ? '' : 's') . ' verified.' : '.')
            : "This is the Seal ID of $who.");
    return $out;
}
