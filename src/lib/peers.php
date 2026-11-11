<?php
/**
 * Seal ID — other installations (docs/PROTOCOL.md sections 4 and 6):
 * discovery with fallbacks, verification, pinning, vouches.
 */
declare(strict_types=1);

/* ---------------------------------------------------------------------
 * Pins (trust on first use)
 * --------------------------------------------------------------------- */

function peer_pin_file(string $url): string
{
    return 'peers/' . substr(hash('sha256', $url), 0, 32) . '.json';
}

function peer_pin_get(string $url): ?array
{
    $p = jread(peer_pin_file($url), null);
    return is_array($p) ? $p : null;
}

function peer_pin_save(array $report): void
{
    $old = peer_pin_get($report['url']) ?? [];
    jwrite(peer_pin_file($report['url']), [
        'url' => $report['url'],
        'name' => $report['name'],
        'fp' => $report['fp'],
        'seq' => $report['seq'],
        'hash' => $report['hash'],
        'hashes' => $report['hashes'],
        'mirrors' => array_values(array_unique(array_merge($report['mirrors'], $report['dns']['mirrors'] ?? []))),
        'first_seen' => $old['first_seen'] ?? time(),
        'last_seen' => time(),
    ]);
}

/** All pinned peers, newest first. */
function peer_pins(): array
{
    $out = [];
    foreach (glob(data_dir() . '/peers/*.json') ?: [] as $f) {
        $j = json_decode((string)file_get_contents($f), true);
        if (is_array($j) && isset($j['url'])) $out[] = $j;
    }
    usort($out, fn($a, $b) => ($b['last_seen'] ?? 0) <=> ($a['last_seen'] ?? 0));
    return $out;
}

/* ---------------------------------------------------------------------
 * Discovery
 * --------------------------------------------------------------------- */

/** The _seal-id TXT record of an identity's host: ['fp' => ?, 'mirrors' => [], 'raw' => ...] or null. */
function peer_dns(string $url): ?array
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) return null;
    $txt = dns_txt('_seal-id.' . $host);
    if (!$txt) return null;
    // A host can carry several Seal IDs (e.g. https://example.com and https://example.com/team).
    // A record applies to the identity it names with "id=", or — without "id=" — only to the
    // identity at the host's root (1.2.0; before, any identity on the host was compared).
    $root = (string)parse_url($url, PHP_URL_PATH) === '';
    $fallback = null;
    foreach ($txt as $t) {
        if (!preg_match('/^\s*v=sealid1\b/i', $t)) continue;
        $out = ['fp' => null, 'mirrors' => [], 'raw' => $t, 'id' => null];
        foreach (preg_split('/\s*;\s*/', $t) as $part) {
            if (preg_match('/^fp=([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$/', $part, $m)) $out['fp'] = strtoupper($m[1]);
            if (preg_match('#^mirror=(https://\S+)$#', $part, $m)) $out['mirrors'][] = $m[1];
            if (preg_match('#^id=(https://\S+)$#', $part, $m)) $out['id'] = Chain::normUrl($m[1]);
        }
        if ($out['id'] === $url) return $out;
        if ($out['id'] === null && $root && $fallback === null) $fallback = $out;
    }
    return $fallback;
}

/**
 * Find a bundle for $url: the static file, the API, then mirrors.
 * Returns ['ok', 'bundle', 'source', 'mirror', 'attempts', 'blocked', 'dns', 'error'].
 */
function peer_fetch(string $url): array
{
    $dns = peer_dns($url);
    $pin = peer_pin_get($url);
    // The API first: it is generated per request, so host caches can't hand out
    // an old chain (a withdrawn vouch must disappear at once). The static file
    // and mirrors are the fallbacks for hosts that block PHP requests.
    $primary = [$url . '/api.php?a=bundle', $url . '/.well-known/seal-id.json'];
    $mirrors = array_values(array_unique(array_merge($dns['mirrors'] ?? [], $pin['mirrors'] ?? [])));
    $attempts = [];
    $blocked = false;
    foreach (array_merge($primary, $mirrors) as $i => $src) {
        // Cache-buster: a CDN or host cache must not hand us an old copy of the chain.
        $fresh = $src . (str_contains($src, '?') ? '&' : '?') . 't=' . time();
        $r = http_fetch($fresh, ['accept' => 'application/json', 'headers' => ['Cache-Control: no-cache']]);
        $why = null;
        if ($r['status'] === 200) {
            $b = json_decode($r['body'], true);
            if (!is_array($b) || ($b['seal_id'] ?? null) !== 1 || !is_array($b['chain'] ?? null) || !is_array($b['keys'] ?? null)) {
                $why = http_looks_blocked($r) ? 'blocked by the host’s security check' : 'not a Seal ID bundle';
                if (http_looks_blocked($r)) $blocked = true;
            } elseif (($b['url'] ?? null) !== $url) {
                $why = 'bundle for a different address (' . (is_string($b['url'] ?? null) ? $b['url'] : '?') . ')';
            } else {
                return ['ok' => true, 'bundle' => $b, 'source' => $src, 'mirror' => $i >= count($primary), 'attempts' => $attempts, 'blocked' => $blocked, 'dns' => $dns, 'error' => null];
            }
        } elseif (http_looks_blocked($r)) {
            $blocked = true;
            $why = "blocked by the host’s security check (HTTP {$r['status']})";
        } else {
            $why = $r['status'] ? "HTTP {$r['status']}" : (string)$r['error'];
        }
        $attempts[] = ['source' => $src, 'result' => $why];
        // The API fallback is pointless if the static file answered 404 from a working Seal ID-less host… but cheap; keep trying.
    }
    $err = $blocked
        ? 'The host blocked automated checking and no mirror had a copy.'
        : 'No Seal ID was found at ' . $url . '.';
    return ['ok' => false, 'bundle' => null, 'source' => null, 'mirror' => false, 'attempts' => $attempts, 'blocked' => $blocked, 'dns' => $dns, 'error' => $err];
}

/* ---------------------------------------------------------------------
 * Verification
 * --------------------------------------------------------------------- */

/**
 * Fetch and fully verify another identity. With $checkProofs every active
 * proof is re-checked by THIS server.
 */
function peer_verify(string $url, bool $checkProofs = true): array
{
    $f = peer_fetch($url);
    $base = ['ok' => false, 'url' => $url, 'attempts' => $f['attempts'], 'blocked' => $f['blocked'], 'dns' => $f['dns'], 'warnings' => []];
    if (!$f['ok']) return $base + ['error' => $f['error']];
    $b = $f['bundle'];
    try {
        $st = Chain::verifyLinks($b['chain'], $b['keys'], $url);
    } catch (ChainError $e) {
        return $base + ['error' => 'This Seal ID did not verify: ' . $e->getMessage(), 'source' => $f['source']];
    }
    $warnings = [];
    if ($f['mirror']) $warnings[] = 'Read from a mirror (' . $f['source'] . ') because the main address did not answer properly.';
    if ($st['reset_from']) $warnings[] = 'This identity was reset: it replaced the lost key ' . Pgp::formatFp($st['reset_from']) . '.';
    if (count($st['fps']) > 1) $warnings[] = 'The key was changed ' . (count($st['fps']) - 1) . ' time(s) with signed rotations.';
    $dns = $f['dns'];
    if ($dns && $dns['fp']) {
        if ($dns['fp'] === $st['fp']) {
            // good: DNS confirms the key
        } elseif (in_array($dns['fp'], $st['fps'], true)) {
            $warnings[] = 'The DNS record still names an older key of this identity.';
        } else {
            return $base + ['error' => 'The DNS record _seal-id.' . parse_url($url, PHP_URL_HOST) . ' names a different key (' . Pgp::formatFp($dns['fp']) . '). Someone may be impersonating this identity.', 'source' => $f['source']];
        }
    }
    // Pin comparison
    $pin = peer_pin_get($url);
    $pinState = 'new';
    if ($pin) {
        $ps = (int)$pin['seq'];
        $pinHashes = $pin['hashes'] ?? [$ps => $pin['hash']];
        if ($ps <= $st['seq'] && ($st['hashes'][$ps] ?? null) === $pin['hash']) {
            $pinState = 'match';
        } elseif ($ps > $st['seq'] && ($pinHashes[$st['seq']] ?? $pinHashes[(string)$st['seq']] ?? null) === $st['hash']) {
            $pinState = 'behind';
            $warnings[] = 'This copy is older than the one seen before (' . $st['seq'] . ' of ' . $ps . ' links).';
        } else {
            $pinState = 'changed';
        }
    }
    $proofs = [];
    foreach ($st['proofs'] as $seq => $p) {
        $loc = $b['locators'][(string)$seq] ?? $b['locators'][$seq] ?? null;
        $cls = proof_service($p['service']);
        if (!is_string($loc) || !$cls || ($cls::LOCATOR && $cls::locatorOk($p['handle'], $loc) === null)) $loc = null;
        $ctx = ['fps' => $st['fps'], 'url' => $url, 'attestation' => is_array($b['attestations'][(string)$seq] ?? null) ? $b['attestations'][(string)$seq] : null];
        $res = $checkProofs ? proof_check($p, $loc, $ctx) : ['status' => 'pending', 'detail' => 'Not checked.'];
        $proofs[] = $p + [
            'label' => $cls ? $cls::LABEL : $p['service'],
            'profile' => $cls ? $cls::profileUrl($p['handle']) : null,
            'locator' => $loc,
            'auto' => $cls ? $cls::AUTO : false,
            'status' => $res['status'],
            'detail' => $res['detail'],
        ];
    }
    return [
        'ok' => true,
        'url' => $url,
        'name' => $st['name'],
        'avatar' => !empty($st['avatar']) ? avatar_fetch_peer($url, $st['avatar']) : null,
        'bio' => $st['bio'],
        'fp' => $st['fp'],
        'fps' => $st['fps'],
        'algo' => Pgp::algoName($st['parsed_key']['primary']),
        'seq' => $st['seq'],
        'hash' => $st['hash'],
        'hashes' => $st['hashes'],
        'created' => $st['created'],
        'updated' => $st['updated'],
        'reset_from' => $st['reset_from'],
        'proofs' => $proofs,
        'vouches' => array_values($st['vouches']),
        'mirrors' => $st['mirrors'],
        'source' => $f['source'],
        'mirror' => $f['mirror'],
        'pin' => $pinState,
        'pinned' => $pin,
        'dns' => $dns,
        'warnings' => $warnings,
        'attempts' => $f['attempts'],
        'blocked' => $f['blocked'],
        'error' => null,
    ];
}

/* ---------------------------------------------------------------------
 * Vouches we receive
 * --------------------------------------------------------------------- */

/**
 * Look up $from's chain and store its newest active vouch for us (or remove
 * it if there is none any more). Returns ['ok', 'error', 'vouch'].
 */
function vouch_import(string $from): array
{
    $me = Chain::state();
    if (empty($me['fp'])) return ['ok' => false, 'error' => 'This Seal ID is not set up.'];
    $from = Chain::normUrl($from);
    if ($from === null || $from === $me['url']) return ['ok' => false, 'error' => 'Not a valid Seal ID address.'];
    $r = peer_verify($from, false);
    if (!$r['ok']) return ['ok' => false, 'error' => $r['error'], 'unreachable' => true];
    if ($r['pin'] === 'changed') return ['ok' => false, 'error' => 'That identity changed in a way that does not extend what was seen before. Check it in the admin page first.'];
    $found = null;
    foreach ($r['vouches'] as $v) {
        if ($v['target'] === $me['url'] && in_array($v['target_fp'], $me['fps'], true)) $found = $v;   // newest wins (ascending seq)
    }
    return with_lock(function () use ($from, $found, $r) {
        $all = jread('vouches.json', []);
        $all = array_values(array_filter($all, fn($v) => $v['url'] !== $from));
        if ($found) {
            $all[] = [
                'url' => $from, 'seq' => $found['seq'], 'fp' => $r['fp'], 'name' => $r['name'],
                'ts' => $found['ts'], 'proofs' => $found['proofs'], 'checked' => time(),
                // Small, hash-checked copy of their picture for the "Verified by" list.
                'avatar' => is_string($r['avatar'] ?? null) && strlen($r['avatar']) <= 120000 ? $r['avatar'] : null,
            ];
        }
        usort($all, fn($a, $b) => $b['ts'] <=> $a['ts']);
        jwrite('vouches.json', $all);
        peer_pin_save($r);
        Chain::writeBundle();
        return $found
            ? ['ok' => true, 'error' => null, 'vouch' => $found]
            : ['ok' => false, 'error' => 'No current vouch for this Seal ID was found in ' . $from . '’s chain.'];
    });
}

/** Re-read one voucher whose vouch was last checked more than a day ago. */
function vouches_refresh(): void
{
    $all = jread('vouches.json', []);
    usort($all, fn($a, $b) => ($a['checked'] ?? 0) <=> ($b['checked'] ?? 0));
    $v = $all[0] ?? null;
    if (!$v || time() - (int)($v['checked'] ?? 0) < 86400) return;
    $r = vouch_import($v['url']);
    if (!$r['ok'] && !empty($r['unreachable'])) {
        // Keep it, try again tomorrow.
        with_lock(function () use ($v) {
            $all = jread('vouches.json', []);
            foreach ($all as &$x) if ($x['url'] === $v['url']) $x['checked'] = time();
            jwrite('vouches.json', $all);
        });
    }
}

/* ---------------------------------------------------------------------
 * Vouches we give: notify the other installation
 * --------------------------------------------------------------------- */

function vouch_notify(string $target, int $seq): array
{
    $me = Chain::state();
    $r = http_fetch($target . '/api.php?a=inbox', [
        'method' => 'POST',
        'body' => json_encode(['from' => $me['url'], 'seq' => $seq]),
        'headers' => ['Content-Type: application/json'],
        'timeout' => 25,
    ]);
    $j = json_decode($r['body'] ?? '', true);
    $ok = $r['status'] >= 200 && $r['status'] < 300 && is_array($j) && !empty($j['ok']);
    $res = [
        'ok' => $ok,
        'at' => time(),
        'detail' => $ok ? 'Delivered: ' . $target . ' confirmed the vouch.'
            : (http_looks_blocked($r) ? 'Their host blocked the notification. They can import it by entering your address.'
            : (is_array($j) && !empty($j['error']) ? 'They answered: ' . $j['error'] : 'Not delivered (' . ($r['status'] ? 'HTTP ' . $r['status'] : $r['error']) . '). They can import it by entering your address.')),
    ];
    with_lock(function () use ($seq, $res) {
        $o = jread('outbox.json', []);
        $o[(string)$seq] = $res;
        jwrite('outbox.json', $o);
    });
    return $res;
}

/* ---------------------------------------------------------------------
 * Aliases (1.2.0): a domain with a verified website/DNS proof can stand
 * for the Seal ID it proves. jeffbristow.com → https://id.bristow.ch
 * --------------------------------------------------------------------- */

/** Seal IDs a domain points to: [[url, token|null, how], …] from its proof file and DNS record. */
function peer_alias_targets(string $host): array
{
    $out = [];
    $r = http_fetch("https://$host/.well-known/seal-id.txt?sealid=" . time(), ['accept' => 'text/plain', 'max_bytes' => 65536, 'headers' => ['Cache-Control: no-cache']]);
    if ($r['status'] === 200 && preg_match_all('#Verifying my Seal ID (https://[^\s]+) (sid1:[A-Za-z0-9_-]{22})#', $r['body'], $m, PREG_SET_ORDER)) {
        foreach ($m as $x) if ($u = Chain::normUrl($x[1])) $out[] = [$u, $x[2], 'web'];
    }
    foreach (dns_txt("_seal-id.$host") ?? [] as $t) {
        if (preg_match('#\bid=(https://[^\s;]+)#', $t, $mm) && ($u = Chain::normUrl($mm[1]))) {
            $out[] = [$u, preg_match('/sid1:[A-Za-z0-9_-]{22}/', $t, $tk) ? $tk[0] : null, 'dns'];
        }
    }
    return $out;
}

/**
 * Look up whatever the user typed: a Seal ID address, or a domain that is a
 * verified alias of one. The alias only counts if the Seal ID it points to
 * has a VERIFIED website or DNS proof for that same domain.
 */
function peer_lookup(string $input, bool $checkProofs = true): array
{
    $url = Chain::normUrl($input);
    if ($url === null) return ['ok' => false, 'url' => $input, 'error' => 'That is not a valid address.', 'attempts' => [], 'blocked' => false, 'warnings' => [], 'dns' => null];
    $r = peer_verify($url, $checkProofs);
    if ($r['ok'] || isset($r['source'])) return $r;          // a Seal ID (valid or not) answered here
    $host = (string)parse_url($url, PHP_URL_HOST);
    if (parse_url($url, PHP_URL_PATH)) return $r;            // aliases are bare domains
    $tried = [];
    foreach (peer_alias_targets($host) as [$target, $token, $how]) {
        if (isset($tried[$target]) || $target === $url) continue;
        $tried[$target] = true;
        $t = peer_verify($target, true);
        if (!$t['ok']) continue;
        foreach ($t['proofs'] as $p) {
            if (in_array($p['service'], ['web', 'dns'], true) && $p['handle'] === $host && $p['status'] === 'verified' && ($token === null || $token === $p['token'])) {
                $t['alias'] = $host;
                array_unshift($t['warnings'], "$host is a verified alias of this Seal ID.");
                return $t;
            }
        }
    }
    if ($tried) $r['error'] = "$host points to a Seal ID, but that Seal ID has no verified proof for $host — so it is not a valid alias.";
    return $r;
}
