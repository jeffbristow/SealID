<?php
/**
 * Seal ID — public JSON API (docs/PROTOCOL.md section 7).
 *   GET  ?a=bundle   the identity bundle (same as /.well-known/seal-id.json)
 *   GET  ?a=key      the current public key (armored)
 *   GET  ?a=status   proof statuses; re-checks a few stale proofs
 *   POST ?a=inbox    {from, seq}  "I vouched for you"
 *   POST ?a=reach    {url}        "can you reach this Seal ID?"
 */
declare(strict_types=1);
require __DIR__ . '/lib/bootstrap.php';

$a = (string)($_GET['a'] ?? '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}

try {
    switch ($a) {
        case 'bundle':
            if (!is_installed()) json_out(['ok' => false, 'error' => 'Not set up yet.'], 404, true);
            json_out(Chain::bundle(), 200, true);

        case 'avatar':
            $av = avatar_current();
            if (!$av) { http_response_code(404); exit; }
            header('Content-Type: ' . $av['mime']);
            header('Content-Length: ' . filesize($av['file']));
            // The URL carries the hash, so it can be cached for long.
            header('Cache-Control: public, max-age=' . (isset($_GET['h']) && str_starts_with($av['sha'], (string)$_GET['h']) ? '2592000, immutable' : '300'));
            header('Access-Control-Allow-Origin: *');
            header('X-Content-Type-Options: nosniff');
            header("Content-Security-Policy: default-src 'none'; sandbox");
            readfile($av['file']);
            exit;

        case 'key':
            $st = Chain::state();
            if (empty($st['key'])) { http_response_code(404); exit; }
            header('Content-Type: application/pgp-keys; charset=utf-8');
            header('Content-Disposition: inline; filename="' . strtolower(substr($st['fp'], -16)) . '.asc"');
            header('Access-Control-Allow-Origin: *');
            header('X-Content-Type-Options: nosniff');
            echo $st['key'];
            exit;

        case 'status':
            if (!is_installed()) fail(404, 'Not set up yet.');
            if (rate_limit('status', 20, 60)) {
                own_recheck((int)cfg('recheck_per_view', 2));
                vouches_refresh();
            }
            $out = [];
            foreach (own_proofs() as $p) {
                $out[] = ['seq' => $p['seq'], 'status' => $p['status'], 'label' => status_label($p['status']), 'detail' => $p['detail'], 'checked' => $p['checked']];
            }
            json_out(['ok' => true, 'proofs' => $out], 200, true);

        case 'inbox':
            if ($method !== 'POST') fail(405, 'POST only.');
            if (!is_installed()) fail(404, 'Not set up yet.');
            if (!rate_limit('inbox', 12, 3600)) fail(429, 'Too many notifications. Try again later.');
            $b = body_json();
            $from = Chain::normUrl((string)($b['from'] ?? ''));
            if ($from === null) fail(400, 'Missing or bad "from" address.');
            $r = vouch_import($from);
            json_out(['ok' => $r['ok'], 'error' => $r['error'] ?? null], $r['ok'] ? 200 : 422);

        case 'claim':
            // 1.2.0 badge lookup: "does this Seal ID have a working proof for this domain/account?"
            //   GET ?a=claim&domain=jeff.bristow.ch   or   ?a=claim&service=github&handle=octocat
            if (!is_installed()) fail(404, 'Not set up yet.');
            if (!rate_limit('claim', 60, 60)) fail(429, 'Too many lookups.');
            $st = Chain::state();
            $domain = strtolower(trim((string)($_GET['domain'] ?? '')));
            $svc = (string)($_GET['service'] ?? '');
            $handle = (string)($_GET['handle'] ?? '');
            $match = null;
            foreach (own_proofs() as $p) {
                $hit = $domain !== ''
                    ? in_array($p['service'], ['web', 'dns'], true) && $p['handle'] === $domain
                    : $p['service'] === $svc && strcasecmp($p['handle'], $handle) === 0;
                if ($hit && ($match === null || $p['status'] === 'verified')) $match = $p;
            }
            $base = $st['url'];
            header('Cache-Control: public, max-age=300');
            json_out([
                'ok' => true,
                'verified' => $match !== null && in_array($match['status'], ['verified', 'witnessed'], true),
                'status' => $match['status'] ?? 'none',
                'service' => $match['service'] ?? ($domain !== '' ? 'web' : $svc),
                'handle' => $match['handle'] ?? ($domain !== '' ? $domain : $handle),
                'checked' => $match['checked'] ?? 0,
                'url' => $base,
                'profile' => $base . '/',
                'name' => $st['name'],
                'fp' => $st['fp'],
                'avatar' => ($a = avatar_url()) ? $base . '/' . $a : null,
            ], 200, true);

        case 'attest':
            // 1.2.0: Seal Chat delivers its signature for a sealchat proof. Self-verifying, so anyone may post it.
            //   POST {"sealchat": "sealchat:<onion>:<fp>", "key": armored public key, "sig": detached signature}
            if ($method !== 'POST') fail(405, 'POST only.');
            if (!is_installed()) fail(404, 'Not set up yet.');
            if (!rate_limit('attest', 20, 3600)) fail(429, 'Too many attempts.');
            $b = body_json();
            $st = Chain::state();
            proof_services();                       // loads the proof classes
            $want = Proof_sealchat::normalize((string)($b['sealchat'] ?? ''));
            $seq = null;
            foreach ($st['proofs'] as $s => $p) if ($p['service'] === 'sealchat' && $p['handle'] === $want) $seq = $s;
            if ($seq === null) fail(404, 'This Seal ID has no proof for that Seal Chat ID. Add it in the Seal ID admin first.');
            $att = ['key' => (string)($b['key'] ?? ''), 'sig' => (string)($b['sig'] ?? '')];
            [$ok, $why] = Proof_sealchat::checkAttestation($want, Chain::proofText($st['url'], $st['proofs'][$seq]['token']), $att);
            if (!$ok) fail(422, $why);
            with_lock(function () use ($seq, $att) {
                $all = jread('attestations.json', []);
                $all[(string)$seq] = $att + ['at' => time()];
                jwrite('attestations.json', $all);
            });
            own_recheck(1, true, $seq);
            Chain::writeBundle();
            json_out(['ok' => true, 'url' => $st['url'], 'seq' => $seq], 200, true);

        case 'reach':
            if ($method !== 'POST') fail(405, 'POST only.');
            if (!rate_limit('reach', 10, 3600)) fail(429, 'Too many tests. Try again later.');
            $b = body_json();
            $url = Chain::normUrl((string)($b['url'] ?? ''));
            if ($url === null) fail(400, 'Bad address.');
            $r = peer_verify($url, false);
            json_out([
                'ok' => $r['ok'],
                'checked_by' => Chain::url() ?? detected_base_url(),
                'url' => $url,
                'fp' => $r['fp'] ?? null,
                'seq' => $r['seq'] ?? null,
                'source' => $r['source'] ?? null,
                'mirror' => $r['mirror'] ?? false,
                'blocked' => $r['blocked'],
                'attempts' => $r['attempts'],
                'error' => $r['error'],
            ]);

        default:
            fail(400, 'Unknown action.');
    }
} catch (Throwable $e) {
    error_log('Seal ID api: ' . $e->getMessage());
    fail(500, 'Server error.');
}
