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
