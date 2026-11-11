<?php
/**
 * Seal ID — shared HTML (Seal family look: dark slate + sealed green).
 */
declare(strict_types=1);

function page_start(string $title, array $o = []): void
{
    send_page_headers($o['wasm'] ?? false);
    $v = h(SEALID_VERSION);
    $desc = h($o['description'] ?? 'Seal ID — self-hosted identity proofs signed with OpenPGP.');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
        . '<meta name="color-scheme" content="dark">'
        . '<title>' . h($title) . '</title>'
        . '<meta name="description" content="' . $desc . '">'
        . ($o['noindex'] ?? false ? '<meta name="robots" content="noindex">' : '')
        . '<link rel="icon" type="image/svg+xml" href="assets/seal-id.svg">'
        . '<link rel="stylesheet" href="assets/site.css?v=' . $v . '">'
        . ($o['head'] ?? '')
        . '</head><body class="' . h($o['body_class'] ?? '') . '">';
    echo '<header class="topbar"><div class="wrap row between">'
        . '<a class="brand" href="./"><img src="assets/seal-id.svg" alt="" width="34" height="34"><span>Seal ID</span></a>'
        . '<nav class="nav">' . ($o['nav'] ?? '') . '</nav></div></header>';
}

function page_end(array $modules = [], array $data = []): void
{
    echo '<footer class="footer"><div class="wrap row between small muted">'
        . '<span><img src="assets/seal-id.svg" alt="" width="20" height="20" class="inline-logo"> Seal ID ' . h(SEALID_VERSION) . ' — self-hosted identity proofs</span>'
        . '<span><a href="' . h(SEALID_REPO) . '" target="_blank" rel="noopener">Open source</a> · part of the Seal family with Seal Post and Seal Chat</span>'
        . '</div></footer>';
    if ($data) {
        echo '<script type="application/json" id="sealid-data" nonce="' . h(csp_nonce()) . '">'
            . json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP)
            . '</script>';
    }
    foreach ($modules as $m) {
        echo '<script type="module" src="assets/' . h($m) . '?v=' . h(SEALID_VERSION) . '" nonce="' . h(csp_nonce()) . '"></script>';
    }
    echo '</body></html>';
}

/** Fingerprint in groups of four; the last 16 characters (the key ID) highlighted. */
function fp_html(?string $fp): string
{
    if (!$fp) return '';
    $g = str_split($fp, 4);
    $tail = array_splice($g, -4);
    return '<span class="fp"><span class="fp-head">' . h(implode(' ', $g)) . '</span> <b>' . h(implode(' ', $tail)) . '</b></span>';
}

function status_badge(string $status, string $title = ''): string
{
    return '<span class="badge s-' . h($status) . '"' . ($title !== '' ? ' title="' . h($title) . '"' : '') . '>' . h(status_label($status)) . '</span>';
}

function ago(int $ts): string
{
    if ($ts <= 0) return 'never';
    $d = time() - $ts;
    if ($d < 90) return 'just now';
    if ($d < 5400) return round($d / 60) . ' minutes ago';
    if ($d < 129600) return round($d / 3600) . ' hours ago';
    if ($d < 86400 * 45) return round($d / 86400) . ' days ago';
    return date('j M Y', $ts);
}

function service_letter(string $service): string
{
    return [
        'web' => 'W', 'dns' => 'D', 'github' => 'GH', 'x' => 'X', 'mastodon' => 'M', 'bluesky' => 'B',
        'hackernews' => 'Y', 'reddit' => 'R', 'youtube' => 'YT', 'facebook' => 'F',
    ][$service] ?? strtoupper(substr($service, 0, 1));
}
