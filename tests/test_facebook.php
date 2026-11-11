<?php
/** Facebook proof page checks (included by tests/run.php) — offline, canned pages. */
declare(strict_types=1);
require_once __DIR__ . '/../src/lib/proofs.php';
require_once __DIR__ . '/../src/lib/proofs/facebook.php';
if (!function_exists('h')) { function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES); } }

$tok = 'sid1:A-Cu3wjccOWtuxsJ8vosEl';
$text = "Verifying my Seal ID https://id.bristow.ch $tok";
$page = fn(string $url, string $desc, bool $swap = false) => '<html><head><meta property="og:title" content="Jeff Bristow" />'
    . ($swap ? '<meta content="' . htmlspecialchars($url) . '" property="og:url" />' : '<meta property="og:url" content="' . htmlspecialchars($url) . '" />')
    . '<meta property="og:description" content="' . htmlspecialchars($desc) . '" /></head><body>…</body></html>';
$final = 'https://www.facebook.com/jeffbristow/posts/pfbid022Tj?rdid=x&share_url=https%3A%2F%2Fwww.facebook.com%2Fshare%2Fp%2F1Fb%2F';

$fb = fn(string $html, string $handle = 'jeffbristow', string $url = '') => Proof_facebook::checkPage($html, $url ?: $final, $handle, $tok)['status'];
t('facebook: right account + token → verified', $fb($page('https://www.facebook.com/jeffbristow/posts/verifying-my-seal-id/10163672594918123/', $text)) === 'verified');
t('facebook: account name compared without case', $fb($page('https://www.facebook.com/JeffBristow/posts/x/1/', $text)) === 'verified');
t('facebook: attributes in either order', $fb($page('https://www.facebook.com/jeffbristow/posts/x/1/', $text, true)) === 'verified');
t('facebook: someone else\'s post → failed', $fb($page('https://www.facebook.com/mallory.x/posts/x/1/', $text), 'jeffbristow', 'https://www.facebook.com/mallory.x/posts/1') === 'failed');
t('facebook: token missing → failed', $fb($page('https://www.facebook.com/jeffbristow/posts/x/1/', 'Hello world')) === 'failed');
t('facebook: login page → not reachable (not failed)', $fb('<html><head><title>Log in to Facebook</title></head></html>') === 'unreachable');
t('facebook: an og:url on another site does not name the owner', $fb($page('https://evil.example/jeffbristow/posts/x/1/', $text), 'jeffbristow', 'https://evil.example/x') === 'unreachable');
t('facebook: numeric profile ids (permalink.php?id=)', Proof_facebook::checkPage($page('https://www.facebook.com/permalink.php?story_fbid=5&id=100012345678', $text), 'https://www.facebook.com/x', '100012345678', $tok)['status'] === 'verified');
