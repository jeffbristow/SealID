<?php
/**
 * Live reachability check of every proof service from THIS server's network.
 * Uses real public accounts with a token that can't be there, so a working
 * checker answers "failed" (reached, author ok, token missing) — "unreachable"
 * means the service blocked or didn't answer this server.
 *   php tests/live-proofs.php
 */
declare(strict_types=1);
require __DIR__ . '/../src/lib/bootstrap.php';

$token = 'sid1:ThisTokenIsNotThere00';
$cases = [
    ['web', 'bristow.ch', null],
    ['dns', 'bristow.ch', null],
    ['github', 'octocat', 'https://gist.github.com/octocat/6cad326836d38bd3a7ae'],
    ['x', 'jack', 'https://x.com/jack/status/20'],
    ['x', 'someoneelse', 'https://x.com/someoneelse/status/20'],
    ['mastodon', 'Gargron@mastodon.social', 'https://mastodon.social/@Gargron/1'],
    ['bluesky', 'bsky.app', 'https://bsky.app/profile/bsky.app/post/3l6oveex3ii2l'],
    ['hackernews', 'pg', null],
    ['reddit', 'spez', 'https://www.reddit.com/r/announcements/comments/3djjxw/'],
    ['reddit', 'someoneelse', 'https://www.reddit.com/r/announcements/comments/3djjxw/'],
    ['youtube', '@YouTube', null],
    ['facebook', 'zuck', 'https://www.facebook.com/zuck/posts/10114'],
];
foreach ($cases as [$svc, $handle, $loc]) {
    $t = microtime(true);
    $r = proof_check(['service' => $svc, 'handle' => $handle, 'token' => $token], $loc);
    printf("%-10s %-24s %-12s %5.1fs  %s\n", $svc, $handle, $r['status'], microtime(true) - $t, $r['detail']);
}
