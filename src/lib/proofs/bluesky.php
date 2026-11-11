<?php
declare(strict_types=1);

/** Bluesky: a post, read through the public AppView API. */
final class Proof_bluesky extends ProofService
{
    public const ID = 'bluesky';
    public const LABEL = 'Bluesky';
    public const HANDLE_HINT = 'name.bsky.social';
    public const LOCATOR = true;
    private const API = 'https://public.api.bsky.app/xrpc/';

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?bsky\.app/profile/#i', '', trim($raw));
        $h = strtolower(ltrim(trim($h, '/'), '@'));
        return preg_match('/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://bsky.app/profile/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in as <b>@' . h($handle) . '</b>, post exactly this:',
            'Open the post, copy its address and paste it below.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        return "https://bsky.app/profile/$handle/post/…";
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        if (!preg_match('#^https://bsky\.app/profile/([A-Za-z0-9.:-]+)/post/([a-z0-9]{8,20})/?$#', trim($url), $m)) return null;
        if (!str_starts_with($m[1], 'did:') && strtolower($m[1]) !== $handle) return null;
        return "https://bsky.app/profile/{$m[1]}/post/{$m[2]}";
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $r = http_json(self::API . 'com.atproto.identity.resolveHandle?handle=' . rawurlencode($handle));
        if ($r['status'] !== 200 || !is_string($r['json']['did'] ?? null)) return self::httpProblem($r, 'The Bluesky account');
        $did = $r['json']['did'];
        preg_match('#/profile/([^/]+)/post/([a-z0-9]+)#', (string)$locator, $m);
        if (str_starts_with($m[1], 'did:') && $m[1] !== $did) return self::res('failed', 'The post belongs to another account.');
        $r = http_json(self::API . 'app.bsky.feed.getPosts?uris=' . rawurlencode("at://$did/app.bsky.feed.post/{$m[2]}"));
        if ($r['status'] !== 200 || !is_array($r['json'])) return self::httpProblem($r, 'The post');
        $post = $r['json']['posts'][0] ?? null;
        if (!$post) return self::res('failed', 'The post was not found (it may have been deleted).');
        if (($post['author']['did'] ?? '') !== $did) return self::res('failed', 'The post belongs to another account.');
        return str_contains((string)($post['record']['text'] ?? ''), $token)
            ? self::res('verified', 'Found in the post.')
            : self::res('failed', 'The post does not contain this proof.');
    }
}
