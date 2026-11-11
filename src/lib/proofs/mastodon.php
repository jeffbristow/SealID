<?php
declare(strict_types=1);

/** Mastodon (and compatible Fediverse servers): a public post. */
final class Proof_mastodon extends ProofService
{
    public const ID = 'mastodon';
    public const LABEL = 'Mastodon';
    public const HANDLE_HINT = 'user@instance.social';
    public const LOCATOR = true;

    public static function normalize(string $raw): ?string
    {
        $r = trim($raw);
        if (preg_match('#^https://([a-z0-9.-]+)/@([A-Za-z0-9_]+)/?$#i', $r, $m)) $r = $m[2] . '@' . $m[1];
        $r = ltrim($r, '@');
        if (!preg_match('/^([A-Za-z0-9_]{1,64})@([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)$/i', $r, $m)) return null;
        return $m[1] . '@' . strtolower($m[2]);
    }

    public static function profileUrl(string $handle): ?string
    {
        [$u, $i] = explode('@', $handle, 2);
        return "https://$i/@$u";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in as <b>@' . h($handle) . '</b>, publish a <b>public</b> post with exactly this:',
            'Copy the post’s address (on your own server) and paste it below.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        [$u, $i] = explode('@', $handle, 2);
        return "https://$i/@$u/…";
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        [$u, $i] = explode('@', $handle, 2);
        $re = '#^https://' . preg_quote($i, '#') . '/(?:@' . preg_quote($u, '#') . '|users/' . preg_quote($u, '#') . '/statuses)/(\d{1,25})/?$#i';
        if (!preg_match($re, trim($url), $m)) return null;
        return "https://$i/@$u/{$m[1]}";
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        [$u, $i] = explode('@', $handle, 2);
        preg_match('#/(\d+)$#', (string)$locator, $m);
        $r = http_json("https://$i/api/v1/statuses/{$m[1]}");
        if ($r['status'] !== 200 || !is_array($r['json'])) return self::httpProblem($r, 'The post');
        $acct = strtolower((string)($r['json']['account']['acct'] ?? ''));
        if ($acct !== strtolower($u) && $acct !== strtolower($handle)) return self::res('failed', "The post was written by @$acct.");
        return self::hasToken((string)($r['json']['content'] ?? ''), $token)
            ? self::res('verified', 'Found in the post.')
            : self::res('failed', 'The post does not contain this proof.');
    }
}
