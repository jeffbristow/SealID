<?php
declare(strict_types=1);

/** X (Twitter): a public post, read through X's public oEmbed service. */
final class Proof_x extends ProofService
{
    public const ID = 'x';
    public const LABEL = 'X (Twitter)';
    public const HANDLE_HINT = 'username';
    public const LOCATOR = true;

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?(www\.)?(x|twitter)\.com/#i', '', trim($raw));
        $h = ltrim(trim($h, '/'), '@');
        return preg_match('/^[A-Za-z0-9_]{1,15}$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://x.com/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in to X as <b>@' . h($handle) . '</b>, post exactly this (keep it public and don’t delete it):',
            'Open the post, copy its address and paste it below.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        return "https://x.com/$handle/status/…";
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        if (!preg_match('#^https://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/(\d{1,25})#i', trim($url), $m)) return null;
        if (strcasecmp($m[1], $handle) !== 0) return null;
        return "https://x.com/$handle/status/{$m[2]}";
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        preg_match('#/status/(\d+)#', (string)$locator, $m);
        $u = 'https://publish.twitter.com/oembed?omit_script=1&url=' . rawurlencode("https://twitter.com/$handle/status/{$m[1]}");
        $r = http_json($u);
        if ($r['status'] !== 200 || !is_array($r['json'])) return self::httpProblem($r, 'The post');
        $author = strtolower(rtrim((string)($r['json']['author_url'] ?? ''), '/'));
        if (!preg_match('#/' . preg_quote(strtolower($handle), '#') . '$#', $author)) {
            return self::res('failed', 'The post was written by ' . ($r['json']['author_name'] ?? 'someone else') . '.');
        }
        return self::hasToken((string)($r['json']['html'] ?? ''), $token)
            ? self::res('verified', 'Found in the post.')
            : self::res('failed', 'The post does not contain this proof.');
    }
}
