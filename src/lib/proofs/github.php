<?php
declare(strict_types=1);

/** GitHub: a public gist containing the proof text. */
final class Proof_github extends ProofService
{
    public const ID = 'github';
    public const LABEL = 'GitHub';
    public const HANDLE_HINT = 'username';
    public const LOCATOR = true;

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?(www\.)?github\.com/#i', '', trim($raw));
        $h = ltrim(trim($h, '/'), '@');
        return preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://github.com/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in to GitHub as <b>' . h($handle) . '</b>, open <a href="https://gist.github.com/" target="_blank" rel="noopener">gist.github.com</a>.',
            'Create a <b>public</b> gist named <code>seal-id.md</code> containing:',
            'Paste the gist’s address below.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        return "https://gist.github.com/$handle/…";
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        if (!preg_match('#^https://gist\.github\.com/(?:([A-Za-z0-9-]+)/)?([0-9a-f]{20,40})/?$#i', trim($url), $m)) return null;
        if ($m[1] !== '' && strcasecmp($m[1], $handle) !== 0) return null;
        return "https://gist.github.com/$handle/" . strtolower($m[2]);
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        preg_match('#([0-9a-f]{20,40})/?$#i', (string)$locator, $m);
        $r = http_json('https://api.github.com/gists/' . $m[1], ['accept' => 'application/vnd.github+json']);
        if ($r['status'] !== 200 || !is_array($r['json'])) return self::httpProblem($r, 'The gist');
        $owner = (string)($r['json']['owner']['login'] ?? '');
        if (strcasecmp($owner, $handle) !== 0) return self::res('failed', "The gist belongs to $owner, not $handle.");
        foreach (($r['json']['files'] ?? []) as $f) {
            if (is_string($f['content'] ?? null) && str_contains($f['content'], $token)) return self::res('verified', 'Found in the gist.');
        }
        return self::res('failed', 'The gist does not contain this proof.');
    }
}
