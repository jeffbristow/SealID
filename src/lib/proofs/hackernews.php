<?php
declare(strict_types=1);

/** Hacker News: the "about" field of the profile. */
final class Proof_hackernews extends ProofService
{
    public const ID = 'hackernews';
    public const LABEL = 'Hacker News';
    public const HANDLE_HINT = 'username';

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?news\.ycombinator\.com/user\?id=#i', '', trim($raw));
        return preg_match('/^[A-Za-z0-9_-]{2,15}$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://news.ycombinator.com/user?id=$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in to Hacker News as <b>' . h($handle) . '</b>, open your profile and add this to the <b>about</b> box:',
            'Save, then press “Check now”.',
        ];
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $r = http_fetch("https://hacker-news.firebaseio.com/v0/user/$handle.json");
        if ($r['status'] !== 200) return self::httpProblem($r, 'The profile');
        $j = json_decode($r['body'], true);
        if (!is_array($j)) return self::res('failed', "There is no Hacker News user $handle.");
        if (($j['id'] ?? '') !== $handle) return self::res('failed', 'User names must match exactly (case matters on Hacker News).');
        return self::hasToken((string)($j['about'] ?? ''), $token)
            ? self::res('verified', 'Found in the profile.')
            : self::res('failed', 'The profile does not contain this proof.');
    }
}
