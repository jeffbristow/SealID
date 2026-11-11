<?php
declare(strict_types=1);

/** Reddit: a post by the account (e.g. on your own profile). */
final class Proof_reddit extends ProofService
{
    public const ID = 'reddit';
    public const LABEL = 'Reddit';
    public const HANDLE_HINT = 'username';
    public const LOCATOR = true;

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?(www\.|old\.)?reddit\.com/(u|user)/#i', '', trim($raw));
        $h = (string)preg_replace('#^/?u/#i', '', trim($h, '/'));
        return preg_match('/^[A-Za-z0-9_-]{3,20}$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://www.reddit.com/user/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in as <b>u/' . h($handle) . '</b>, create a post on your profile (or in any community) whose <b>title</b> is:',
            'Copy the post’s address and paste it below.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        return "https://www.reddit.com/user/$handle/comments/…";
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        if (!preg_match('#^https://(?:www\.|old\.|new\.)?reddit\.com/(r|u|user)/([A-Za-z0-9_-]+)/comments/([a-z0-9]{4,12})#i', trim($url), $m)) return null;
        $kind = strtolower($m[1]) === 'r' ? 'r' : 'user';
        return "https://www.reddit.com/$kind/{$m[2]}/comments/" . strtolower($m[3]) . '/';
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        preg_match('#/comments/([a-z0-9]+)#i', (string)$locator, $m);
        // Reddit's oEmbed service answers servers that the JSON API blocks
        // (datacenter IPs). It gives the author and the title.
        $o = http_json('https://www.reddit.com/oembed?url=' . rawurlencode((string)$locator));
        if ($o['status'] === 200 && is_array($o['json']) && isset($o['json']['author_name'])) {
            if (strcasecmp((string)$o['json']['author_name'], $handle) !== 0) return self::res('failed', 'The post was written by u/' . $o['json']['author_name'] . '.');
            if (self::hasToken((string)($o['json']['html'] ?? '') . ' ' . (string)($o['json']['title'] ?? ''), $token)) return self::res('verified', 'Found in the post title.');
            $titleChecked = true;
        }
        $r = ['status' => 0, 'error' => 'not tried', 'body' => ''];
        foreach (['https://www.reddit.com/comments/', 'https://old.reddit.com/comments/'] as $base) {
            $r = http_json($base . $m[1] . '.json?raw_json=1');
            if ($r['status'] === 200) break;
        }
        $post = $r['json'][0]['data']['children'][0]['data'] ?? null;
        if ($r['status'] !== 200 || !is_array($post)) {
            if (!empty($titleChecked)) return self::res('failed', 'The post title does not contain this proof.');
            return self::httpProblem($r, 'The post');
        }
        if (strcasecmp((string)($post['author'] ?? ''), $handle) !== 0) return self::res('failed', 'The post was written by u/' . ($post['author'] ?? '?') . '.');
        return str_contains(($post['title'] ?? '') . ' ' . ($post['selftext'] ?? ''), $token)
            ? self::res('verified', 'Found in the post.')
            : self::res('failed', 'The post does not contain this proof.');
    }
}
