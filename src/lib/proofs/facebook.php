<?php
declare(strict_types=1);

/**
 * Facebook: a PUBLIC post. Facebook's page for a public post carries the
 * standard link-preview tags: og:url (facebook.com/<account>/posts/…, so the
 * author) and og:description (the post's text). Seal ID asks for the page
 * honestly, as itself, and checks both (1.2.4 — before, Facebook proofs were
 * witnessed only).
 *
 * If Facebook answers with a login page instead (it may, for some servers or
 * regions), the proof is "not reachable right now" — not failed — and other
 * Seal ID owners can still witness it when they vouch.
 */
final class Proof_facebook extends ProofService
{
    public const ID = 'facebook';
    public const LABEL = 'Facebook';
    public const HANDLE_HINT = 'profile name';
    public const LOCATOR = true;

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?(www\.|m\.)?facebook\.com/#i', '', trim($raw));
        $h = trim($h, '/');
        if (preg_match('/^profile\.php\?id=(\d{5,20})$/', $h, $m)) return $m[1];
        return preg_match('/^[A-Za-z0-9.]{5,50}$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return ctype_digit($handle) ? "https://www.facebook.com/profile.php?id=$handle" : "https://www.facebook.com/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Signed in to Facebook as <b>' . h($handle) . '</b>, publish a post set to <b>Public</b> containing exactly:',
            'Open the post (or use Share → Copy link), and paste its address below.',
            'The post must stay Public: Seal ID reads it the way a link preview does. If Facebook ever hides it from servers, other Seal ID owners can still witness it when they vouch for you.',
        ];
    }

    public static function locatorHint(string $handle): string
    {
        return 'https://www.facebook.com/…';
    }

    public static function locatorOk(string $handle, string $url): ?string
    {
        $u = trim($url);
        if (!preg_match('#^https://(?:www\.|m\.)?facebook\.com/[^\s"<>]{3,300}$#i', $u)) return null;
        return (string)preg_replace('#^https://(?:www\.|m\.)?#i', 'https://www.', $u);
    }

    /** The account a post URL belongs to: its username, or a numeric id. */
    private static function ownerOf(string $postUrl): ?string
    {
        $p = parse_url(html_entity_decode($postUrl, ENT_QUOTES));
        if (!$p || !preg_match('#(^|\.)facebook\.com$#i', (string)($p['host'] ?? ''))) return null;
        $path = (string)($p['path'] ?? '');
        if (preg_match('#^/([A-Za-z0-9.]{5,50})/(posts|videos|photos)/#', $path, $m)) return $m[1];
        parse_str((string)($p['query'] ?? ''), $q);
        if (in_array($path, ['/permalink.php', '/story.php'], true) && isset($q['id']) && ctype_digit((string)$q['id'])) return (string)$q['id'];
        return null;
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $r = http_fetch((string)$locator, ['accept' => 'text/html', 'redirects' => 5, 'max_bytes' => 4 * 1048576, 'timeout' => 20]);
        if ($r['status'] !== 200) return self::httpProblem($r, 'The post');
        return self::checkPage($r['body'], $r['url'], $handle, $token);
    }

    /** The decision, from the post's page and the address it ended at (separate for tests). */
    public static function checkPage(string $html, string $finalUrl, string $handle, string $token): array
    {
        $og = [];
        if (preg_match_all('#<meta\s[^>]*>#i', $html, $tags)) {
            foreach ($tags[0] as $tag) {
                if (!preg_match('#\bproperty\s*=\s*["\']og:(url|description|title)["\']#i', $tag, $p)) continue;
                if (!preg_match('#\bcontent\s*=\s*"([^"]*)"|\bcontent\s*=\s*\'([^\']*)\'#i', $tag, $c)) continue;
                $og[strtolower($p[1])] ??= html_entity_decode($c[1] !== '' ? $c[1] : ($c[2] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
        }
        if (!isset($og['description']) && !isset($og['url'])) {
            return self::res('unreachable', 'Facebook showed a login page instead of the post — it may not be Public, or Facebook is hiding it from servers right now. Other Seal ID owners can still witness it.');
        }
        $owner = self::ownerOf($og['url'] ?? '') ?? self::ownerOf($finalUrl);
        if ($owner === null) return self::res('unreachable', 'Facebook did not say whose post this is.');
        if (strcasecmp($owner, $handle) !== 0) return self::res('failed', "The post belongs to $owner, not $handle.");
        return str_contains($og['description'] ?? '', $token)
            ? self::res('verified', 'Found in the public post.')
            : self::res('failed', 'The post does not contain this proof (it must be Public and contain the exact text).');
    }
}
