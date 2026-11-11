<?php
declare(strict_types=1);

/**
 * Facebook: no server can read Facebook posts without a Meta-approved app, so
 * this proof is "witnessed": other Seal ID owners open the post, see it with
 * their own eyes and vouch for it.
 */
final class Proof_facebook extends ProofService
{
    public const ID = 'facebook';
    public const LABEL = 'Facebook';
    public const HANDLE_HINT = 'profile name';
    public const LOCATOR = true;
    public const AUTO = false;

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
            'Copy the post’s address and paste it below.',
            'Facebook does not let servers read posts, so this proof is <b>witnessed</b>: other Seal ID owners open the post when they vouch for you and confirm it. Your profile shows who witnessed it.',
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

    public static function check(string $handle, ?string $locator, string $token): array
    {
        return self::res('pending', 'Witnessed by people, not checked by servers.');
    }
}
