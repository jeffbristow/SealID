<?php
declare(strict_types=1);

/** YouTube: the channel description. */
final class Proof_youtube extends ProofService
{
    public const ID = 'youtube';
    public const LABEL = 'YouTube';
    public const HANDLE_HINT = '@channel';

    public static function normalize(string $raw): ?string
    {
        $h = (string)preg_replace('#^(https?://)?(www\.|m\.)?youtube\.com/#i', '', trim($raw));
        $h = trim($h, '/');
        if (!str_starts_with($h, '@')) $h = '@' . $h;
        return preg_match('/^@[A-Za-z0-9._-]{3,30}$/', $h) ? $h : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return "https://www.youtube.com/$handle";
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'In YouTube Studio for <b>' . h($handle) . '</b>, open <b>Customisation → Profile</b> and add this line to the channel description:',
            'Publish, then press “Check now”.',
        ];
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $r = http_fetch("https://www.youtube.com/$handle/about", [
            'accept' => 'text/html',
            'headers' => ['Accept-Language: en-US,en;q=0.8', 'Cookie: CONSENT=YES+1; SOCS=CAI'],
            'max_bytes' => 4 * 1048576,
            'ua' => 'Mozilla/5.0 (compatible; SealID/' . SEALID_VERSION . ')',
        ]);
        if ($r['status'] !== 200) return self::httpProblem($r, 'The channel');
        if (stripos($r['body'], $handle) === false) {
            return self::res('unreachable', 'YouTube did not return the channel page.');
        }
        return str_contains($r['body'], $token)
            ? self::res('verified', 'Found in the channel description.')
            : self::res('failed', 'The channel description does not contain this proof.');
    }
}
