<?php
declare(strict_types=1);

/** A domain you control: TXT record _seal-id.<domain> = sid1:<token> */
final class Proof_dns extends ProofService
{
    public const ID = 'dns';
    public const LABEL = 'Domain (DNS)';
    public const HANDLE_HINT = 'example.com';

    public static function normalize(string $raw): ?string
    {
        return Proof_web::normalize($raw);
    }

    public static function profileUrl(string $handle): ?string
    {
        return 'https://' . $handle;
    }

    public static function publishText(string $text, string $token): string
    {
        return $token;
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'At your DNS provider, add a <b>TXT</b> record named <code>_seal-id.' . h($handle) . '</code> (some providers only want <code>_seal-id</code>).',
            'Set its value to:',
            'DNS changes can take a while to appear. Press “Check now” later.',
        ];
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $txt = dns_txt("_seal-id.$handle");
        if ($txt === null) return self::res('unreachable', 'The DNS lookup failed.');
        foreach ($txt as $t) {
            if (str_contains($t, $token)) return self::res('verified', "Found in the TXT record _seal-id.$handle.");
        }
        return self::res('failed', $txt ? "_seal-id.$handle has TXT records, but not this proof." : "No TXT record at _seal-id.$handle yet.");
    }
}
