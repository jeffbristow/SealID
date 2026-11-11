<?php
declare(strict_types=1);

/** A website you control: a line in https://<domain>/.well-known/seal-id.txt */
final class Proof_web extends ProofService
{
    public const ID = 'web';
    public const LABEL = 'Website';
    public const HANDLE_HINT = 'example.com';

    public static function normalize(string $raw): ?string
    {
        $d = strtolower(trim((string)preg_replace('#^https?://#i', '', trim($raw)), '/'));
        if (str_contains($d, '/')) return null;
        return preg_match('/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/', $d) ? $d : null;
    }

    public static function profileUrl(string $handle): ?string
    {
        return 'https://' . $handle;
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'Create the file <code>https://' . h($handle) . '/.well-known/seal-id.txt</code> on that website.',
            'Put this line in it (one line per proof; other lines are ignored):',
        ];
    }

    public static function check(string $handle, ?string $locator, string $token): array
    {
        $file = "https://$handle/.well-known/seal-id.txt";
        // Cache-buster: hosts and CDNs may keep serving a cached 404 from before the file existed.
        $r = http_fetch($file . '?sealid=' . time(), ['accept' => 'text/plain, */*;q=0.5', 'max_bytes' => 65536, 'headers' => ['Cache-Control: no-cache']]);
        if ($r['status'] !== 200) return self::httpProblem($r, $file);
        $host = strtolower((string)parse_url($r['url'], PHP_URL_HOST));
        if ($host !== $handle && $host !== "www.$handle") {
            return self::res('failed', 'The file redirected to another site (' . $host . ').');
        }
        return str_contains($r['body'], $token)
            ? self::res('verified', 'Found in /.well-known/seal-id.txt.')
            : self::res('failed', 'The file exists but does not contain this proof.');
    }
}
