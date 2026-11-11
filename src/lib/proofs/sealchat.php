<?php
declare(strict_types=1);

/**
 * Seal Chat (1.2.0): proves which Seal Chat ID belongs to this Seal ID.
 *
 * Handle: the Seal Chat ID "sealchat:<onion>:<fingerprint>".
 *   - Same key: if the Seal Chat fingerprint is one of this Seal ID's own keys,
 *     the signed chain already proves it ("same key").
 *   - Different key: the Seal Chat key signs the proof text (a detached OpenPGP
 *     signature). That "attestation" ({key, sig}) is published in the bundle
 *     under "attestations"; anyone can check it — it is self-verifying, so
 *     anyone may deliver it (Seal Chat does, via api.php?a=attest).
 */
final class Proof_sealchat extends ProofService
{
    public const ID = 'sealchat';
    public const LABEL = 'Seal Chat';
    public const HANDLE_HINT = 'sealchat:…onion…:FINGERPRINT';

    public static function parse(string $handle): ?array
    {
        if (!preg_match('/^sealchat:([a-z2-7]{55}d):([0-9A-F]{40}|[0-9A-F]{64})$/', $handle, $m)) return null;
        return ['onion' => $m[1], 'fp' => $m[2]];
    }

    public static function normalize(string $raw): ?string
    {
        $r = preg_replace('/\s+/', '', trim($raw));
        if (!preg_match('/^sealchat:([a-z2-7]{55}d):([0-9a-f]{40}|[0-9a-f]{64})$/i', (string)$r, $m)) return null;
        return 'sealchat:' . strtolower($m[1]) . ':' . strtoupper($m[2]);
    }

    public static function profileUrl(string $handle): ?string
    {
        return null;
    }

    public static function steps(string $handle, string $text, string $token): array
    {
        return [
            'If Seal Chat uses the <b>same key</b> as this Seal ID, there is nothing more to do: press “Check now”.',
            'Otherwise, in Seal Chat open <b>Settings → Seal ID</b> and link this Seal ID; Seal Chat signs this text with its own key and sends the signature here:',
        ];
    }

    /** Verify an attestation {key, sig} for $handle + $token's proof text. Returns [ok, why]. */
    public static function checkAttestation(string $handle, string $text, ?array $att): array
    {
        $p = self::parse($handle);
        if (!$p) return [false, 'Not a valid Seal Chat ID.'];
        if (!is_array($att) || !is_string($att['key'] ?? null) || !is_string($att['sig'] ?? null)) return [false, 'Waiting for Seal Chat to sign this proof.'];
        try { $k = Pgp::readKey($att['key']); } catch (PgpError $e) { return [false, 'Seal Chat key: ' . $e->getMessage()]; }
        if ($k['fp'] !== $p['fp']) return [false, 'The signing key is not this Seal Chat ID’s key.'];
        $v = Pgp::verifyAny($text, $att['sig'], $k);
        return $v['ok'] ? [true, 'Signed by the Seal Chat key.'] : [false, 'Seal Chat signature: ' . $v['error']];
    }

    /** $ctx: ['fps' => this identity's key fingerprints, 'url' => identity address, 'attestation' => {key, sig}|null] */
    public static function check(string $handle, ?string $locator, string $token, array $ctx = []): array
    {
        $p = self::parse($handle);
        if (!$p) return self::res('failed', 'Not a valid Seal Chat ID.');
        if (in_array($p['fp'], $ctx['fps'] ?? [], true)) return self::res('verified', 'Seal Chat uses the same key as this Seal ID.');
        if (empty($ctx['url'])) return self::res('pending', 'Waiting for Seal Chat to sign this proof.');
        [$ok, $why] = self::checkAttestation($handle, Chain::proofText($ctx['url'], $token), $ctx['attestation'] ?? null);
        return self::res($ok ? 'verified' : (empty($ctx['attestation']) ? 'pending' : 'failed'), $why);
    }
}
