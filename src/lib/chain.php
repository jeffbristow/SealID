<?php
/**
 * Seal ID — the signature chain (docs/PROTOCOL.md section 2) and the bundle
 * (section 3).
 *
 * verifyLinks() checks ANY chain — ours or another installation's — and
 * returns the identity state it describes. Our own chain lives in
 * <data>/chain.json as {"links": [...], "keys": {fp: armored}}.
 */
declare(strict_types=1);

final class ChainError extends RuntimeException
{
    public function __construct(string $message, public int $seq = 0)
    {
        parent::__construct($seq ? "Link $seq: $message" : $message);
    }
}

final class Chain
{
    public const TYPES = ['eldest', 'profile', 'proof', 'revoke', 'vouch', 'mirrors', 'rotate'];
    private const HEX = '/^[0-9A-F]{40}$|^[0-9A-F]{64}$/';

    private static ?array $state = null;

    public static function hash(string $payload): string
    {
        return hash('sha256', $payload);
    }

    /** The proof token for a proof link's payload: sid1:<22 chars>. */
    public static function token(string $payload): string
    {
        return 'sid1:' . substr(rtrim(strtr(base64_encode(hash('sha256', $payload, true)), '+/', '-_'), '='), 0, 22);
    }

    public static function proofText(string $url, string $token): string
    {
        return "Verifying my Seal ID $url $token";
    }

    /** Normalise an identity address: https, lower-case host, no trailing slash. */
    public static function normUrl(string $u): ?string
    {
        $u = trim($u);
        if ($u === '') return null;
        if (!preg_match('#^https?://#i', $u)) $u = 'https://' . $u;
        $p = parse_url($u);
        if (!$p || empty($p['host']) || isset($p['query']) || isset($p['fragment']) || isset($p['user']) || isset($p['port'])) return null;
        $host = strtolower($p['host']);
        if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $host)) return null;
        $path = rtrim($p['path'] ?? '', '/');
        $path = preg_replace('#/(index|admin|api)\.php$#', '', $path);
        if ($path !== '' && !preg_match('#^(/[A-Za-z0-9._~-]+)+$#', $path)) return null;
        return 'https://' . $host . $path;
    }

    /* ------------------------------------------------------------------
     * Verification (any chain)
     * ------------------------------------------------------------------ */

    /**
     * @param list<array{payload:string,sig:string,sig_new?:string}> $links
     * @param array<string,string> $keys fingerprint => armored public key
     * @throws ChainError
     */
    public static function verifyLinks(array $links, array $keys, string $url): array
    {
        if (!$links) throw new ChainError('The chain is empty.');
        if (count($links) > 5000) throw new ChainError('The chain is too long.');
        $st = [
            'url' => $url, 'fp' => null, 'key' => null, 'seq' => 0, 'hash' => null,
            'name' => '', 'bio' => '', 'avatar' => null, 'created' => 0, 'updated' => 0, 'reset_from' => null,
            'proofs' => [], 'vouches' => [], 'mirrors' => [], 'revoked' => [], 'fps' => [],
            'hashes' => [], 'payloads' => [], 'types' => [], 'keys' => [],
        ];
        $parsed = null;              // parsed current key
        $prevHash = null;
        $prevTs = 0;
        foreach (array_values($links) as $i => $link) {
            $seq = $i + 1;
            $payload = $link['payload'] ?? null;
            $sig = $link['sig'] ?? null;
            if (!is_string($payload) || !is_string($sig)) throw new ChainError('Missing payload or signature.', $seq);
            if (strlen($payload) > 20000 || strpbrk($payload, "\r\n") !== false || rtrim($payload) !== $payload) {
                throw new ChainError('Malformed payload.', $seq);
            }
            $p = json_decode($payload, true);
            if (!is_array($p)) throw new ChainError('The payload is not JSON.', $seq);
            if (($p['v'] ?? null) !== 1) throw new ChainError('Unknown statement version.', $seq);
            if (($p['seq'] ?? null) !== $seq) throw new ChainError('Out of order.', $seq);
            if (!array_key_exists('prev', $p) || $p['prev'] !== $prevHash) throw new ChainError('It does not follow the previous link (hash mismatch).', $seq);
            if (($p['url'] ?? null) !== $url) throw new ChainError('It belongs to a different identity (' . (is_string($p['url'] ?? null) ? $p['url'] : '?') . ').', $seq);
            $ts = $p['ts'] ?? null;
            if (!is_int($ts) || $ts < $prevTs || $ts > time() + 3600) throw new ChainError('Bad time stamp.', $seq);
            $type = $p['type'] ?? null;
            if (!in_array($type, self::TYPES, true)) throw new ChainError('Unknown statement type.', $seq);
            $body = $p['body'] ?? null;
            if (!is_array($body)) throw new ChainError('Missing body.', $seq);
            $fp = $p['fp'] ?? null;
            if (!is_string($fp) || !preg_match(self::HEX, $fp)) throw new ChainError('Bad fingerprint.', $seq);

            if ($seq === 1) {
                if ($type !== 'eldest') throw new ChainError('The first link must be "eldest".', 1);
                $armored = $keys[$fp] ?? null;
                if (!is_string($armored)) throw new ChainError('The public key for ' . $fp . ' is missing.', 1);
                try { $parsed = Pgp::readKey($armored); } catch (PgpError $e) { throw new ChainError($e->getMessage(), 1); }
                if ($parsed['fp'] !== $fp) throw new ChainError('The included key does not have fingerprint ' . $fp . '.', 1);
                $st['fp'] = $fp;
                $st['key'] = $armored;
                $st['fps'][] = $fp;
                $st['keys'][$fp] = $armored;
                $st['created'] = $ts;
            } elseif ($type === 'eldest') {
                throw new ChainError('"eldest" may only be the first link.', $seq);
            }
            if ($fp !== $st['fp']) throw new ChainError('Signed with the wrong key.', $seq);
            $v = Pgp::verifyAny($payload, $sig, $parsed);
            // After a rotation the key from the link body may be older than the
            // stored copy (e.g. a signing subkey added later): try that copy too.
            if (!$v['ok'] && isset($keys[$fp]) && $keys[$fp] !== $st['key']) {
                try {
                    $alt = Pgp::readKey($keys[$fp]);
                    if ($alt['fp'] === $fp) { $v = Pgp::verifyAny($payload, $sig, $alt); if ($v['ok']) { $parsed = $alt; $st['key'] = $keys[$fp]; $st['keys'][$fp] = $keys[$fp]; } }
                } catch (PgpError $e) { /* keep the first error */ }
            }
            if (!$v['ok']) throw new ChainError('Bad signature: ' . $v['error'], $seq);

            switch ($type) {
                case 'eldest':
                case 'profile':
                    $st['name'] = self::str($body['name'] ?? '', 80, $seq, 'name');
                    $st['bio'] = self::str($body['bio'] ?? '', 500, $seq, 'bio');
                    // 1.1.0: optional profile picture, pinned by its SHA-256.
                    $av = $body['avatar'] ?? null;
                    if ($av !== null && (!is_string($av) || !preg_match('/^[0-9a-f]{64}$/', $av))) throw new ChainError('Bad avatar hash.', $seq);
                    $st['avatar'] = $av;
                    if ($type === 'eldest' && isset($body['reset_from'])) {
                        if (!is_string($body['reset_from']) || !preg_match(self::HEX, $body['reset_from'])) throw new ChainError('Bad reset_from.', $seq);
                        $st['reset_from'] = $body['reset_from'];
                    }
                    break;
                case 'proof':
                    $svc = $body['service'] ?? null;
                    $handle = $body['handle'] ?? null;
                    if (!is_string($svc) || !preg_match('/^[a-z0-9_-]{1,24}$/', $svc) || !is_string($handle) || $handle === '' || strlen($handle) > 200) {
                        throw new ChainError('Bad proof.', $seq);
                    }
                    $st['proofs'][$seq] = ['seq' => $seq, 'service' => $svc, 'handle' => $handle, 'ts' => $ts, 'token' => self::token($payload)];
                    break;
                case 'revoke':
                    $seqs = $body['seqs'] ?? null;
                    if (!is_array($seqs) || !$seqs || count($seqs) > 100) throw new ChainError('Bad revoke.', $seq);
                    foreach ($seqs as $r) {
                        if (!is_int($r) || $r < 1 || $r >= $seq) throw new ChainError('Revoke points at an unknown link.', $seq);
                        if (!in_array($st['types'][$r] ?? '', ['proof', 'vouch', 'mirrors'], true)) throw new ChainError('Only proofs, vouches and mirror lists can be revoked.', $seq);
                        $st['revoked'][$r] = $seq;
                        unset($st['proofs'][$r], $st['vouches'][$r]);
                        if (($st['mirrors_seq'] ?? 0) === $r) { $st['mirrors'] = []; $st['mirrors_seq'] = 0; }
                    }
                    break;
                case 'vouch':
                    $t = $body['target'] ?? null;
                    if (!is_string($t) || self::normUrl($t) !== $t || $t === $url) throw new ChainError('Bad vouch target.', $seq);
                    if (!is_string($body['target_fp'] ?? null) || !preg_match(self::HEX, $body['target_fp'])) throw new ChainError('Bad vouch fingerprint.', $seq);
                    if (!is_int($body['target_seq'] ?? null) || !is_string($body['target_hash'] ?? null) || !preg_match('/^[0-9a-f]{64}$/', $body['target_hash'])) throw new ChainError('Bad vouch head.', $seq);
                    $pr = [];
                    foreach (($body['proofs'] ?? []) as $x) {
                        if (!is_array($x) || !is_int($x['seq'] ?? null) || !is_string($x['service'] ?? null) || !is_string($x['handle'] ?? null) || !in_array($x['how'] ?? '', ['auto', 'witnessed'], true)) {
                            throw new ChainError('Bad vouched proof.', $seq);
                        }
                        $pr[] = ['seq' => $x['seq'], 'service' => $x['service'], 'handle' => $x['handle'], 'how' => $x['how']];
                    }
                    $st['vouches'][$seq] = ['seq' => $seq, 'ts' => $ts, 'target' => $t, 'target_fp' => $body['target_fp'], 'target_seq' => $body['target_seq'], 'target_hash' => $body['target_hash'], 'proofs' => $pr];
                    break;
                case 'mirrors':
                    $urls = $body['urls'] ?? null;
                    if (!is_array($urls) || count($urls) > 10) throw new ChainError('Bad mirror list.', $seq);
                    foreach ($urls as $m) if (!is_string($m) || !preg_match('#^https://[^\s]{4,300}$#', $m)) throw new ChainError('Bad mirror address.', $seq);
                    $st['mirrors'] = array_values($urls);
                    $st['mirrors_seq'] = $seq;
                    break;
                case 'rotate':
                    $nfp = $body['new_fp'] ?? null;
                    $nkey = $body['new_key'] ?? null;
                    if (!is_string($nfp) || !preg_match(self::HEX, $nfp) || !is_string($nkey)) throw new ChainError('Bad key rotation.', $seq);
                    try { $nk = Pgp::readKey($nkey); } catch (PgpError $e) { throw new ChainError('New key: ' . $e->getMessage(), $seq); }
                    if ($nk['fp'] !== $nfp) throw new ChainError('The new key does not match new_fp.', $seq);
                    $v2 = Pgp::verifyAny($payload, (string)($link['sig_new'] ?? ''), $nk);
                    if (!$v2['ok']) throw new ChainError('The new key did not sign the rotation: ' . $v2['error'], $seq);
                    $parsed = $nk;
                    $st['fp'] = $nfp;
                    $st['key'] = $keys[$nfp] ?? $nkey;
                    $st['fps'][] = $nfp;
                    $st['keys'][$nfp] = $st['key'];
                    break;
            }
            $prevHash = self::hash($payload);
            $prevTs = $ts;
            $st['seq'] = $seq;
            $st['hash'] = $prevHash;
            $st['hashes'][$seq] = $prevHash;
            $st['payloads'][$seq] = $payload;
            $st['types'][$seq] = $type;
            $st['updated'] = $ts;
        }
        $st['parsed_key'] = $parsed;
        return $st;
    }

    private static function str(mixed $v, int $max, int $seq, string $what): string
    {
        if (!is_string($v) || mb_strlen($v) > $max || !mb_check_encoding($v, 'UTF-8')) throw new ChainError("Bad $what.", $seq);
        return $v;
    }

    /* ------------------------------------------------------------------
     * Our own chain
     * ------------------------------------------------------------------ */

    public static function own(): array
    {
        return jread('chain.json', ['url' => null, 'links' => [], 'keys' => []]);
    }

    /** Verified state of our own chain ([] when not installed or broken). */
    public static function state(bool $fresh = false): array
    {
        if (self::$state !== null && !$fresh) return self::$state;
        $own = self::own();
        if (!$own['links']) return self::$state = [];
        try {
            self::$state = self::verifyLinks($own['links'], $own['keys'], $own['url']);
        } catch (ChainError $e) {
            self::$state = ['broken' => $e->getMessage(), 'url' => $own['url'], 'fp' => null];
        }
        return self::$state;
    }

    public static function url(): ?string
    {
        return self::own()['url'] ?? null;
    }

    /** Build the exact payload for the next link. */
    public static function nextPayload(string $type, array $body, ?array $st = null, ?string $url = null, ?string $fp = null): string
    {
        $st ??= self::state();
        $p = [
            'v' => 1,
            'seq' => ($st['seq'] ?? 0) + 1,
            'prev' => $st['hash'] ?? null,
            'ts' => max(time(), (int)($st['updated'] ?? 0)),
            'url' => $url ?? $st['url'],
            'fp' => $fp ?? $st['fp'],
            'type' => $type,
            'body' => $body ?: new stdClass(),
        ];
        return json_encode($p, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Append a signed link to our own chain. The whole chain plus the new link
     * is re-verified before anything is saved.
     * @throws ChainError
     */
    public static function append(string $payload, string $sig, ?string $sigNew = null, ?array $extraKeys = null): array
    {
        return with_lock(function () use ($payload, $sig, $sigNew, $extraKeys) {
            $own = self::own();
            $link = ['payload' => $payload, 'sig' => trim($sig)];
            if ($sigNew !== null) $link['sig_new'] = trim($sigNew);
            $links = $own['links'];
            $links[] = $link;
            $keys = $own['keys'] + ($extraKeys ?? []);
            $st = self::verifyLinks($links, $keys, $own['url']);
            $own['links'] = $links;
            $own['keys'] = $st['keys'];
            jwrite('chain.json', $own);
            self::$state = $st;
            self::writeBundle();
            return $st;
        });
    }

    /** Start a new chain (setup or reset). */
    public static function create(string $url, string $armoredKey, string $payload, string $sig): array
    {
        return with_lock(function () use ($url, $armoredKey, $payload, $sig) {
            $k = Pgp::readKey($armoredKey);
            $links = [['payload' => $payload, 'sig' => trim($sig)]];
            $st = self::verifyLinks($links, [$k['fp'] => $armoredKey], $url);
            if (is_file(data_dir() . '/chain.json')) {
                @rename(data_dir() . '/chain.json', data_dir() . '/chain-replaced-' . date('Ymd-His') . '.json');
            }
            jwrite('chain.json', ['url' => $url, 'links' => $links, 'keys' => $st['keys']]);
            self::$state = $st;
            self::writeBundle();
            return $st;
        });
    }

    /** Replace the stored copy of the current key with an updated copy (same fingerprint). */
    public static function updateKey(string $armored): array
    {
        return with_lock(function () use ($armored) {
            $k = Pgp::readKey($armored);
            $own = self::own();
            $st = self::state(true);
            if ($k['fp'] !== ($st['fp'] ?? '')) throw new ChainError('That key has a different fingerprint. Use key rotation to change keys.');
            $own['keys'][$k['fp']] = $armored;
            $st = self::verifyLinks($own['links'], $own['keys'], $own['url']);
            jwrite('chain.json', $own);
            self::$state = $st;
            self::writeBundle();
            return $st;
        });
    }

    /* ------------------------------------------------------------------
     * Bundle
     * ------------------------------------------------------------------ */

    public static function bundle(): array
    {
        $own = self::own();
        $st = self::state();
        $checks = [];
        foreach (jread('checks.json', []) as $seq => $c) {
            if (isset($st['proofs'][(int)$seq])) $checks[(string)$seq] = ['status' => $c['status'], 'at' => $c['at']];
        }
        $locators = [];
        foreach (jread('locators.json', []) as $seq => $u) {
            if (isset($st['proofs'][(int)$seq])) $locators[(string)$seq] = $u;
        }
        $vb = [];
        foreach (jread('vouches.json', []) as $v) $vb[] = ['url' => $v['url'], 'seq' => $v['seq']];
        return [
            'seal_id' => 1,
            'url' => $own['url'],
            'fp' => $st['fp'] ?? null,
            'keys' => (object)$own['keys'],
            'chain' => $own['links'],
            'locators' => (object)$locators,
            'vouched_by' => $vb,
            'checks' => (object)$checks,
            // 1.1.0: where to fetch the profile picture; its hash is signed in the chain.
            'avatar' => ($av = avatar_current()) ? ['url' => 'api.php?a=avatar&h=' . substr($av['sha'], 0, 16), 'sha256' => $av['sha'], 'type' => $av['mime']] : null,
            'software' => 'SealID/' . SEALID_VERSION,
            'updated' => time(),
        ];
    }

    /** Write the static .well-known/seal-id.json. Returns an error message or null. */
    public static function writeBundle(): ?string
    {
        try {
            $dir = SEALID_ROOT . '/.well-known';
            if (!is_dir($dir) && !@mkdir($dir, 0755, true)) return 'Cannot create the .well-known folder.';
            atomic_write($dir . '/seal-id.json', json_encode(self::bundle(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            return null;
        } catch (Throwable $e) {
            return $e->getMessage();
        }
    }
}
