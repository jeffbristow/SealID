<?php
/**
 * Seal ID — minimal OpenPGP verifier (pure PHP: sodium + openssl + hash).
 *
 * Only what Seal ID needs: read public keys, compute fingerprints, verify
 * detached and cleartext signatures. It never handles private keys.
 *
 * Keys:       v4 and v6 public keys and subkeys.
 * Algorithms: RSA (1/3, >= 2048 bits), EdDSALegacy over Ed25519 (22),
 *             Ed25519 (27).
 * Hashes:     SHA-224/256/384/512, SHA3-256/512 (SHA-1 only for old key
 *             binding signatures, never for statements).
 * Subkeys:    a subkey may sign if its binding signature (0x18) by the primary
 *             verifies, its key flags allow signing and its embedded primary
 *             key binding (back-)signature (0x19) verifies. Revoked subkeys
 *             (0x28) and a revoked primary (0x20) are refused.
 */
declare(strict_types=1);

final class PgpError extends RuntimeException {}

final class Pgp
{
    private const ED25519_OID = "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01";
    private const HASHES = [2 => 'sha1', 8 => 'sha256', 9 => 'sha384', 10 => 'sha512', 11 => 'sha224', 12 => 'sha3-256', 14 => 'sha3-512'];
    private const OPENSSL_HASHES = ['sha1' => OPENSSL_ALGO_SHA1, 'sha224' => OPENSSL_ALGO_SHA224, 'sha256' => OPENSSL_ALGO_SHA256, 'sha384' => OPENSSL_ALGO_SHA384, 'sha512' => OPENSSL_ALGO_SHA512];

    /* ------------------------------------------------------------------
     * Armor
     * ------------------------------------------------------------------ */

    /** Decode the first ASCII-armored block of $text. $kind receives e.g. "PUBLIC KEY BLOCK". */
    public static function dearmor(string $text, ?string &$kind = null): string
    {
        $text = str_replace("\r\n", "\n", $text);
        if (!preg_match('/-----BEGIN PGP ([A-Z ,0-9\/]+)-----\n(.*?)-----END PGP \1-----/s', $text, $m)) {
            throw new PgpError('No ASCII-armored OpenPGP block found.');
        }
        $kind = $m[1];
        $lines = explode("\n", $m[2]);
        // Skip armor headers ("Version: …", "Comment: …") and the blank line after them.
        $i = 0;
        while ($i < count($lines) && preg_match('/^[A-Za-z][A-Za-z0-9-]*: /', $lines[$i])) $i++;
        while ($i < count($lines) && trim($lines[$i]) === '') $i++;
        $b64 = '';
        $crc = null;
        for (; $i < count($lines); $i++) {
            $l = trim($lines[$i]);
            if ($l === '') continue;
            if ($l[0] === '=' && strlen($l) === 5) { $crc = base64_decode(substr($l, 1), true); break; }
            $b64 .= $l;
        }
        $bin = base64_decode($b64, true);
        if ($bin === false || $bin === '') throw new PgpError('The armored block is not valid base64.');
        if ($crc !== null && $crc !== false && strlen($crc) === 3 && self::crc24($bin) !== $crc) {
            throw new PgpError('The armored block is damaged (checksum mismatch).');
        }
        return $bin;
    }

    private static function crc24(string $data): string
    {
        $crc = 0xB704CE;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $crc ^= ord($data[$i]) << 16;
            for ($b = 0; $b < 8; $b++) {
                $crc <<= 1;
                if ($crc & 0x1000000) $crc ^= 0x1864CFB;
            }
        }
        $crc &= 0xFFFFFF;
        return chr(($crc >> 16) & 0xFF) . chr(($crc >> 8) & 0xFF) . chr($crc & 0xFF);
    }

    /**
     * Split a cleartext-signed message. Returns [signedText, armoredSignature]
     * or null when $text is not a cleartext-signed message. The signed text is
     * returned the way it was hashed (dash-escaping removed, trailing
     * whitespace stripped, CRLF line endings).
     */
    public static function splitCleartext(string $text): ?array
    {
        $text = str_replace("\r\n", "\n", $text);
        $start = strpos($text, "-----BEGIN PGP SIGNED MESSAGE-----\n");
        if ($start === false) return null;
        $rest = substr($text, $start + 35);
        $sigPos = strpos($rest, "\n-----BEGIN PGP SIGNATURE-----");
        if ($sigPos === false) return null;
        $head = substr($rest, 0, $sigPos);
        $sig = substr($rest, $sigPos + 1);
        if (strncmp($head, "\n", 1) === 0) {
            $body = substr($head, 1);                 // no armor headers
        } else {
            $blank = strpos($head, "\n\n");
            if ($blank === false) return null;
            $body = substr($head, $blank + 2);
        }
        $out = [];
        foreach (explode("\n", $body) as $line) {
            if (strncmp($line, '- ', 2) === 0) $line = substr($line, 2);
            $out[] = rtrim($line, " \t");
        }
        return [implode("\r\n", $out), $sig];
    }

    /* ------------------------------------------------------------------
     * Packets
     * ------------------------------------------------------------------ */

    /** @return list<array{0:int,1:string}> [tag, body] pairs */
    public static function packets(string $bin): array
    {
        $out = [];
        $pos = 0;
        $n = strlen($bin);
        while ($pos < $n) {
            $b = ord($bin[$pos++]);
            if (!($b & 0x80)) throw new PgpError('Malformed OpenPGP packet header.');
            if ($b & 0x40) {
                $tag = $b & 0x3F;
                $body = '';
                while (true) {
                    if ($pos >= $n) throw new PgpError('Truncated OpenPGP packet.');
                    $o1 = ord($bin[$pos++]);
                    if ($o1 < 192) { $len = $o1; $partial = false; }
                    elseif ($o1 < 224) { $len = (($o1 - 192) << 8) + ord($bin[$pos++] ?? "\0") + 192; $partial = false; }
                    elseif ($o1 === 255) { $len = unpack('N', substr($bin, $pos, 4))[1]; $pos += 4; $partial = false; }
                    else { $len = 1 << ($o1 & 0x1F); $partial = true; }
                    if ($pos + $len > $n) throw new PgpError('Truncated OpenPGP packet.');
                    $body .= substr($bin, $pos, $len);
                    $pos += $len;
                    if (!$partial) break;
                }
            } else {
                $tag = ($b >> 2) & 0x0F;
                $lt = $b & 3;
                if ($lt === 0) { $len = ord($bin[$pos] ?? "\0"); $pos += 1; }
                elseif ($lt === 1) { $len = unpack('n', substr($bin, $pos, 2))[1]; $pos += 2; }
                elseif ($lt === 2) { $len = unpack('N', substr($bin, $pos, 4))[1]; $pos += 4; }
                else { $len = $n - $pos; }
                if ($pos + $len > $n) throw new PgpError('Truncated OpenPGP packet.');
                $body = substr($bin, $pos, $len);
                $pos += $len;
            }
            $out[] = [$tag, $body];
        }
        return $out;
    }

    private static function mpi(string $s, int &$p): string
    {
        if ($p + 2 > strlen($s)) throw new PgpError('Truncated MPI.');
        $bits = unpack('n', substr($s, $p, 2))[1];
        $len = intdiv($bits + 7, 8);
        $p += 2;
        if ($p + $len > strlen($s)) throw new PgpError('Truncated MPI.');
        $v = substr($s, $p, $len);
        $p += $len;
        return $v;
    }

    /* ------------------------------------------------------------------
     * Keys
     * ------------------------------------------------------------------ */

    /** Parse one public key / subkey packet body. */
    public static function parseKeyPacket(string $body): array
    {
        $ver = ord($body[0] ?? "\0");
        if ($ver !== 4 && $ver !== 6) throw new PgpError("Unsupported key version $ver.");
        $created = unpack('N', substr($body, 1, 4))[1];
        $algo = ord($body[5]);
        $p = 6;
        if ($ver === 6) $p += 4;            // octet count of the key material
        $k = ['version' => $ver, 'created' => $created, 'algo' => $algo, 'body' => $body, 'material' => null];
        try {
            if ($algo === 1 || $algo === 3) {
                $nn = self::mpi($body, $p);
                $e = self::mpi($body, $p);
                $k['material'] = ['n' => ltrim($nn, "\0"), 'e' => ltrim($e, "\0")];
            } elseif ($algo === 22) {
                $ol = ord($body[$p]);
                $oid = substr($body, $p + 1, $ol);
                $p += 1 + $ol;
                $pt = self::mpi($body, $p);
                if ($oid === self::ED25519_OID && strlen($pt) === 33 && $pt[0] === "\x40") {
                    $k['material'] = ['pk' => substr($pt, 1)];
                }
            } elseif ($algo === 27) {
                $pk = substr($body, $p, 32);
                if (strlen($pk) === 32) $k['material'] = ['pk' => $pk];
            }
        } catch (PgpError $e) {
            $k['material'] = null;
        }
        if ($ver === 4) {
            $fp = sha1("\x99" . pack('n', strlen($body)) . $body, true);
            $k['keyid'] = substr($fp, -8);
        } else {
            $fp = hash('sha256', "\x9B" . pack('N', strlen($body)) . $body, true);
            $k['keyid'] = substr($fp, 0, 8);
        }
        $k['fp'] = strtoupper(bin2hex($fp));
        return $k;
    }

    private static function keyHashPrefix(array $k): string
    {
        return $k['version'] === 6
            ? "\x9B" . pack('N', strlen($k['body'])) . $k['body']
            : "\x99" . pack('n', strlen($k['body'])) . $k['body'];
    }

    /**
     * Read an armored (or binary) transferable public key.
     * Returns ['fp', 'primary', 'signers' => [key…], 'uids' => [..], 'revoked' => bool, 'armored'].
     * 'signers' are the keys allowed to sign statements: the primary plus
     * every valid signing subkey.
     */
    public static function readKey(string $armoredOrBinary): array
    {
        if (str_contains($armoredOrBinary, '-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
            throw new PgpError('That is a PRIVATE key. Seal ID only needs your PUBLIC key — never upload your private key.');
        }
        $bin = str_contains($armoredOrBinary, '-----BEGIN PGP') ? self::dearmor($armoredOrBinary, $kind) : $armoredOrBinary;
        if (isset($kind) && $kind !== 'PUBLIC KEY BLOCK') {
            throw new PgpError($kind === 'PRIVATE KEY BLOCK'
                ? 'That is a PRIVATE key. Seal ID only needs your PUBLIC key — never upload your private key.'
                : 'Expected a PUBLIC KEY BLOCK, got ' . $kind . '.');
        }
        $primary = null;
        $subkeys = [];
        $uids = [];
        $directSigs = [];
        $cur = null;                       // 'primary' | 'uid' | index of subkey
        foreach (self::packets($bin) as [$tag, $body]) {
            if ($tag === 6) {
                if ($primary !== null) break;          // a second key: stop at the first one
                $primary = self::parseKeyPacket($body);
                $cur = 'primary';
            } elseif ($tag === 5 || $tag === 7) {
                throw new PgpError('That is a PRIVATE key. Seal ID only needs your PUBLIC key — never upload your private key.');
            } elseif ($tag === 13) {
                $uids[] = $body;
                $cur = 'uid';
            } elseif ($tag === 17) {
                $cur = 'uid';
            } elseif ($tag === 14) {
                $sk = self::parseKeyPacket($body);
                $sk['sigs'] = [];
                $subkeys[] = $sk;
                $cur = count($subkeys) - 1;
            } elseif ($tag === 2) {
                try { $sig = self::parseSig($body); } catch (PgpError $e) { continue; }
                if ($cur === 'primary') $directSigs[] = $sig;
                elseif (is_int($cur)) $subkeys[$cur]['sigs'][] = $sig;
            }
        }
        if ($primary === null) throw new PgpError('No public key found.');
        if ($primary['material'] === null) {
            throw new PgpError('This key uses an algorithm Seal ID cannot verify yet (supported: Ed25519 and RSA).');
        }
        $revoked = false;
        foreach ($directSigs as $s) {
            if ($s['type'] === 0x20 && self::verifyHashed($primary, $s, self::keyHashPrefix($primary), true)) $revoked = true;
        }
        $signers = [$primary];
        foreach ($subkeys as $sk) {
            if ($sk['material'] === null) continue;
            $bound = false;
            $canSign = false;
            $rev = false;
            $data = self::keyHashPrefix($primary) . self::keyHashPrefix($sk);
            foreach ($sk['sigs'] as $s) {
                if ($s['type'] === 0x28 && self::verifyHashed($primary, $s, $data, true)) $rev = true;
                if ($s['type'] !== 0x18 || !self::verifyHashed($primary, $s, $data, true)) continue;
                $flags = $s['sub'][27][0] ?? '';
                if ($flags === '' || !(ord($flags[0]) & 0x02)) { $bound = true; continue; }
                // The back-signature is usually in the unhashed area (it protects itself).
                foreach (array_merge($s['sub'][32] ?? [], $s['unsub'][32] ?? []) as $emb) {
                    try { $back = self::parseSig($emb); } catch (PgpError $e) { continue; }
                    if ($back['type'] === 0x19 && self::verifyHashed($sk, $back, $data, true)) { $canSign = true; }
                }
                $bound = true;
            }
            if ($bound && $canSign && !$rev) $signers[] = $sk;
        }
        $names = [];
        foreach ($uids as $u) { if (mb_check_encoding($u, 'UTF-8')) $names[] = $u; }
        return [
            'fp' => $primary['fp'],
            'primary' => $primary,
            'signers' => $signers,
            'uids' => $names,
            'revoked' => $revoked,
            'algo' => self::algoName($primary),
        ];
    }

    public static function algoName(array $k): string
    {
        return match ($k['algo']) {
            1, 3 => 'RSA-' . (strlen($k['material']['n'] ?? '') * 8),
            22 => 'Ed25519 (legacy)',
            27 => 'Ed25519',
            default => 'algorithm ' . $k['algo'],
        };
    }

    /** Pretty fingerprint: groups of 4. */
    public static function formatFp(string $fp): string
    {
        return trim(chunk_split($fp, 4, ' '));
    }

    /* ------------------------------------------------------------------
     * Signatures
     * ------------------------------------------------------------------ */

    public static function parseSig(string $b): array
    {
        $ver = ord($b[0] ?? "\0");
        if ($ver !== 4 && $ver !== 6) throw new PgpError("Unsupported signature version $ver.");
        $s = ['version' => $ver, 'type' => ord($b[1]), 'pubalgo' => ord($b[2]), 'hashalgo' => ord($b[3])];
        if ($ver === 4) {
            $hl = unpack('n', substr($b, 4, 2))[1];
            $p = 6;
        } else {
            $hl = unpack('N', substr($b, 4, 4))[1];
            $p = 8;
        }
        $hashedArea = substr($b, $p, $hl);
        if (strlen($hashedArea) !== $hl) throw new PgpError('Truncated signature.');
        $s['prefix'] = substr($b, 0, $p + $hl);
        $p += $hl;
        if ($ver === 4) { $ul = unpack('n', substr($b, $p, 2))[1]; $p += 2; }
        else { $ul = unpack('N', substr($b, $p, 4))[1]; $p += 4; }
        $unhashed = substr($b, $p, $ul);
        $p += $ul;
        $s['left16'] = substr($b, $p, 2);
        $p += 2;
        $s['salt'] = '';
        if ($ver === 6) {
            $sl = ord($b[$p]);
            $s['salt'] = substr($b, $p + 1, $sl);
            $p += 1 + $sl;
        }
        $s['sub'] = self::subpackets($hashedArea);
        $s['unsub'] = self::subpackets($unhashed);
        // Signature material
        $mat = null;
        try {
            if ($s['pubalgo'] === 1 || $s['pubalgo'] === 3) {
                $mat = ['s' => self::mpi($b, $p)];
            } elseif ($s['pubalgo'] === 22) {
                $r = self::mpi($b, $p);
                $ss = self::mpi($b, $p);
                if (strlen($r) <= 32 && strlen($ss) <= 32) {
                    $mat = ['sig' => str_pad($r, 32, "\0", STR_PAD_LEFT) . str_pad($ss, 32, "\0", STR_PAD_LEFT)];
                }
            } elseif ($s['pubalgo'] === 27) {
                $sig = substr($b, $p, 64);
                if (strlen($sig) === 64) $mat = ['sig' => $sig];
            }
        } catch (PgpError $e) {
            $mat = null;
        }
        $s['material'] = $mat;
        return $s;
    }

    /** @return array<int, list<string>> subpacket type => list of bodies */
    private static function subpackets(string $area): array
    {
        $out = [];
        $p = 0;
        $n = strlen($area);
        while ($p < $n) {
            $o = ord($area[$p++]);
            if ($o < 192) $len = $o;
            elseif ($o < 255) { $len = (($o - 192) << 8) + ord($area[$p++] ?? "\0") + 192; }
            else { $len = unpack('N', substr($area, $p, 4))[1]; $p += 4; }
            if ($len < 1 || $p + $len > $n) break;
            $type = ord($area[$p]) & 0x7F;
            $out[$type][] = substr($area, $p + 1, $len - 1);
            $p += $len;
        }
        return $out;
    }

    /** Signature creation time (Unix) or 0. */
    public static function sigCreated(array $s): int
    {
        $c = $s['sub'][2][0] ?? '';
        return strlen($c) === 4 ? unpack('N', $c)[1] : 0;
    }

    /** Verify $sig made by $key over $data (the bytes before the signature trailer). */
    private static function verifyHashed(array $key, array $sig, string $data, bool $allowSha1 = false): bool
    {
        if ($key['material'] === null || $sig['material'] === null) return false;
        if ($key['algo'] !== $sig['pubalgo'] && !(in_array($key['algo'], [1, 3], true) && $sig['pubalgo'] === 1)) return false;
        $h = self::HASHES[$sig['hashalgo']] ?? null;
        if ($h === null || ($h === 'sha1' && !$allowSha1)) return false;
        if ($sig['version'] !== $key['version']) return false;   // v4 keys make v4 signatures, v6 keys v6
        $trailer = ($sig['version'] === 6 ? "\x06\xFF" : "\x04\xFF") . pack('N', strlen($sig['prefix']));
        $input = $sig['salt'] . $data . $sig['prefix'] . $trailer;
        $digest = hash($h, $input, true);
        if (!hash_equals(substr($digest, 0, 2), $sig['left16'])) return false;
        if ($key['algo'] === 22 || $key['algo'] === 27) {
            if (!function_exists('sodium_crypto_sign_verify_detached')) throw new PgpError('PHP sodium extension missing.');
            try {
                return sodium_crypto_sign_verify_detached($sig['material']['sig'], $digest, $key['material']['pk']);
            } catch (Throwable $e) {
                return false;
            }
        }
        // RSA
        $n = $key['material']['n'];
        if (strlen($n) < 256) return false;          // < 2048 bits
        $oh = self::OPENSSL_HASHES[$h] ?? null;
        if ($oh === null) return false;
        $sigBytes = str_pad(ltrim($sig['material']['s'], "\0"), strlen($n), "\0", STR_PAD_LEFT);
        $pem = self::rsaPem($n, $key['material']['e']);
        $ok = @openssl_verify($input, $sigBytes, $pem, $oh);
        return $ok === 1;
    }

    private static function derLen(int $l): string
    {
        if ($l < 128) return chr($l);
        $s = '';
        while ($l > 0) { $s = chr($l & 0xFF) . $s; $l >>= 8; }
        return chr(0x80 | strlen($s)) . $s;
    }

    private static function derInt(string $v): string
    {
        $v = ltrim($v, "\0");
        if ($v === '' || (ord($v[0]) & 0x80)) $v = "\0" . $v;
        return "\x02" . self::derLen(strlen($v)) . $v;
    }

    private static function rsaPem(string $n, string $e): string
    {
        $rsa = self::derInt($n) . self::derInt($e);
        $rsa = "\x30" . self::derLen(strlen($rsa)) . $rsa;
        $bit = "\x00" . $rsa;
        $alg = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";
        $spki = $alg . "\x03" . self::derLen(strlen($bit)) . $bit;
        $spki = "\x30" . self::derLen(strlen($spki)) . $spki;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Verify a detached (armored or binary) signature over $data with a key from readKey().
     * Returns ['ok' => bool, 'error' => string|null, 'signer' => fingerprint of the
     * (sub)key that signed, 'created' => unix time].
     */
    public static function verifyDetached(string $data, string $signature, array $key): array
    {
        if ($key['revoked']) return ['ok' => false, 'error' => 'This key has been revoked.', 'signer' => null, 'created' => 0];
        try {
            $bin = str_contains($signature, '-----BEGIN PGP') ? self::dearmor($signature, $kind) : $signature;
            if (isset($kind) && $kind !== 'SIGNATURE') {
                return ['ok' => false, 'error' => 'Expected a PGP SIGNATURE block (detached signature), got ' . $kind . '.', 'signer' => null, 'created' => 0];
            }
            $sigs = [];
            foreach (self::packets($bin) as [$tag, $body]) {
                if ($tag === 2) $sigs[] = self::parseSig($body);
            }
        } catch (PgpError $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'signer' => null, 'created' => 0];
        }
        if (!$sigs) return ['ok' => false, 'error' => 'No signature found.', 'signer' => null, 'created' => 0];
        $why = 'The signature does not match this key and text.';
        foreach ($sigs as $s) {
            if ($s['type'] !== 0x00 && $s['type'] !== 0x01) { $why = 'That is not a document signature.'; continue; }
            if (($s['hashalgo'] === 2)) { $why = 'SHA-1 signatures are not accepted. Use SHA-256 or better.'; continue; }
            $d = $s['type'] === 0x01 ? preg_replace("/\r?\n/", "\r\n", $data) : $data;
            $issuerFp = null;
            foreach (array_merge($s['sub'][33] ?? [], $s['unsub'][33] ?? []) as $f) {
                if (strlen($f) > 1) $issuerFp = strtoupper(bin2hex(substr($f, 1)));
            }
            $issuerId = null;
            foreach (array_merge($s['sub'][16] ?? [], $s['unsub'][16] ?? []) as $f) {
                if (strlen($f) === 8) $issuerId = $f;
            }
            foreach ($key['signers'] as $k) {
                if ($issuerFp !== null && $issuerFp !== $k['fp']) continue;
                if ($issuerFp === null && $issuerId !== null && $issuerId !== $k['keyid']) continue;
                if (self::verifyHashed($k, $s, $d)) {
                    return ['ok' => true, 'error' => null, 'signer' => $k['fp'], 'created' => self::sigCreated($s)];
                }
            }
            if ($issuerFp !== null || $issuerId !== null) {
                $match = false;
                foreach ($key['signers'] as $k) {
                    if ($issuerFp === $k['fp'] || ($issuerFp === null && $issuerId === $k['keyid'])) $match = true;
                }
                if (!$match) $why = 'This was signed by a different key (or a subkey that is not allowed to sign).';
            }
        }
        return ['ok' => false, 'error' => $why, 'signer' => null, 'created' => 0];
    }

    /**
     * Accept either a detached signature or a cleartext-signed message whose
     * text is exactly $data. Returns the same shape as verifyDetached().
     */
    public static function verifyAny(string $data, string $pasted, array $key): array
    {
        $ct = self::splitCleartext($pasted);
        if ($ct !== null) {
            [$text, $sig] = $ct;
            $expect = preg_replace("/\r?\n/", "\r\n", rtrim($data, " \t"));
            if ($text !== $expect) {
                return ['ok' => false, 'error' => 'The signed text is not exactly the statement shown. Copy it again without changes.', 'signer' => null, 'created' => 0];
            }
            return self::verifyDetached($data, $sig, $key);
        }
        return self::verifyDetached($data, $pasted, $key);
    }
}
