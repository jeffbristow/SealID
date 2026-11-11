<?php
/**
 * Seal ID CLI tests.  php tests/run.php
 * Fixtures: tests/fixtures/*.json (OpenPGP.js + gpg keys and signatures).
 */
declare(strict_types=1);
error_reporting(E_ALL);
require __DIR__ . '/../src/lib/openpgp.php';

$fails = 0;
$passes = 0;
function t(string $name, bool $ok, string $extra = ''): void
{
    global $fails, $passes;
    if ($ok) { $passes++; return; }
    $fails++;
    echo "FAIL  $name" . ($extra !== '' ? "  — $extra" : '') . "\n";
}

$all = [];
foreach (glob(__DIR__ . '/fixtures/*.json') as $f) {
    $j = json_decode(file_get_contents($f), true);
    foreach ($j['keys'] as $k) { $k['payload'] = $j['payload']; $all[] = $k; }
}

foreach ($all as $i => $k) {
    $n = $k['name'];
    try {
        $key = Pgp::readKey($k['publicKey']);
    } catch (Throwable $e) {
        t("$n readKey", false, $e->getMessage());
        continue;
    }
    t("$n fingerprint", $key['fp'] === $k['fp'], $key['fp'] . ' vs ' . $k['fp']);
    $r = Pgp::verifyAny($k['payload'], $k['detached'], $key);
    t("$n detached", $r['ok'], (string)$r['error']);
    $r = Pgp::verifyAny($k['payload'], $k['clear'], $key);
    t("$n cleartext", $r['ok'], (string)$r['error']);
    $r = Pgp::verifyAny($k['payload'], $k['wrong'], $key);
    t("$n wrong text rejected", !$r['ok']);
    $r = Pgp::verifyAny($k['payload'] . 'x', $k['detached'], $key);
    t("$n tampered payload rejected", !$r['ok']);
    $other = $all[($i + 1) % count($all)];
    $r = Pgp::verifyAny($k['payload'], $other['detached'], $key);
    t("$n other key's signature rejected", !$r['ok']);
    if ($n === 'gpg-subkey') t("$n has signing subkey", count($key['signers']) === 2, (string)count($key['signers']));
    echo sprintf("  ok   %-12s %s  %s\n", $n, Pgp::formatFp($key['fp']), $key['algo']);
}

// Private keys are refused
try { Pgp::readKey("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxVgEZ\n=AAAA\n-----END PGP PRIVATE KEY BLOCK-----"); t('private key refused', false); }
catch (PgpError $e) { t('private key refused', str_contains($e->getMessage(), 'PRIVATE')); }

foreach (glob(__DIR__ . '/test_*.php') as $f) require $f;

echo "\n$passes passed, $fails failed\n";
exit($fails ? 1 : 0);
