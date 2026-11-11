<?php
/**
 * Updater test, run on its own:  php tests/update-test.php [dist/SealID-<v>.zip]
 *
 * Makes a throwaway install of src/ that claims to be version 1.0.9, builds a
 * package of the real src/ (signed with the real update key, read from
 * ~/.sealid/update-signing-key.pem or SEALID_SIGNING_KEY), then:
 *   - tampered zip / wrong version / bad signature / unsigned → refused, nothing changed
 *   - real package → installed, config.php + .well-known untouched
 *   - Undo → back to 1.0.9; install again → fine
 */
declare(strict_types=1);
error_reporting(E_ALL);

$src = realpath(__DIR__ . '/../src');
$boot = file_get_contents("$src/lib/bootstrap.php");
preg_match("/const SEALID_VERSION = '([0-9.]+)'/", $boot, $m);
$ver = $m[1];

// --- the signing key (seed = last 32 bytes of the PKCS#8 Ed25519 key) ---
$keyPath = getenv('SEALID_SIGNING_KEY') ?: (getenv('USERPROFILE') ?: getenv('HOME')) . '/.sealid/update-signing-key.pem';
if (!is_file($keyPath)) { echo "SKIP: no signing key at $keyPath\n"; exit(0); }
$der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', file_get_contents($keyPath)));
$kp = sodium_crypto_sign_seed_keypair(substr($der, -32));
$sk = sodium_crypto_sign_secretkey($kp);

// --- throwaway install claiming 1.0.9 ---
$tmp = sys_get_temp_dir() . '/sealid-uptest-' . bin2hex(random_bytes(4));
$site = "$tmp/site";
$copy = function (string $from, string $to) use (&$copy) {
    @mkdir($to, 0777, true);
    foreach (scandir($from) as $f) {
        if ($f === '.' || $f === '..') continue;
        is_dir("$from/$f") ? $copy("$from/$f", "$to/$f") : copy("$from/$f", "$to/$f");
    }
};
$copy($src, $site);
file_put_contents("$site/lib/bootstrap.php", str_replace("const SEALID_VERSION = '$ver'", "const SEALID_VERSION = '1.0.9'", $boot));
file_put_contents("$site/index.php", "<?php // old index\n");
file_put_contents("$site/config.php", "<?php return ['data_dir' => " . var_export("$tmp/data", true) . ", 'setup_code' => 'keep-me-123'];\n");
@mkdir("$site/.well-known");
file_put_contents("$site/.well-known/seal-id.json", '{"keep":true}');
$configBefore = file_get_contents("$site/config.php");

// --- packages ---
$makeZip = function (string $prefix, ?callable $tweak = null) use ($src): string {
    $f = tempnam(sys_get_temp_dir(), 'sidzip');
    $z = new ZipArchive();
    $z->open($f, ZipArchive::OVERWRITE);
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($src) + 1));
        if ($rel === 'config.php' || str_starts_with($rel, '.well-known/')) continue;
        $z->addFromString($prefix . $rel, file_get_contents($file->getPathname()));
    }
    if ($tweak) $tweak($z);
    $z->close();
    $b = file_get_contents($f);
    unlink($f);
    return $b;
};
$signFor = fn(string $v, string $zip) => json_encode(['version' => $v, 'sha256' => hash('sha256', $zip),
    'sig' => base64_encode(sodium_crypto_sign_detached("sealid-update-v1|$v|" . hash('sha256', $zip), $sk))]);

// Optional: test a built release instead (php tests/update-test.php dist/SealID-x.y.z.zip)
$pkg = $argv[1] ?? null;
$good = $pkg ? file_get_contents($pkg) : $makeZip("SealID-$ver/");
$goodSig = $pkg ? file_get_contents($pkg . ".sig") : $signFor($ver, $good);

require "$site/lib/bootstrap.php";

$fails = 0;
$t = function (string $name, bool $ok, string $extra = '') use (&$fails) {
    echo ($ok ? '  ok   ' : 'FAIL  ') . $name . ($ok || $extra === '' ? '' : "  — $extra") . "\n";
    if (!$ok) $fails++;
};

$t('install starts at 1.0.9', up_current() === '1.0.9');
[$ok, $msg] = up_install_package($ver, $good . 'x', $goodSig);
$t('tampered zip refused', !$ok && str_contains($msg, 'does not match'), $msg);
[$ok, $msg] = up_install_package($ver, $good, $signFor('9.9.9', $good));
$t('signature for another version refused', !$ok, $msg);
$bad = json_decode($goodSig, true);
$bad['sig'] = base64_encode(str_repeat("\0", 64));
[$ok, $msg] = up_install_package($ver, $good, json_encode($bad));
$t('bad signature refused', !$ok && str_contains($msg, 'NOT signed'), $msg);
$otherKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
$forged = json_encode(['version' => $ver, 'sha256' => hash('sha256', $good), 'sig' => base64_encode(sodium_crypto_sign_detached("sealid-update-v1|$ver|" . hash('sha256', $good), $otherKey))]);
[$ok, $msg] = up_install_package($ver, $good, $forged);
$t('package signed by another key refused', !$ok && str_contains($msg, 'NOT signed'), $msg);
$evil = $makeZip("SealID-$ver/", fn($z) => $z->addFromString("SealID-$ver/../evil.php", '<?php'));
[$ok, $msg] = up_install_package($ver, $evil, $signFor($ver, $evil));
$t('path escape refused (even when signed)', !$ok && str_contains($msg, 'unsafe'), $msg);
$wrongTop = $makeZip("other/");
[$ok, $msg] = up_install_package($ver, $wrongTop, $signFor($ver, $wrongTop));
$t('wrong top folder refused', !$ok, $msg);
$t('nothing changed so far', up_current() === '1.0.9' && file_get_contents("$site/index.php") === "<?php // old index\n");

[$ok, $msg] = up_install_package($ver, $good, $goodSig);
$t("real package installs ($ver)", $ok && up_current() === $ver, $msg);
$t('files replaced', file_get_contents("$site/index.php") === file_get_contents("$src/index.php"));
$t('config.php untouched', file_get_contents("$site/config.php") === $configBefore);
$t('.well-known untouched', file_get_contents("$site/.well-known/seal-id.json") === '{"keep":true}');
$t('undo offered', (up_state()['undo'] ?? null) === '1.0.9');
[$ok2, $msg2] = up_install_package($ver, $good, $goodSig);
$t('same version again refused', !$ok2);

[$ok, $msg] = up_restore();
$t('undo', $ok && up_current() === '1.0.9' && file_get_contents("$site/index.php") === "<?php // old index\n", $msg);
[$ok, $msg] = up_install_package($ver, $good, $goodSig);
$t('install again after undo', $ok && up_current() === $ver, $msg);

// clean up
$rm = function (string $d) use (&$rm) { foreach (array_diff(scandir($d), ['.', '..']) as $f) is_dir("$d/$f") ? $rm("$d/$f") : unlink("$d/$f"); rmdir($d); };
$rm($tmp);
echo $fails ? "\n$fails FAILED\n" : "\nupdater: all checks passed\n";
exit($fails ? 1 : 0);
