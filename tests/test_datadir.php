<?php
/**
 * 1.5.2: two Seal IDs on one account never share a data folder (included by tests/run.php).
 * Makes two throwaway installs, A and B, side by side and asks each (in its own
 * PHP process, since data_dir() is per request) which data folder it uses.
 */
declare(strict_types=1);

$P = str_replace('\\', '/', sys_get_temp_dir()) . '/sealid-dd-' . bin2hex(random_bytes(4));
$src = str_replace('\\', '/', dirname(__DIR__) . '/src');
$copy = function (string $from, string $to) use (&$copy): void {
    @mkdir($to, 0700, true);
    foreach (scandir($from) as $f) {
        if ($f === '.' || $f === '..' || $f === 'config.php') continue;
        is_dir("$from/$f") ? $copy("$from/$f", "$to/$f") : copy("$from/$f", "$to/$f");
    }
};
$copy("$src/lib", "$P/A/lib");
$copy("$src/lib", "$P/B/lib");
$rm = function (string $d) use (&$rm): void {
    foreach (is_dir($d) ? scandir($d) : [] as $f) {
        if ($f === '.' || $f === '..') continue;
        is_dir("$d/$f") && !is_link("$d/$f") ? $rm("$d/$f") : @unlink("$d/$f");
    }
    @rmdir($d);
};

/** Which data folder does install $who use? [exit code, folder or error] */
$ask = function (string $who, string $host = '', ?string $dataDir = null) use ($P): array {
    @unlink("$P/$who/config.php");
    if ($dataDir !== null) file_put_contents("$P/$who/config.php", '<?php return ' . var_export(['data_dir' => $dataDir], true) . ';');
    $run = "$P/run-$who.php";
    file_put_contents($run, '<?php ' . ($host !== '' ? '$_SERVER["HTTP_HOST"] = ' . var_export($host, true) . ';' : '')
        . 'require ' . var_export("$P/$who/lib/bootstrap.php", true) . '; echo str_replace("\\\\", "/", data_dir());');
    $out = [];
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($run) . ' 2>&1', $out, $code);
    return [$code, trim(implode("\n", $out))];
};
$owner = fn(string $d) => json_decode((string)@file_get_contents("$d/install.json"), true)['root'] ?? null;
$real = fn(string $d) => str_replace('\\', '/', realpath($d) ?: $d);

// A goes first and gets the default folder
[$c, $d] = $ask('A');
t('datadir: first install uses .sealid-data', $c === 0 && $d === "$P/.sealid-data", "$c $d");
t('datadir: and marks it as its own', $owner("$P/.sealid-data") === $real("$P/A"), (string)$owner("$P/.sealid-data"));
[$c, $d] = $ask('A');
t('datadir: same install again → same folder', $c === 0 && $d === "$P/.sealid-data");

// B next to it must not touch A's data
[$c, $d] = $ask('B');
t('datadir: second install gets its own folder', $c === 0 && $d === "$P/.sealid-data-B", "$c $d");
t('datadir: A still owns .sealid-data', $owner("$P/.sealid-data") === $real("$P/A"));
t('datadir: B owns .sealid-data-B', $owner("$P/.sealid-data-B") === $real("$P/B"));

// B pointed at A's folder on purpose → refuses to start
[$c, $d] = $ask('B', '', "$P/.sealid-data");
t('datadir: data_dir owned by another install → refuses', $c !== 0 && str_contains($d, 'belongs to another Seal ID'), "$c $d");
t('datadir: refusal leaves A\'s marker alone', $owner("$P/.sealid-data") === $real("$P/A"));

// B with its own data_dir → fine
[$c, $d] = $ask('B', '', "$P/data-for-b");
t('datadir: own data_dir works', $c === 0 && $d === "$P/data-for-b", "$c $d");

// Data from before 1.5.2 (no install.json): the identity's address decides
@unlink("$P/.sealid-data/install.json");
file_put_contents("$P/.sealid-data/chain.json", json_encode(['url' => 'https://id.a.test', 'links' => []]));
[$c, $d] = $ask('B', 'id.b.test');
t('datadir: old data of another site → not taken', $c === 0 && $d === "$P/.sealid-data-B", "$c $d");
t('datadir: and still unmarked', !is_file("$P/.sealid-data/install.json"));
[$c, $d] = $ask('A', 'id.a.test:443');
t('datadir: old data of this site → taken and marked', $c === 0 && $d === "$P/.sealid-data" && $owner("$P/.sealid-data") === $real("$P/A"), "$c $d");
@unlink("$P/.sealid-data/install.json");
[$c, $d] = $ask('A');
t('datadir: old data from the command line → kept', $c === 0 && $d === "$P/.sealid-data" && $owner("$P/.sealid-data") === $real("$P/A"), "$c $d");

// A moved to a new folder (old one gone) → its data follows it
file_put_contents("$P/.sealid-data/install.json", json_encode(['root' => "$P/old-place"]));
[$c, $d] = $ask('A', 'id.a.test');
t('datadir: moved install keeps its data', $c === 0 && $d === "$P/.sealid-data" && $owner("$P/.sealid-data") === $real("$P/A"), "$c $d");

$rm($P);
