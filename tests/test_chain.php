<?php
/** Chain verification tests (included by tests/run.php). */
declare(strict_types=1);
require_once __DIR__ . '/../src/lib/chain.php';
require_once __DIR__ . '/../src/lib/http.php';

$fx = json_decode((string)file_get_contents(__DIR__ . '/chain-fixture.json'), true);

$st = Chain::verifyLinks($fx['links'], $fx['keys'], $fx['url']);
t('chain verifies', $st['seq'] === 8);
t('chain name from profile', $st['name'] === 'Chain Tester');
t('chain revoked proof gone', !isset($st['proofs'][2]) && isset($st['proofs'][3]));
t('chain rotated key', $st['fp'] === $fx['fp2'] && $st['fps'] === [$fx['fp1'], $fx['fp2']]);
t('chain mirrors', $st['mirrors'] === ['https://mirror.example.test/seal-id.json']);
t('chain vouch', isset($st['vouches'][8]) && $st['vouches'][8]['target'] === 'https://id.other.test');
t('token format', (bool)preg_match('/^sid1:[A-Za-z0-9_-]{22}$/', $st['proofs'][3]['token']));
echo "  ok   chain        8 links, rotation " . substr($fx['fp1'], -8) . " -> " . substr($fx['fp2'], -8) . "\n";

function expect_fail(string $name, array $links, array $keys, string $url, string $contains = ''): void
{
    try {
        Chain::verifyLinks($links, $keys, $url);
        t($name, false, 'accepted');
    } catch (ChainError $e) {
        t($name, $contains === '' || str_contains($e->getMessage(), $contains), $e->getMessage());
    }
}

$L = $fx['links'];
expect_fail('wrong url rejected', $L, $fx['keys'], 'https://id.evil.test', 'different identity');
$x = $L; array_splice($x, 3, 1);
expect_fail('removed link rejected', $x, $fx['keys'], $fx['url'], 'Out of order');
$x = $L; $x[1]['payload'] = str_replace('"handle":"example.test"', '"handle":"evil.test"', $x[1]['payload']);
expect_fail('edited payload rejected', $x, $fx['keys'], $fx['url'], 'Bad signature');
$x = $L; [$x[1], $x[2]] = [$x[2], $x[1]];
expect_fail('reordered links rejected', $x, $fx['keys'], $fx['url']);
$x = $L; unset($x[6]['sig_new']);
expect_fail('rotation without new-key signature rejected', $x, $fx['keys'], $fx['url'], 'new key did not sign');
$x = $L; $x[7]['sig'] = $L[6]['sig'];
expect_fail('signature from another link rejected', $x, $fx['keys'], $fx['url'], 'Bad signature');
expect_fail('missing eldest key rejected', $L, [], $fx['url'], 'missing');
$x = array_slice($L, 0, 5);
t('prefix of a chain still verifies', Chain::verifyLinks($x, $fx['keys'], $fx['url'])['seq'] === 5);

// URL normalisation
t('normUrl bare host', Chain::normUrl('ID.Example.com') === 'https://id.example.com');
t('normUrl trailing slash + index', Chain::normUrl('https://example.com/seal/index.php') === 'https://example.com/seal');
t('normUrl rejects query', Chain::normUrl('https://example.com/?x=1') === null);
t('normUrl rejects port', Chain::normUrl('https://example.com:8443') === null);

// SSRF guard
t('private IP refused', !ip_is_public('10.1.2.3') && !ip_is_public('127.0.0.1') && !ip_is_public('169.254.169.254') && !ip_is_public('::1') && !ip_is_public('fd00::1'));
t('public IP allowed', ip_is_public('1.1.1.1') && ip_is_public('2606:4700:4700::1111'));
