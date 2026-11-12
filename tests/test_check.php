<?php
/** Public checker (1.5.0): input cleanup and verdicts (included by tests/run.php) — offline. */
declare(strict_types=1);
require_once __DIR__ . '/../src/lib/chain.php';
require_once __DIR__ . '/../src/lib/check.php';

// What people type → the address that gets checked
$n = [
    'jeffbristow.com' => 'https://jeffbristow.com',
    '  JeffBristow.com/ ' => 'https://jeffbristow.com',
    'www.jeffbristow.com' => 'https://jeffbristow.com',
    'http://jeffbristow.com' => 'https://jeffbristow.com',
    'https://www.example.com/team' => 'https://example.com/team',
    'https://id.bristow.ch/index.php' => 'https://id.bristow.ch',
    'id.bristow.ch' => 'https://id.bristow.ch',
];
foreach ($n as $in => $want) t("check: normalize '$in'", check_normalize($in) === $want, (string)check_normalize($in));
foreach (['', 'not a domain', 'localhost', 'https://example.com/?x=1', 'https://user@example.com', 'example.com:8080', str_repeat('a', 200) . '.com'] as $bad) {
    t("check: refuses '" . substr($bad, 0, 30) . "'", check_normalize($bad) === null);
}

// Verdicts from peer_lookup-shaped reports
$valid = [
    'ok' => true, 'code' => 'ok', 'url' => 'https://id.example.com', 'name' => 'Alice', 'bio' => '', 'avatar' => null,
    'fp' => str_repeat('AB', 20), 'algo' => 'Ed25519', 'created' => 1, 'pin' => 'new',
    'warnings' => ['example.com is a verified alias of this Seal ID.', 'The key was changed 1 time(s) with signed rotations.'],
    'alias' => 'example.com', 'alias_how' => 'dns',
    'proofs' => [
        ['service' => 'github', 'label' => 'GitHub', 'handle' => 'alice', 'status' => 'failed', 'detail' => 'Gone', 'profile' => 'https://github.com/alice'],
        ['service' => 'dns', 'label' => 'Domain (DNS)', 'handle' => 'example.com', 'status' => 'verified', 'detail' => 'OK', 'profile' => null],
        ['service' => 'x', 'label' => 'X', 'handle' => 'alice', 'status' => 'witnessed', 'detail' => 'OK', 'profile' => null],
    ],
];
$r = check_result('example.com', 'https://example.com', $valid, 'https://id.me.test');
t('check: valid alias → valid', $r['verdict'] === 'valid' && $r['title'] === 'Valid Seal ID');
t('check: names the owner', str_contains($r['message'], 'Alice') && str_contains($r['message'], 'example.com belongs to'));
t('check: alias + how', $r['alias'] === 'example.com' && $r['alias_how'] === 'dns');
t('check: verified + witnessed counted', $r['verified_count'] === 2, (string)$r['verified_count']);
t('check: verified proofs first', $r['proofs'][0]['status'] !== 'failed' && end($r['proofs'])['status'] === 'failed');
t('check: alias note not repeated as a warning', count($r['warnings']) === 1 && str_contains($r['warnings'][0], 'rotations'));
t('check: checked_by passed through', $r['checked_by'] === 'https://id.me.test');
t('check: no internal fields leak', !isset($r['hashes']) && !isset($r['attempts']) && !isset($r['pinned']) && !isset($r['vouches']));

$self = $valid; unset($self['alias'], $self['alias_how']); $self['warnings'] = [];
$r = check_result('https://id.example.com', 'https://id.example.com', $self);
t('check: Seal ID address → "is the Seal ID of"', $r['verdict'] === 'valid' && str_contains($r['message'], 'is the Seal ID of Alice') && $r['alias'] === null);

$changed = $self; $changed['pin'] = 'changed';
t('check: changed history warns', count(check_result('x', 'https://id.example.com', $changed)['warnings']) === 1);

$cases = [
    'not_confirmed' => ['ok' => false, 'code' => 'not_confirmed', 'error' => 'example.com points to a Seal ID, but …', 'claimed' => ['https://id.evil.test']],
    'invalid' => ['ok' => false, 'code' => 'invalid', 'error' => 'This Seal ID did not verify: bad signature'],
    'dns_mismatch' => ['ok' => false, 'code' => 'dns_mismatch', 'error' => 'The DNS record names a different key'],
    'blocked' => ['ok' => false, 'code' => 'blocked', 'error' => 'The host blocked automated checking'],
    'not_found' => ['ok' => false, 'code' => 'not_found', 'error' => 'No Seal ID was found at https://example.com.'],
    'bad_address' => ['ok' => false, 'code' => 'bad_address', 'error' => 'That is not a valid address.'],
    'no code' => ['ok' => false, 'error' => 'something'],
];
$want = ['not_confirmed' => 'not_confirmed', 'invalid' => 'invalid', 'dns_mismatch' => 'invalid', 'blocked' => 'unreachable', 'not_found' => 'none', 'bad_address' => 'bad_address', 'no code' => 'none'];
foreach ($cases as $k => $rep) {
    $r = check_result('example.com', 'https://example.com', $rep);
    t("check: $k → {$want[$k]}", $r['verdict'] === $want[$k], $r['verdict']);
    t("check: $k keeps the reason, no profile", $r['message'] === $rep['error'] && !isset($r['fp']) && !isset($r['name']));
}
t('check: not_confirmed lists the claimed Seal ID', (check_result('e.com', 'https://e.com', $cases['not_confirmed'])['claimed'] ?? []) === ['https://id.evil.test']);
