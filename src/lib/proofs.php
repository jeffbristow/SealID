<?php
/**
 * Seal ID — proofs (docs/PROTOCOL.md section 5).
 *
 * Each service is a class in lib/proofs/<id>.php extending ProofService.
 * Check results: verified | failed | unreachable | pending | witnessed | unsupported.
 */
declare(strict_types=1);

abstract class ProofService
{
    public const ID = '';
    public const LABEL = '';
    public const HANDLE_HINT = '';
    /** Does the owner have to tell us where the proof post is? */
    public const LOCATOR = false;
    /** Can a server check it automatically? (false = witnessed only) */
    public const AUTO = true;

    /** Normalise a handle typed by the owner, or null if it is not valid. */
    abstract public static function normalize(string $raw): ?string;

    /** Public URL of the account. */
    abstract public static function profileUrl(string $handle): ?string;

    /** Owner-facing steps: where to put the proof text. */
    abstract public static function steps(string $handle, string $text, string $token): array;

    /** @return array{status:string, detail:string} */
    abstract public static function check(string $handle, ?string $locator, string $token): array;

    /** Normalised locator URL if it is acceptable for this handle, else null. */
    public static function locatorOk(string $handle, string $url): ?string
    {
        return null;
    }

    public static function locatorHint(string $handle): string
    {
        return '';
    }

    /** The text to publish (some services want something shorter or different). */
    public static function publishText(string $text, string $token): string
    {
        return $text;
    }

    protected static function res(string $status, string $detail): array
    {
        return ['status' => $status, 'detail' => $detail];
    }

    /** Turn an HTTP failure into unreachable / failed. */
    protected static function httpProblem(array $r, string $what): array
    {
        if ($r['status'] === 404 || $r['status'] === 410) return self::res('failed', "$what was not found (it may have been deleted).");
        if ($r['status'] === 0) return self::res('unreachable', $r['error'] ?? 'No answer.');
        if (http_looks_blocked($r)) return self::res('unreachable', "The service refused automated checking right now (HTTP {$r['status']}). It will be retried.");
        return self::res('unreachable', "Unexpected answer (HTTP {$r['status']}).");
    }

    protected static function hasToken(string $haystack, string $token): bool
    {
        $t = html_entity_decode(strip_tags(str_replace(['<br>', '<br/>', '<br />', '</p>'], ' ', $haystack)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        return str_contains($t, $token) || str_contains($haystack, $token);
    }
}

/** @return array<string, class-string<ProofService>> */
function proof_services(): array
{
    static $list = null;
    if ($list !== null) return $list;
    $list = [];
    foreach (['web', 'dns', 'github', 'x', 'mastodon', 'bluesky', 'hackernews', 'reddit', 'youtube', 'facebook'] as $id) {
        $f = __DIR__ . "/proofs/$id.php";
        if (!is_file($f)) continue;
        require_once $f;
        $cls = 'Proof_' . $id;
        if (class_exists($cls)) $list[$id] = $cls;
    }
    return $list;
}

/** @return class-string<ProofService>|null */
function proof_service(string $id): ?string
{
    return proof_services()[$id] ?? null;
}

/**
 * Check one proof of identity $url. $proof = ['service','handle','token'].
 */
function proof_check(array $proof, ?string $locator): array
{
    $cls = proof_service($proof['service']);
    if ($cls === null) return ['status' => 'unsupported', 'detail' => 'This Seal ID version cannot check "' . $proof['service'] . '" proofs.'];
    if (!$cls::AUTO) return ['status' => 'pending', 'detail' => 'Checked by people: other Seal ID owners witness this proof.'];
    if ($cls::LOCATOR && !$locator) return ['status' => 'pending', 'detail' => 'Waiting for the address of the proof post.'];
    if ($locator && $cls::LOCATOR && $cls::locatorOk($proof['handle'], $locator) === null) {
        return ['status' => 'failed', 'detail' => 'The proof address does not belong to ' . $proof['handle'] . '.'];
    }
    try {
        return $cls::check($proof['handle'], $locator, $proof['token']);
    } catch (Throwable $e) {
        return ['status' => 'unreachable', 'detail' => 'Check failed: ' . $e->getMessage()];
    }
}

/** Witness counts for our own proofs, from the vouches we received. seq => [count, [urls]] */
function own_witnesses(array $st): array
{
    $out = [];
    foreach (jread('vouches.json', []) as $v) {
        foreach ($v['proofs'] ?? [] as $p) {
            $mine = $st['proofs'][$p['seq']] ?? null;
            if (!$mine || $mine['service'] !== $p['service'] || $mine['handle'] !== $p['handle']) continue;
            $out[$p['seq']]['all'][] = $v['url'];
            if ($p['how'] === 'witnessed') $out[$p['seq']]['witnessed'][] = $v['url'];
        }
    }
    return $out;
}

/** Our own proofs with their stored status, locator and witnesses, newest first. */
function own_proofs(): array
{
    $st = Chain::state();
    if (empty($st['proofs'])) return [];
    $checks = jread('checks.json', []);
    $loc = jread('locators.json', []);
    $wit = own_witnesses($st);
    $out = [];
    foreach (array_reverse($st['proofs'], true) as $seq => $p) {
        $cls = proof_service($p['service']);
        $c = $checks[$seq] ?? null;
        $w = $wit[$seq]['witnessed'] ?? [];
        $status = $c['status'] ?? ($cls && !$cls::AUTO ? 'pending' : 'pending');
        if ($cls && !$cls::AUTO) $status = $w ? 'witnessed' : 'pending';
        $out[] = $p + [
            'label' => $cls ? $cls::LABEL : $p['service'],
            'profile' => $cls ? $cls::profileUrl($p['handle']) : null,
            'locator' => $loc[$seq] ?? null,
            'needs_locator' => $cls ? $cls::LOCATOR : false,
            'auto' => $cls ? $cls::AUTO : false,
            'status' => $status,
            'detail' => $c['detail'] ?? ($cls && !$cls::AUTO ? 'Waiting for other Seal ID owners to witness it.' : 'Not checked yet.'),
            'checked' => $c['at'] ?? 0,
            'witnesses' => $w,
            'vouchers' => array_values(array_unique($wit[$seq]['all'] ?? [])),
        ];
    }
    return $out;
}

/**
 * Re-check our own proofs. Without $force only stale ones (verified: older
 * than recheck_hours; others: older than 30 minutes), at most $max per call.
 */
function own_recheck(int $max = 3, bool $force = false, ?int $onlySeq = null): int
{
    $st = Chain::state();
    if (empty($st['proofs'])) return 0;
    $lockF = data_dir() . '/.recheck.lock';
    $lh = fopen($lockF, 'c');
    if ($lh === false || !flock($lh, LOCK_EX | LOCK_NB)) return 0;     // someone else is already checking
    try {
        $checks = jread('checks.json', []);
        $loc = jread('locators.json', []);
        $hours = (float)cfg('recheck_hours', 6);
        $todo = [];
        foreach ($st['proofs'] as $seq => $p) {
            if ($onlySeq !== null && $seq !== $onlySeq) continue;
            $cls = proof_service($p['service']);
            if (!$cls || !$cls::AUTO) continue;
            $c = $checks[$seq] ?? null;
            $age = $c ? time() - (int)$c['at'] : PHP_INT_MAX;
            $limit = ($c['status'] ?? '') === 'verified' ? $hours * 3600 : 1800;
            if ($force || $age > $limit) $todo[$seq] = $age;
        }
        arsort($todo);
        $n = 0;
        foreach (array_slice(array_keys($todo), 0, $max) as $seq) {
            $r = proof_check($st['proofs'][$seq], $loc[$seq] ?? null);
            // A proof that verified before and is now merely unreachable keeps its status for a day.
            $prev = $checks[$seq] ?? null;
            if ($r['status'] === 'unreachable' && ($prev['status'] ?? '') === 'verified' && time() - (int)($prev['ok_at'] ?? 0) < 86400) {
                $checks[$seq]['detail'] = 'Verified earlier; the last re-check could not reach the service.';
                $checks[$seq]['at'] = time();
            } else {
                $checks[$seq] = ['status' => $r['status'], 'detail' => $r['detail'], 'at' => time(), 'ok_at' => $r['status'] === 'verified' ? time() : (int)($prev['ok_at'] ?? 0)];
            }
            $n++;
        }
        if ($n) {
            jwrite('checks.json', $checks);
            Chain::writeBundle();
        }
        return $n;
    } finally {
        flock($lh, LOCK_UN);
        fclose($lh);
    }
}

function status_label(string $s): string
{
    return [
        'verified' => 'Verified', 'failed' => 'Failed', 'unreachable' => 'Not reachable right now',
        'pending' => 'Pending', 'witnessed' => 'Witnessed', 'unsupported' => 'Not supported here', 'revoked' => 'Revoked',
    ][$s] ?? $s;
}
