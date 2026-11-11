<?php
/**
 * Seal ID — outgoing requests.
 *
 * Every fetch of a URL that came from outside (peer addresses, proof
 * locators) goes through http_fetch(): HTTPS only, port 443, public IP
 * addresses only (the resolved address is pinned for the connection so DNS
 * can't be switched in between), redirects followed by hand and re-checked,
 * size and time limits.
 */
declare(strict_types=1);

const HTTP_MAX_BYTES = 1048576;
const HTTP_TIMEOUT = 10;

function http_user_agent(): string
{
    return 'SealID/' . SEALID_VERSION . ' (+' . SEALID_REPO . ')';
}

function ip_is_public(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        && !preg_match('/^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.|169\.254\.|fe80:|fc|fd)/i', $ip);
}

/** Resolve $host to its public addresses, or null if it has none / any private one. */
function resolve_public(string $host): ?array
{
    if (filter_var($host, FILTER_VALIDATE_IP)) return ip_is_public($host) ? [$host] : null;
    $ips = [];
    $a = @gethostbynamel($host);
    if (is_array($a)) $ips = $a;
    $aaaa = @dns_get_record($host, DNS_AAAA);
    if (is_array($aaaa)) foreach ($aaaa as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    if (!$ips) return null;
    foreach ($ips as $ip) if (!ip_is_public($ip)) return null;
    return array_values(array_unique($ips));
}

/**
 * Fetch an HTTPS URL. Returns ['status' => int (0 = no answer), 'body' => string,
 * 'type' => content-type, 'url' => final URL, 'error' => string|null].
 * $opt: method, body, headers (list), max_bytes, timeout, redirects.
 */
function http_fetch(string $url, array $opt = []): array
{
    $redirects = $opt['redirects'] ?? 3;
    $method = $opt['method'] ?? 'GET';
    for ($hop = 0; $hop <= $redirects; $hop++) {
        $p = parse_url($url);
        if (!$p || strtolower($p['scheme'] ?? '') !== 'https' || empty($p['host'])) {
            return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'Only https:// addresses can be fetched.'];
        }
        if (isset($p['port']) && (int)$p['port'] !== 443) {
            return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'Only the standard HTTPS port (443) is allowed.'];
        }
        if (isset($p['user']) || isset($p['pass'])) {
            return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'Addresses with a user name are not allowed.'];
        }
        $host = strtolower(trim($p['host'], '[]'));
        $ips = resolve_public($host);
        if ($ips === null) {
            return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => "Could not find $host (or it points to a private address)."];
        }
        $ip = $ips[0];
        $body = '';
        $tooBig = false;
        $max = $opt['max_bytes'] ?? HTTP_MAX_BYTES;
        $headers = [];
        $ch = curl_init($url);
        $h = array_merge(['Accept: ' . ($opt['accept'] ?? 'application/json, text/plain;q=0.9, */*;q=0.5')], $opt['headers'] ?? []);
        curl_setopt_array($ch, [
            CURLOPT_RESOLVE => [$host . ':443:' . (str_contains($ip, ':') ? "[$ip]" : $ip)],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_TIMEOUT => $opt['timeout'] ?? HTTP_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => $opt['ua'] ?? http_user_agent(),
            CURLOPT_HTTPHEADER => $h,
            CURLOPT_ENCODING => '',
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$headers) {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($c, $chunk) use (&$body, &$tooBig, $max) {
                $body .= $chunk;
                if (strlen($body) > $max) { $tooBig = true; return 0; }
                return strlen($chunk);
            },
        ]);
        if (isset($opt['body'])) curl_setopt($ch, CURLOPT_POSTFIELDS, $opt['body']);
        curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_errno($ch) ? curl_error($ch) : null;

        if ($tooBig) return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'The answer was too large.'];
        if ($err !== null && $status === 0) return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'No answer from ' . $host . ' (' . $err . ').'];
        if ($status >= 300 && $status < 400 && !empty($headers['location']) && !empty($opt['no_follow'])) {
            // The caller wants the redirect itself (e.g. GitHub's /releases/latest → /releases/tag/vX).
            return ['status' => $status, 'body' => '', 'type' => '', 'url' => $url, 'location' => http_resolve_url($url, $headers['location']), 'error' => null];
        }
        if ($status >= 300 && $status < 400 && !empty($headers['location'])) {
            $url = http_resolve_url($url, $headers['location']);
            if ($status === 303) { $method = 'GET'; unset($opt['body']); }
            continue;
        }
        return ['status' => $status, 'body' => $body, 'type' => strtolower($headers['content-type'] ?? ''), 'url' => $url, 'error' => null];
    }
    return ['status' => 0, 'body' => '', 'type' => '', 'url' => $url, 'error' => 'Too many redirects.'];
}

function http_resolve_url(string $base, string $loc): string
{
    if (preg_match('#^https?://#i', $loc)) return $loc;
    $p = parse_url($base);
    $origin = $p['scheme'] . '://' . $p['host'];
    if (str_starts_with($loc, '//')) return $p['scheme'] . ':' . $loc;
    if (str_starts_with($loc, '/')) return $origin . $loc;
    $dir = rtrim(dirname($p['path'] ?? '/'), '/');
    return $origin . $dir . '/' . $loc;
}

function http_json(string $url, array $opt = []): array
{
    $r = http_fetch($url, $opt);
    $r['json'] = ($r['status'] >= 200 && $r['status'] < 300) ? json_decode($r['body'], true) : null;
    return $r;
}

/** TXT records of $name as a list of strings, [] if none, null if DNS failed. */
function dns_txt(string $name): ?array
{
    if (!preg_match('/^[a-z0-9._-]+$/i', $name)) return [];
    $r = @dns_get_record($name, DNS_TXT);
    if ($r === false) return null;
    $out = [];
    foreach ($r as $rec) {
        if (isset($rec['entries']) && is_array($rec['entries'])) $out[] = implode('', $rec['entries']);
        elseif (isset($rec['txt'])) $out[] = $rec['txt'];
    }
    return $out;
}

/** Does this answer look like a bot-check / firewall page rather than real content? */
function http_looks_blocked(array $r): bool
{
    if (in_array($r['status'], [401, 403, 429, 503], true)) return true;
    $b = substr($r['body'] ?? '', 0, 4000);
    return (bool)preg_match('/verify (that )?you(\'| a)re (not a robot|human)|captcha|cf-chl|challenge-platform|stackprotect|Just a moment\.\.\./i', $b);
}
