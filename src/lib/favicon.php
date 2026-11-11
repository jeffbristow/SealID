<?php
/**
 * Seal ID — favicons for proven domains (1.3.0).
 *
 * Fetched by THIS server (never by visitors' browsers, which would tell the
 * domain who looks at the profile, and break the page's CSP), through the
 * SSRF-guarded http_fetch(), decoded (PNG/JPEG/GIF/WebP/ICO — ICO with PNG
 * or bitmap images), re-drawn as a 64×64 PNG and served by api.php?a=favicon.
 * Re-fetched weekly. Domains without a usable icon keep the plain globe.
 *
 * Files: <data>/favicons/<sha1(domain)>.png and .json {at, ok, src}
 */
declare(strict_types=1);

const FAVICON_MAX_AGE = 7 * 86400;
const FAVICON_SIZE = 64;

function favicon_path(string $domain, string $ext = 'png'): string
{
    $d = data_dir() . '/favicons';
    if (!is_dir($d)) @mkdir($d, 0700, true);
    return $d . '/' . sha1(strtolower($domain)) . '.' . $ext;
}

/** URL of the cached favicon for one of our own proven domains, or null. */
function favicon_url(string $domain): ?string
{
    $f = favicon_path($domain);
    return is_file($f) ? 'api.php?a=favicon&d=' . rawurlencode($domain) . '&v=' . filemtime($f) : null;
}

/** Refresh favicons that are missing or older than a week (at most $max fetches). */
function favicons_refresh(array $domains, int $max = 1): void
{
    if (!function_exists('imagecreatetruecolor')) return;
    foreach ($domains as $d) {
        if ($max <= 0) return;
        $meta = json_decode((string)@file_get_contents(favicon_path($d, 'json')), true) ?: [];
        if (time() - (int)($meta['at'] ?? 0) < FAVICON_MAX_AGE) continue;
        $max--;
        $src = favicon_fetch($d);
        @file_put_contents(favicon_path($d, 'json'), json_encode(['at' => time(), 'ok' => $src !== null, 'src' => $src]));
    }
}

/** Find, fetch and store a domain's icon. Returns where it came from, or null. */
function favicon_fetch(string $domain): ?string
{
    $cands = [];
    $home = http_fetch("https://$domain/", ['accept' => 'text/html', 'max_bytes' => 512 * 1024, 'timeout' => 10]);
    if ($home['status'] === 200 && preg_match_all('#<link\s[^>]*>#i', $home['body'], $links)) {
        $ranked = [];
        foreach ($links[0] as $l) {
            if (!preg_match('#\brel\s*=\s*["\']([^"\']+)["\']#i', $l, $rel) || !preg_match('#\bhref\s*=\s*["\']([^"\']+)["\']#i', $l, $href)) continue;
            $rel = strtolower($rel[1]);
            if (!str_contains($rel, 'icon')) continue;
            $u = http_resolve_url($home['url'], html_entity_decode($href[1], ENT_QUOTES));
            if (str_ends_with(strtolower(parse_url($u, PHP_URL_PATH) ?? ''), '.svg')) continue;   // can't be drawn here safely
            $size = preg_match('#\bsizes\s*=\s*["\'](\d+)x\d+#i', $l, $sz) ? (int)$sz[1] : 0;
            $score = (str_contains($rel, 'apple-touch') ? 180 : $size) ?: 16;
            $ranked[$u] = max($ranked[$u] ?? 0, $score);
        }
        arsort($ranked);
        $cands = array_keys($ranked);
    }
    $cands[] = "https://$domain/apple-touch-icon.png";
    $cands[] = "https://$domain/favicon.ico";
    foreach (array_slice(array_values(array_unique($cands)), 0, 5) as $u) {
        if (!str_starts_with($u, 'https://')) continue;
        $r = http_fetch($u, ['accept' => 'image/*', 'max_bytes' => 512 * 1024, 'timeout' => 10]);
        if ($r['status'] !== 200 || $r['body'] === '') continue;
        $img = favicon_decode($r['body']);
        if (!$img) continue;
        $out = imagecreatetruecolor(FAVICON_SIZE, FAVICON_SIZE);
        imagealphablending($out, false);
        imagesavealpha($out, true);
        imagefill($out, 0, 0, imagecolorallocatealpha($out, 0, 0, 0, 127));
        imagecopyresampled($out, $img, 0, 0, 0, 0, FAVICON_SIZE, FAVICON_SIZE, imagesx($img), imagesy($img));
        ob_start(); imagepng($out, null, 9); $png = (string)ob_get_clean();
        if ($png === '') continue;
        atomic_write(favicon_path($domain), $png);
        return $u;
    }
    @unlink(favicon_path($domain));
    return null;
}

/** Bytes → GD image (PNG, JPEG, GIF, WebP, ICO with PNG or bitmap entries), or null. */
function favicon_decode(string $b): mixed
{
    if (strncmp($b, "\x00\x00\x01\x00", 4) === 0) return favicon_decode_ico($b);
    $info = @getimagesizefromstring($b);
    if (!$info || !in_array($info['mime'] ?? '', ['image/png', 'image/jpeg', 'image/gif', 'image/webp'], true)) return null;
    if ($info[0] < 8 || $info[1] < 8 || $info[0] > 1024 || $info[1] > 1024) return null;
    return @imagecreatefromstring($b) ?: null;
}

function favicon_decode_ico(string $b): mixed
{
    $n = unpack('v', substr($b, 4, 2))[1] ?? 0;
    if ($n < 1 || $n > 64 || strlen($b) < 6 + 16 * $n) return null;
    $best = null;
    for ($i = 0; $i < $n; $i++) {
        $e = unpack('Cw/Ch/Ccolors/Cres/vplanes/vbpp/Vsize/Voffset', substr($b, 6 + 16 * $i, 16));
        $w = $e['w'] ?: 256;
        if ($e['offset'] + $e['size'] > strlen($b) || $e['size'] < 40) continue;
        if (!$best || $w > $best['w'] || ($w === $best['w'] && $e['bpp'] > $best['bpp'])) $best = $e + ['w' => $w];
    }
    if (!$best) return null;
    $data = substr($b, $best['offset'], $best['size']);
    if (strncmp($data, "\x89PNG", 4) === 0) return favicon_decode($data);
    // A bitmap entry: a BMP without its file header, twice as high (the AND mask follows).
    $hdr = unpack('Vsize/lwidth/lheight/vplanes/vbpp/Vcompr/Vimgsize/lxppm/lyppm/Vclrused', substr($data, 0, 36));
    if ($hdr['size'] < 40 || $hdr['width'] < 8 || $hdr['width'] > 256) return null;
    $bpp = $hdr['bpp'];
    $palette = $bpp <= 8 ? 4 * ($hdr['clrused'] ?: (1 << $bpp)) : 0;
    $realH = intdiv(abs($hdr['height']), 2);
    $dib = substr($data, 0, 8) . pack('l', $realH) . substr($data, 12);
    $bmp = 'BM' . pack('V', 14 + strlen($dib)) . "\0\0\0\0" . pack('V', 14 + $hdr['size'] + $palette) . $dib;
    if (!function_exists('imagecreatefrombmp')) return null;
    $tmp = tempnam(sys_get_temp_dir(), 'sidico');
    file_put_contents($tmp, $bmp);
    $img = @imagecreatefrombmp($tmp);
    @unlink($tmp);
    return $img ?: null;
}
