<?php
/**
 * Seal ID — profile picture (added 1.1.0).
 *
 * The picture is part of the signed profile: the profile statement holds the
 * SHA-256 of the image bytes ("avatar"), so nobody can swap the picture
 * without the owner's key. Uploads are re-drawn by GD (cropped square,
 * resized, saved as WebP/PNG) so no metadata or odd payloads survive.
 *
 * Files in the data folder:
 *   avatar.bin + avatar.json {sha, mime}                    the current picture
 *   avatar-pending.bin + avatar-pending.json {sha, mime}    uploaded, not yet signed
 */
declare(strict_types=1);

const AVATAR_SIZE = 384;
const AVATAR_MAX_UPLOAD = 4 * 1048576;
const AVATAR_MAX_SERVE = 524288;
const AVATAR_TYPES = ['image/webp', 'image/png', 'image/jpeg'];

/** Turn uploaded bytes into a clean square picture. Returns [bytes, mime]. */
function avatar_process(string $bytes): array
{
    if ($bytes === '' || strlen($bytes) > AVATAR_MAX_UPLOAD) throw new RuntimeException('Pictures can be up to 4 MB.');
    $info = @getimagesizefromstring($bytes);
    if (!$info || !in_array($info['mime'] ?? '', ['image/png', 'image/jpeg', 'image/webp', 'image/gif'], true)) {
        throw new RuntimeException('Use a PNG, JPEG, WebP or GIF picture.');
    }
    [$w, $h] = $info;
    if ($w < 32 || $h < 32 || $w > 8000 || $h > 8000) throw new RuntimeException('The picture must be between 32 and 8000 pixels wide and high.');

    if (!function_exists('imagecreatefromstring')) {
        // No GD on this host: keep the picture as it is, if it is small and a safe type.
        if (!in_array($info['mime'], AVATAR_TYPES, true) || strlen($bytes) > AVATAR_MAX_SERVE) {
            throw new RuntimeException('This server can’t resize pictures (no PHP GD). Upload a square PNG, JPEG or WebP under 512 KB.');
        }
        return [$bytes, $info['mime']];
    }
    $src = @imagecreatefromstring($bytes);
    if (!$src) throw new RuntimeException('That picture could not be read.');
    $side = min($w, $h);
    $out = min(AVATAR_SIZE, $side);
    $dst = imagecreatetruecolor($out, $out);
    imagealphablending($dst, false);
    imagesavealpha($dst, true);
    imagefill($dst, 0, 0, imagecolorallocatealpha($dst, 0, 0, 0, 127));
    imagecopyresampled($dst, $src, 0, 0, intdiv($w - $side, 2), intdiv($h - $side, 2), $out, $out, $side, $side);
    ob_start();
    if (function_exists('imagewebp')) { imagewebp($dst, null, 86); $mime = 'image/webp'; }
    else { imagepng($dst, null, 9); $mime = 'image/png'; }
    $clean = (string)ob_get_clean();
    imagedestroy($src);
    imagedestroy($dst);
    if ($clean === '') throw new RuntimeException('The picture could not be saved.');
    return [$clean, $mime];
}

/** Store an upload as the pending picture; returns its SHA-256. */
function avatar_store_pending(string $bytes): array
{
    [$clean, $mime] = avatar_process($bytes);
    $sha = hash('sha256', $clean);
    atomic_write(data_dir() . '/avatar-pending.bin', $clean);
    jwrite('avatar-pending.json', ['sha' => $sha, 'mime' => $mime]);
    return ['sha' => $sha, 'mime' => $mime, 'data' => 'data:' . $mime . ';base64,' . base64_encode($clean)];
}

/** After a signed profile statement: make the pending picture current (if it is the signed one). */
function avatar_commit(?string $sha): void
{
    $d = data_dir();
    if ($sha === null) {
        @unlink("$d/avatar.bin");
        @unlink("$d/avatar.json");
        return;
    }
    $cur = jread('avatar.json', []);
    if (($cur['sha'] ?? '') === $sha && is_file("$d/avatar.bin")) return;
    $p = jread('avatar-pending.json', []);
    if (($p['sha'] ?? '') !== $sha || !is_file("$d/avatar-pending.bin") || hash_file('sha256', "$d/avatar-pending.bin") !== $sha) return;
    @rename("$d/avatar-pending.bin", "$d/avatar.bin");
    jwrite('avatar.json', ['sha' => $sha, 'mime' => $p['mime']]);
    @unlink("$d/avatar-pending.json");
}

/** Is a picture with this hash available to sign (current or pending)? */
function avatar_known(string $sha): bool
{
    return (jread('avatar.json', [])['sha'] ?? '') === $sha || (jread('avatar-pending.json', [])['sha'] ?? '') === $sha;
}

/** The current signed picture: ['sha','mime','file'] or null. */
function avatar_current(): ?array
{
    $want = Chain::state()['avatar'] ?? null;
    if (!$want) return null;
    $a = jread('avatar.json', []);
    $f = data_dir() . '/avatar.bin';
    if (($a['sha'] ?? '') !== $want || !is_file($f)) return null;
    return ['sha' => $want, 'mime' => in_array($a['mime'] ?? '', AVATAR_TYPES, true) ? $a['mime'] : 'image/png', 'file' => $f];
}

/** URL of our own picture (relative), cache-safe because it carries the hash. */
function avatar_url(): ?string
{
    $a = avatar_current();
    return $a ? 'api.php?a=avatar&h=' . substr($a['sha'], 0, 16) : null;
}

/** Fetch another Seal ID's picture and check it against the signed hash. Returns a data: URI or null. */
function avatar_fetch_peer(string $url, string $sha): ?string
{
    $r = http_fetch($url . '/api.php?a=avatar&h=' . substr($sha, 0, 16), ['max_bytes' => AVATAR_MAX_SERVE, 'accept' => 'image/*', 'timeout' => 10]);
    if ($r['status'] !== 200 || !hash_equals($sha, hash('sha256', $r['body']))) return null;
    $info = @getimagesizefromstring($r['body']);
    if (!$info || !in_array($info['mime'] ?? '', AVATAR_TYPES, true)) return null;
    return 'data:' . $info['mime'] . ';base64,' . base64_encode($r['body']);
}

/** An <img> or the initial-letter placeholder. */
function avatar_html(?string $src, string $name, string $class = 'avatar'): string
{
    if ($src) return '<img class="' . h($class) . ' avatar-img" src="' . h($src) . '" alt="">';
    $initial = mb_strtoupper(mb_substr($name !== '' ? $name : '?', 0, 1));
    return '<div class="' . h($class) . '" aria-hidden="true">' . h($initial) . '</div>';
}
