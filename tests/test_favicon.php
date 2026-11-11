<?php
/** Favicon decoding (included by tests/run.php) — offline; skipped without GD. */
declare(strict_types=1);
require_once __DIR__ . '/../src/lib/favicon.php';

if (!function_exists('imagecreatetruecolor')) {
    echo "skip  favicon tests (no GD; try: php -d extension=gd tests/run.php)\n";
    return;
}

$png = function (int $w, int $h, array $rgb = [60, 207, 145]): string {
    $im = imagecreatetruecolor($w, $h);
    imagefill($im, 0, 0, imagecolorallocate($im, ...$rgb));
    ob_start(); imagepng($im); return (string)ob_get_clean();
};
// ICO directory with one entry
$ico = fn(int $w, int $bpp, string $data) => "\x00\x00\x01\x00" . pack('v', 1)
    . pack('CCCCvvVV', $w & 0xff, $w & 0xff, 0, 0, 1, $bpp, strlen($data), 22) . $data;
// 32-bit bitmap entry: BITMAPINFOHEADER with double height, BGRA pixels, then the AND mask
$bmp32 = function (int $w, array $rgb) {
    $hdr = pack('VllvvVVllVV', 40, $w, $w * 2, 1, 32, 0, 0, 0, 0, 0, 0);
    $px = str_repeat(chr($rgb[2]) . chr($rgb[1]) . chr($rgb[0]) . "\xff", $w * $w);
    $mask = str_repeat("\0", (int)(ceil($w / 32) * 4) * $w);
    return $hdr . $px . $mask;
};
$color = function ($im): array { $c = imagecolorat($im, 4, 4); return [($c >> 16) & 255, ($c >> 8) & 255, $c & 255]; };

$im = favicon_decode($png(32, 32));
t('favicon: PNG decodes', $im !== null && imagesx($im) === 32);
t('favicon: tiny image refused', favicon_decode($png(4, 4)) === null);
t('favicon: huge image refused', favicon_decode($png(1200, 20)) === null);
t('favicon: garbage refused', favicon_decode('not an image at all') === null);
t('favicon: SVG refused', favicon_decode('<svg xmlns="http://www.w3.org/2000/svg"></svg>') === null);
$im = favicon_decode($ico(48, 32, $png(48, 48, [10, 20, 30])));
t('favicon: ICO with a PNG entry', $im !== null && imagesx($im) === 48 && $color($im) === [10, 20, 30]);
if (function_exists('imagecreatefrombmp')) {
    $im = favicon_decode($ico(16, 32, $bmp32(16, [200, 100, 50])));
    t('favicon: ICO with a 32-bit bitmap entry', $im !== null && imagesx($im) === 16 && imagesy($im) === 16 && $color($im) === [200, 100, 50],
        $im ? imagesx($im) . 'x' . imagesy($im) . ' ' . implode(',', $color($im)) : 'null');
}
t('favicon: truncated ICO refused', favicon_decode(substr($ico(16, 32, $bmp32(16, [1, 2, 3])), 0, 30)) === null);
