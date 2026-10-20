<?php
// QR Print Studio - hosted website (relay). Stores only ENCRYPTED files for a short time.
// The decryption key lives only inside the QR code (after the # in the link) and never reaches this server.
const MAX_BLOB   = 32 * 1024 * 1024;   // per file
const MAX_ROOM   = 200 * 1024 * 1024;  // per customer session
const MAX_FILES  = 60;
const ROOM_TTL   = 4 * 3600;
const BLOB_TTL   = 1800;
const MAX_ROOMS  = 3000;

$DATA = __DIR__ . '/data';
if (!is_dir($DATA)) { @mkdir($DATA, 0700, true); }
if (!file_exists("$DATA/.htaccess")) { @file_put_contents("$DATA/.htaccess", "Require all denied\nDeny from all\n"); @file_put_contents("$DATA/index.html", ""); }

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');

function fail($code, $msg) { http_response_code($code); header('Content-Type: text/plain'); echo $msg; exit; }
function valid_room($s) { return is_string($s) && preg_match('/^[0-9a-f]{16,64}$/', $s); }
function room_dir($room) { global $DATA; return "$DATA/$room"; }
function meta_read($room) {
    $f = room_dir($room) . '/meta.json';
    if (!is_file($f)) return null;
    $m = json_decode(@file_get_contents($f), true);
    return is_array($m) ? $m : null;
}
function rrmdir($d) {
    if (!is_dir($d)) return;
    foreach (scandir($d) as $f) { if ($f === '.' || $f === '..') continue; $p = "$d/$f"; is_dir($p) ? rrmdir($p) : @unlink($p); }
    @rmdir($d);
}
function gc() {
    global $DATA;
    if (mt_rand(1, 20) !== 1) return; // run on ~5% of requests
    $now = time();
    foreach (glob("$DATA/*", GLOB_ONLYDIR) ?: [] as $d) {
        $m = @json_decode(@file_get_contents("$d/meta.json"), true);
        if (!$m || $now - ($m['created'] ?? 0) > ROOM_TTL) { rrmdir($d); continue; }
        foreach (glob("$d/*.bin") ?: [] as $b) { if ($now - filemtime($b) > BLOB_TTL) @unlink($b); }
    }
}
function pc_ok($m) {
    $t = $_SERVER['HTTP_X_PC'] ?? '';
    return $t !== '' && hash_equals($m['hash'], hash('sha256', $t));
}
function json_out($v) { header('Content-Type: application/json'); echo json_encode($v); exit; }

gc();
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
if ($base !== '' && strpos($path, $base) === 0) $path = substr($path, strlen($base));
$parts = array_values(array_filter(explode('/', $path), 'strlen'));
$method = $_SERVER['REQUEST_METHOD'];

// ---- phone page: /p/ROOM
if (($parts[0] ?? '') === 'p') {
    $room = $parts[1] ?? '';
    if (!valid_room($room) || !meta_read($room)) fail(404, 'This QR code has expired. Please scan the new one on the counter computer.');
    header('Content-Type: text/html; charset=utf-8');
    readfile(__DIR__ . '/phone.html');
    exit;
}

// ---- API: /r/ROOM/...
if (($parts[0] ?? '') === 'r') {
    $room = $parts[1] ?? '';
    if (!valid_room($room)) fail(404, 'not found');
    $act = $parts[2] ?? '';
    $dir = room_dir($room);
    $m = meta_read($room);

    if ($act === 'open' && $method === 'POST') {
        $tok = $_SERVER['HTTP_X_PC'] ?? '';
        if (strlen($tok) < 16) fail(400, 'bad token');
        $h = hash('sha256', $tok);
        if ($m) { if (!hash_equals($m['hash'], $h)) fail(409, 'taken'); echo 'ok'; exit; }
        if (count(glob("$DATA/*", GLOB_ONLYDIR) ?: []) >= MAX_ROOMS) fail(503, 'busy');
        @mkdir($dir, 0700, true);
        file_put_contents("$dir/meta.json", json_encode(['hash' => $h, 'created' => time(), 'seq' => 0]));
        echo 'ok'; exit;
    }

    if ($act === 'up' && $method === 'POST') {
        if (!$m) fail(404, 'expired');
        $len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($len > MAX_BLOB) fail(413, 'too large');
        $data = file_get_contents('php://input', false, null, 0, MAX_BLOB + 1);
        if ($data === false || strlen($data) < 29 || strlen($data) > MAX_BLOB) fail(413, 'bad or too large (max 30 MB per file)');
        $lock = fopen("$dir/.lock", 'c'); flock($lock, LOCK_EX);
        $m = meta_read($room);
        $files = glob("$dir/*.bin") ?: [];
        $total = 0; foreach ($files as $f) $total += filesize($f);
        if (count($files) >= MAX_FILES || $total + strlen($data) > MAX_ROOM) { flock($lock, LOCK_UN); fail(507, 'full'); }
        $m['seq']++;
        $id = $m['seq'] . '-' . bin2hex(random_bytes(3));
        file_put_contents("$dir/$id.bin", $data);
        file_put_contents("$dir/meta.json", json_encode($m));
        flock($lock, LOCK_UN);
        json_out(['id' => $id]);
    }

    if (!$m) fail(404, 'not found');
    if (!pc_ok($m)) fail(403, 'forbidden');

    if ($act === 'list' && $method === 'GET') {
        $out = [];
        $files = glob("$dir/*.bin") ?: [];
        usort($files, function ($a, $b) { return (int)basename($a) <=> (int)basename($b); });
        foreach ($files as $f) $out[] = ['id' => basename($f, '.bin'), 'size' => filesize($f)];
        json_out($out);
    }
    if ($act === 'f' && isset($parts[3]) && preg_match('/^[0-9]+-[0-9a-f]+$/', $parts[3])) {
        $f = "$dir/{$parts[3]}.bin";
        if ($method === 'GET') {
            if (!is_file($f)) fail(404, 'not found');
            header('Content-Type: application/octet-stream');
            header('Content-Length: ' . filesize($f));
            readfile($f); exit;
        }
        if ($method === 'DELETE') { @unlink($f); echo 'ok'; exit; }
    }
    if ($act === '' && $method === 'DELETE') { rrmdir($dir); echo 'ok'; exit; }
    fail(404, 'not found');
}

header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><meta name="viewport" content="width=device-width"><body style="font:18px Arial;padding:40px">QR Print Studio website is running &#10003;<br><small>Scan the QR shown on the counter computer.</small>';
