<?php
declare(strict_types=1);


$dirs = ['core', 'cli', 'utils', 'plugins'];
foreach ($dirs as $d) {
    $p = __DIR__ . DIRECTORY_SEPARATOR . $d;
    if (!is_dir($p)) continue;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p));
    foreach ($it as $f) {
        if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
            require_once $f->getPathname();
        }
    }
}

use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Crypto\Hash;
use Bahll\Core\Crypto\FolderEncrypt;
use Bahll\Core\Logging\ActivityLogger;
use Bahll\Core\Keyring\Keyring;

echo "\n=======================================================\n";
echo "   BAHLL VALIDATION TEST\n";
echo "=======================================================\n\n";

$passed = 0;
$failed = 0;


echo "[1] AES-256-GCM with Password... ";
try {
    $enc = Symmetric::encryptAesGcm("Hello", "pwd123");
    $dec = Symmetric::decryptAesGcm($enc, "pwd123");
    if ($dec === "Hello") {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[2] AES-256-CBC with HMAC... ";
try {
    $enc = Symmetric::encryptAesCbcWithHmac("Secret", "pwd456");
    $dec = Symmetric::decryptAesCbcWithHmac($enc, "pwd456");
    if ($dec === "Secret") {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[3] Ed25519 Generation... ";
try {
    $kp = Asymmetric::generateEd25519();
    if (isset($kp['private_hex']) && isset($kp['public_hex'])) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[4] Hashing (SHA256/SHA512)... ";
try {
    $h1 = Hash::sha256("test");
    $h2 = Hash::sha512("test");
    if (strlen($h1) === 64 && strlen($h2) === 128) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[5] Activity Logger... ";
try {
    $log = new ActivityLogger();
    $c1 = $log->count();
    $log->logHash('SHA-256');
    $c2 = $log->count();
    if ($c2 > $c1) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[6] Folder Encrypt Setup... ";
try {
    $fe = new FolderEncrypt();
    if (is_dir($fe->getDataDir()) && is_dir($fe->getEncryptedDir())) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[7] Keyring Init (24-byte nonce)... ";
try {
    $kr = new Keyring();
    if ($kr->init("test123")) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}

echo "\n=======================================================\n";
echo "   RESULTS: $passed passed, $failed failed\n";
echo "=======================================================\n\n";

if ($failed === 0) {
    echo "✓ ALL TESTS PASSED!\n\n";
} else {
    echo "✗ SOME TESTS FAILED\n\n";
}
