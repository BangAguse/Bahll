<?php
declare(strict_types=1);


require_once __DIR__ . '/../bahll.php';

use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Crypto\Hash;
use Bahll\Core\Crypto\FolderEncrypt;
use Bahll\Core\Logging\ActivityLogger;
use Bahll\Core\Keyring\Keyring;

echo "\n═══════════════════════════════════════════════════════════\n";
echo "  BAHLL CRYPTOGRAPHY SUITE - VALIDATION TEST\n";
echo "═══════════════════════════════════════════════════════════\n\n";

$testsPassed = 0;
$testsFailed = 0;


echo "[TEST 1] Symmetric Encryption (AES-256-GCM with Password)\n";
try {
    $plaintext = "Hello, World!";
    $password = "MySecurePassword123";
    
    $encrypted = Symmetric::encryptAesGcm($plaintext, $password);
    $decrypted = Symmetric::decryptAesGcm($encrypted, $password);
    
    if ($decrypted === $plaintext) {
        echo "  ✓ PASS: Encryption/Decryption works correctly\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Decrypted text doesn't match\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 2] Symmetric Encryption (AES-256-CBC with HMAC)\n";
try {
    $plaintext = "Secret Data";
    $password = "StrongPassword456";
    
    $encrypted = Symmetric::encryptAesCbcWithHmac($plaintext, $password);
    $decrypted = Symmetric::decryptAesCbcWithHmac($encrypted, $password);
    
    if ($decrypted === $plaintext) {
        echo "  ✓ PASS: AES-CBC with HMAC works\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Decrypted text doesn't match\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 3] Ed25519 Keypair Generation\n";
try {
    $keypair = Asymmetric::generateEd25519();
    
    if (isset($keypair['private_hex']) && isset($keypair['public_hex'])) {
        $pk_len = strlen(hex2bin($keypair['public_hex']));
        $sk_len = strlen(hex2bin($keypair['private_hex']));
        
        if ($pk_len === 32 && $sk_len === 64) {
            echo "  ✓ PASS: Ed25519 keypair generated with correct sizes\n";
            $testsPassed++;
        } else {
            echo "  ✗ FAIL: Key sizes incorrect (PK: {$pk_len}, SK: {$sk_len})\n";
            $testsFailed++;
        }
    } else {
        echo "  ✗ FAIL: Keypair missing keys\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 4] Hashing Algorithms\n";
try {
    $data = "Test Data";
    
    $sha256 = Hash::sha256($data);
    $sha512 = Hash::sha512($data);
    $blake2 = Hash::blake2($data);
    
    if (strlen($sha256) === 64 && strlen($sha512) === 128 && !strpos($blake2, '✖')) {
        echo "  ✓ PASS: All hash algorithms working\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Some hash algorithms failed\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 5] Activity Logger\n";
try {
    $logger = new ActivityLogger();
    $initialCount = $logger->count();
    
    $logger->logHash('SHA-256');
    $logger->logEncryption('AES-256-GCM', true);
    $logger->logKeyGeneration('Ed25519');
    
    $newCount = $logger->count();
    
    if ($newCount >= $initialCount + 3) {
        echo "  ✓ PASS: Activity logging working\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Entries not logged correctly\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 6] Folder Encryption Setup\n";
try {
    $fe = new FolderEncrypt();
    $dataDir = $fe->getDataDir();
    $encDir = $fe->getEncryptedDir();
    
    if (is_dir($dataDir) && is_dir($encDir)) {
        echo "  ✓ PASS: Folder structure created\n";
        echo "    Data Dir: {$dataDir}\n";
        echo "    Encrypted Dir: {$encDir}\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Directories not created\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n[TEST 7] Keyring Initialization (24-byte nonce)\n";
try {
    $keyring = new Keyring();
    $result = $keyring->init("TestKeyringPassword");
    
    if ($result) {
        echo "  ✓ PASS: Keyring initialized with 24-byte nonce support\n";
        $testsPassed++;
    } else {
        echo "  ✗ FAIL: Keyring initialization failed\n";
        $testsFailed++;
    }
} catch (Exception $e) {
    echo "  ✗ FAIL: " . $e->getMessage() . "\n";
    $testsFailed++;
}


echo "\n═══════════════════════════════════════════════════════════\n";
echo "  TEST SUMMARY\n";
echo "═══════════════════════════════════════════════════════════\n\n";
echo "Tests Passed: $testsPassed\n";
echo "Tests Failed: $testsFailed\n";
echo "Total Tests: " . ($testsPassed + $testsFailed) . "\n\n";

if ($testsFailed === 0) {
    echo "✓ ALL TESTS PASSED - Bahll is ready to use!\n\n";
} else {
    echo "✗ Some tests failed - review errors above\n\n";
}

echo "═══════════════════════════════════════════════════════════\n";
