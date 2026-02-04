<?php
declare(strict_types=1);


$baseDir = __DIR__ . '/../';


require_once $baseDir . 'utils/Utils.php';
require_once $baseDir . 'core/crypto/Symmetric.php';
require_once $baseDir . 'core/crypto/Asymmetric.php';
require_once $baseDir . 'core/crypto/Hash.php';
require_once $baseDir . 'core/crypto/FolderEncrypt.php';
require_once $baseDir . 'core/keyring/Keyring.php';
require_once $baseDir . 'core/logging/ActivityLogger.php';

use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Crypto\Hash;
use Bahll\Core\Crypto\FolderEncrypt;
use Bahll\Core\Logging\ActivityLogger;
use Bahll\Core\Keyring\Keyring;

echo "\n=======================================================\n";
echo "   BAHLL CRYPTOGRAPHY SUITE - VALIDATION TEST\n";
echo "=======================================================\n\n";

$passed = 0;
$failed = 0;


echo "[1] AES-256-GCM with Password: ";
try {
    $plaintext = "Hello, World!";
    $password = "MySecurePassword123";
    
    $encrypted = Symmetric::encryptAesGcm($plaintext, $password);
    $decrypted = Symmetric::decryptAesGcm($encrypted, $password);
    
    if ($decrypted === $plaintext) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (mismatch)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[2] AES-256-CBC with HMAC: ";
try {
    $plaintext = "Secret Data";
    $password = "StrongPassword456";
    
    $encrypted = Symmetric::encryptAesCbcWithHmac($plaintext, $password);
    $decrypted = Symmetric::decryptAesCbcWithHmac($encrypted, $password);
    
    if ($decrypted === $plaintext) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (mismatch)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[3] Ed25519 Keypair Generation: ";
try {
    $keypair = Asymmetric::generateEd25519();
    
    if (!isset($keypair['error']) && isset($keypair['private_hex']) && isset($keypair['public_hex'])) {
        $pk_len = strlen(hex2bin($keypair['public_hex']));
        $sk_len = strlen(hex2bin($keypair['private_hex']));
        
        if ($pk_len === 32 && $sk_len === 64) {
            echo "✓\n";
            $passed++;
        } else {
            echo "✗ (size mismatch)\n";
            $failed++;
        }
    } else {
        echo "✗ (generation failed)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[4] SHA256 & SHA512 Hashing: ";
try {
    $data = "Test Data";
    $sha256 = Hash::sha256($data);
    $sha512 = Hash::sha512($data);
    
    if (strlen($sha256) === 64 && strlen($sha512) === 128) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (invalid output)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[5] Activity Logger Functionality: ";
try {
    $logger = new ActivityLogger();
    $initialCount = $logger->count();
    
    $logger->logHash('SHA-256');
    $logger->logEncryption('AES-256-GCM', true, 'with password');
    $logger->logKeyGeneration('Ed25519');
    
    $newCount = $logger->count();
    
    if ($newCount >= $initialCount + 3) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (entries not logged)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[6] Folder Encryption Setup: ";
try {
    $fe = new FolderEncrypt();
    $dataDir = $fe->getDataDir();
    $encDir = $fe->getEncryptedDir();
    
    if (is_dir($dataDir) && is_dir($encDir)) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (directories not created)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[7] Keyring Init (24-byte nonce): ";
try {
    $keyring = new Keyring();
    $result = $keyring->init("TestKeyringPassword123");
    
    if ($result === true) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (initialization failed)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[8] Ed25519 Sign & Verify: ";
try {
    $keypair = Asymmetric::generateEd25519();
    $message = "Sign me!";
    
    $signature = Asymmetric::signEd25519($keypair['private_hex'], $message);
    $verified = Asymmetric::verifyEd25519($keypair['public_hex'], $message, $signature);
    
    if ($verified === true && !empty($signature)) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (sign/verify failed)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}


echo "[9] Wrong Password Rejection: ";
try {
    $encrypted = Symmetric::encryptAesCbcWithHmac("Secret", "password1");
    $decrypted = Symmetric::decryptAesCbcWithHmac($encrypted, "password2");
    
    if ($decrypted === false) {
        echo "✓\n";
        $passed++;
    } else {
        echo "✗ (wrong password accepted)\n";
        $failed++;
    }
} catch (Exception $e) {
    echo "✗ " . $e->getMessage() . "\n";
    $failed++;
}

echo "\n=======================================================\n";
echo "   TEST RESULTS\n";
echo "=======================================================\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";
echo "Total:  " . ($passed + $failed) . "\n\n";

if ($failed === 0) {
    echo "✓ ALL TESTS PASSED - Bahll is fully operational!\n\n";
    exit(0);
} else {
    echo "✗ Some tests failed - review errors above\n\n";
    exit(1);
}
