<?php
namespace Bahll\CLI;

use Bahll\CLI\Input;
use Bahll\CLI\Output;
use Bahll\Core\Crypto\Hash;
use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Crypto\FolderEncrypt;
use Bahll\Core\Crypto\Bruteforce;
use Bahll\Core\Keyring\Keyring;
use Bahll\Core\Logging\ActivityLogger;

class Menu
{
    private ActivityLogger $logger;
    private FolderEncrypt $folderEncrypt;

    public function __construct()
    {
        $this->logger = new ActivityLogger();
        $this->folderEncrypt = new FolderEncrypt();
    }

    public function run(): void
    {
        $this->clearScreen();
        Output::banner();
        $keyring = new Keyring();

        while (true) {
            Output::section("Main Menu");
            Output::writeln("1) Hashing & KDF");
            Output::writeln("2) Symmetric Encryption");
            Output::writeln("3) Asymmetric Crypto");
            Output::writeln("4) Keyring / Key Management");
            Output::writeln("5) Encoding / Obfuscation");
            Output::writeln("6) Randomness & Entropy");
            Output::writeln("7) Audit & Validation");
            Output::writeln("8) Secret Lifecycle");
            Output::writeln("9) Encryptor Manager");
            Output::writeln("10) Decryptor Manager");
            Output::writeln("11) Activity Log");
            Output::writeln("12) Dev & CI Utilities");
            Output::writeln("h) Help");
            Output::writeln("i) Info");
            Output::writeln("q) Exit");
            Output::writeln("Type clear to clear the display");

            $choice = Input::prompt('Select an option');

            switch (trim($choice)) {
                case '1':
                    $this->menuHash();
                    break;
                case '2':
                    $this->menuSymmetric();
                    break;
                case '3':
                    $this->menuAsymmetric();
                    break;
                case '4':
                    $this->menuKeyring($keyring);
                    break;
                case '5':
                    $this->menuEncoding();
                    break;
                case '6':
                    $this->menuRandom();
                    break;
                case '7':
                    $this->menuAudit();
                    break;
                case '8':
                    $this->menuSecrets();
                    break;
                case '9':
                    $this->menuEncryptor();
                    break;
                case '10':
                    $this->menuDecryptorManager();
                    break;
                case '11':
                    $this->menuActivityLog();
                    break;
                case '12':
                    Output::writeln("Dev & CI utilities are available in the CLI.");
                    break;
                case 'h':
                case 'H':
                    $this->menuHelp();
                    break;
                case 'i':
                case 'I':
                    $this->menuInfo();
                    break;
                case 'clear':
                case 'CLEAR':
                case 'Clear':
                    $this->clearScreen();
                    Output::banner();
                    
                    break;
                case 'q':
                case 'Q':
                    Output::writeln("Bye.");
                    $this->logger->log('Application exit', 'success');
                    exit(0);
                default:
                    Output::error("Invalid selection, try again.");
            }
        }
    }

    private function clearScreen(): void
    {
        if (DIRECTORY_SEPARATOR === '/') {
            
            if (function_exists('system')) {
                @system('clear');
            } elseif (function_exists('exec')) {
                @exec('clear');
            } else {
                
                echo "\033[H\033[2J\033[3J";
            }
        } else {
            @system('cls');
        }

        
        if (function_exists('ob_get_level') && ob_get_level() > 0) {
            @ob_flush();
        }
        @flush();
    }

    private function menuHash(): void
    {
        while (true) {
            Output::section("Hashing & KDF Menu");
            Output::writeln("1) SHA-1");
            Output::writeln("2) SHA-256");
            Output::writeln("3) SHA-512");
            Output::writeln("4) SHA3-512");
            Output::writeln("5) BLAKE2");
            Output::writeln("6) BLAKE3");
            Output::writeln("7) HMAC");
            Output::writeln("8) PBKDF2");
            Output::writeln("9) bcrypt");
            Output::writeln("10) scrypt");
            Output::writeln("11) Argon2id");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
            case '1':
                $d = Input::prompt('Data to hash');
                $hash = Hash::sha1($d);
                Output::warning("SHA-1 is deprecated and insecure");
                Output::result('SHA-1 Hash', $hash);
                $this->logger->logHash('SHA-1');
                break;
            case '2':
                $d = Input::prompt('Data to hash');
                $hash = Hash::sha256($d);
                Output::result('SHA-256 Hash', $hash);
                $this->logger->logHash('SHA-256');
                break;
            case '3':
                $d = Input::prompt('Data to hash');
                $hash = Hash::sha512($d);
                Output::result('SHA-512 Hash', $hash);
                $this->logger->logHash('SHA-512');
                break;
            case '4':
                $d = Input::prompt('Data to hash');
                $hash = Hash::sha3($d);
                if (strpos($hash, '✖') === 0) {
                    Output::error($hash);
                } else {
                    Output::result('SHA3-512 Hash', $hash);
                    $this->logger->logHash('SHA3-512');
                }
                break;
            case '5':
                $d = Input::prompt('Data to hash');
                $hash = Hash::blake2($d);
                if (strpos($hash, '✖') === 0) {
                    Output::error($hash);
                } else {
                    Output::result('BLAKE2 Hash', $hash);
                    $this->logger->logHash('BLAKE2');
                }
                break;
            case '6':
                $msg = Hash::blake3('');
                Output::warning($msg);
                break;
            case '7':
                $d = Input::prompt('Data');
                $k = Input::prompt('Key');
                $hash = Hash::hmac('sha256', $d, $k);
                Output::result('HMAC-SHA256', $hash);
                $this->logger->logHash('HMAC-SHA256');
                break;
            case '8':
                $p = Input::prompt('Password');
                $s = Input::prompt('Salt (leave blank to auto)');
                $iter = (int)Input::prompt('Iterations (e.g. 100000)');
                $hash = Hash::pbkdf2($p, $s ?: null, $iter ?: 100000);
                Output::result('PBKDF2 Derived Key', $hash);
                $this->logger->logHash('PBKDF2');
                break;
            case '9':
                $p = Input::prompt('Password');
                $hash = Hash::bcrypt($p);
                Output::result('bcrypt Hash', $hash);
                $this->logger->logHash('bcrypt');
                break;
            case '10':
                $msg = Hash::scrypt('');
                Output::warning($msg);
                break;
            case '11':
                $p = Input::prompt('Password');
                $hash = Hash::argon2id($p);
                if (strpos($hash, '✖') === 0) {
                    Output::error($hash);
                } else {
                    Output::result('Argon2id Hash', $hash);
                    $this->logger->logHash('Argon2id');
                }
                break;
            default:
                Output::info('Returning to menu selection');
                break;
            }
        }
    }

    private function menuSymmetric(): void
    {
        while (true) {
            Output::section("Symmetric Encryption");
            Output::writeln("1) AES-256-GCM encrypt string");
            Output::writeln("2) AES-256-GCM decrypt string");
            Output::writeln("3) AES-256-CBC with HMAC encrypt");
            Output::writeln("4) AES-256-CBC with HMAC decrypt");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
            case '1':
                $pt = Input::prompt('Plaintext');
                $pw = Input::prompt('Password (leave blank to use random key)');
                $res = Symmetric::encryptAesGcm($pt, $pw ?: null);
                Output::result('Encrypted Data', $res);
                break;
            case '2':
                $blob = Input::prompt('Cipher blob (base64)');
                $pw = Input::prompt('Password (if used)');
                $out = Symmetric::decryptAesGcm($blob, $pw ?: null);
                if ($out === false) {
                    Output::error('Decryption failed - wrong password or corrupted data');
                } else {
                    Output::result('Decrypted Data', $out);
                }
                break;
            case '3':
                $pt = Input::prompt('Plaintext');
                $pw = Input::prompt('Password');
                $res = Symmetric::encryptAesCbcWithHmac($pt, $pw);
                Output::result('Encrypted Data', $res);
                break;
            case '4':
                $blob = Input::prompt('Cipher blob (base64)');
                $pw = Input::prompt('Password');
                $out = Symmetric::decryptAesCbcWithHmac($blob, $pw);
                if ($out === false) {
                    Output::error('Decryption failed - wrong password or MAC verification failed');
                } else {
                    Output::result('Decrypted Data', $out);
                }
                break;
            default:
                Output::info('Returning to menu selection');
                break;
            }
        }
    }

    private function menuAsymmetric(): void
    {
        while (true) {
            Output::section("Asymmetric Crypto");
            Output::writeln("1) Generate RSA keypair");
            Output::writeln("2) Generate Ed25519 keypair");
            Output::writeln("3) Sign/Verify using Ed25519");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
            case '1':
                $bits = (int)Input::prompt('Key size (2048/3072/4096)');
                $p = Input::prompt('Passphrase (optional)');
                $kp = Asymmetric::generateRsa($bits ?: 2048, $p ?: null);
                if (isset($kp['error'])) {
                    Output::error($kp['error']);
                    $this->logger->logKeyGeneration('RSA', $bits ?: 2048);
                } else {
                    Output::section("RSA Keypair Generated");
                    Output::writeln("Private Key:\n" . $kp['private']);
                    Output::writeln("\nPublic Key:\n" . $kp['public']);
                    $this->logger->logKeyGeneration('RSA', $bits ?: 2048);
                }
                break;
            case '2':
                $kp = Asymmetric::generateEd25519();
                if (isset($kp['error'])) {
                    Output::error($kp['error']);
                } else {
                    Output::section("Ed25519 Keypair Generated");
                    Output::result('Private Key (hex)', $kp['private_hex']);
                    Output::result('Public Key (hex)', $kp['public_hex']);
                    $this->logger->logKeyGeneration('Ed25519');
                }
                break;
            case '3':
                $action = Input::prompt('sign/verify');
                if (trim($action) === 'sign') {
                    $sk = Input::prompt('Private key (hex)');
                    $msg = Input::prompt('Message');
                    $sig = Asymmetric::signEd25519($sk, $msg);
                    if (empty($sig)) {
                        Output::error('Signing failed');
                        $this->logger->log('Ed25519 sign', 'failed');
                    } else {
                        Output::result('Signature (base64)', base64_encode($sig));
                        $this->logger->log('Ed25519 sign', 'success');
                    }
                } else {
                    $pk = Input::prompt('Public key (hex)');
                    $msg = Input::prompt('Message');
                    $sig = base64_decode(Input::prompt('Signature (base64)'));
                    $ok = Asymmetric::verifyEd25519($pk, $msg, $sig);
                    if ($ok) {
                        Output::success('Signature VALID');
                        $this->logger->log('Ed25519 verify', 'success');
                    } else {
                        Output::error('Signature INVALID');
                        $this->logger->log('Ed25519 verify', 'failed');
                    }
                }
                break;
            default:
                Output::info('Returning to menu selection');
                break;
            }
        }
    }

    private function menuKeyring(Keyring $k): void
    {
        while (true) {
            Output::section("Keyring Management");
            Output::writeln("1) Initialize keyring");
            Output::writeln("2) Add key");
            Output::writeln("3) List keys");
            Output::writeln("4) Export key");
            Output::writeln("5) Remove key");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
            case '1':
                $pw = Input::prompt('Set passphrase for keyring');
                if ($k->init($pw)) {
                    Output::success('Keyring initialized successfully');
                    $this->logger->log('Keyring init', 'success');
                } else {
                    Output::error('Failed to initialize keyring');
                    $this->logger->log('Keyring init', 'failed');
                }
                break;
            case '2':
                $alias = Input::prompt('Alias');
                $data = Input::prompt('Key data (PEM/json/base64)');
                $pw = Input::prompt('Keyring passphrase');
                if ($k->addKey($alias, $data, $pw)) {
                    Output::success('Key added successfully');
                    $this->logger->log("Add key to keyring - {$alias}", 'success');
                } else {
                    Output::error('Failed to add key');
                    $this->logger->log("Add key to keyring - {$alias}", 'failed');
                }
                break;
            case '3':
                $pw = Input::prompt('Keyring passphrase');
                $list = $k->listKeys($pw);
                if (empty($list)) {
                    Output::info('No keys found');
                } else {
                    Output::section("Stored Keys");
                    foreach ($list as $alias => $info) {
                        Output::writeln("  - {$alias} (added: {$info['added']})");
                    }
                    $this->logger->log('List keyring keys', 'success');
                }
                break;
            case '4':
                $alias = Input::prompt('Alias');
                $pw = Input::prompt('Keyring passphrase');
                $out = $k->exportKey($alias, $pw);
                if ($out === false) {
                    Output::error('Not found or bad passphrase');
                    $this->logger->log("Export key - {$alias}", 'failed');
                } else {
                    Output::result("Key: {$alias}", $out);
                    $this->logger->log("Export key - {$alias}", 'success');
                }
                break;
            case '5':
                $alias = Input::prompt('Alias');
                $pw = Input::prompt('Keyring passphrase');
                if ($k->removeKey($alias, $pw)) {
                    Output::success("Key removed: {$alias}");
                    $this->logger->log("Remove key - {$alias}", 'success');
                } else {
                    Output::error('Not found or bad passphrase');
                    $this->logger->log("Remove key - {$alias}", 'failed');
                }
                break;
            default:
                Output::info('Returning to menu selection');
                break;
            }
        }
    }

    private function menuEncoding(): void
    {
        while (true) {
            Output::section("Encoding / Obfuscation");
            Output::writeln("1) Encode data (Base64/URL-safe/Hex)");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;

            if ($c === '1') {
                $d = Input::prompt('Data to encode');
                if ($d === null) continue;
                $b64 = base64_encode($d);
                $b64url = rtrim(strtr($b64, '+/', '-_'), '=');
                $hex = bin2hex($d);

                Output::writeln('');
                Output::result('Base64', $b64);
                Output::result('URL-safe Base64', $b64url);
                Output::result('Hexadecimal', $hex);

                $this->logger->log('Encode data', 'success', 'Multiple formats');
            } else {
                Output::info('Unknown selection');
            }
        }
    }

    private function menuRandom(): void
    {
        while (true) {
            Output::section("CSPRNG - Randomness Generator");
            Output::writeln("1) Generate random bytes");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;

            if ($c === '1') {
                $n = (int)Input::prompt('Bytes to generate (default 32)');
                $n = $n > 0 ? $n : 32;

                if ($n > 10000) {
                    Output::warning("Large size requested ({$n} bytes), this may be slow");
                }

                $tok = random_bytes($n);
                $hex = bin2hex($tok);
                $b64 = base64_encode($tok);

                Output::writeln('');
                Output::result("Random Bytes (Hex) [{$n} bytes]", $hex);
                Output::result("Random Bytes (Base64)", $b64);

                $this->logger->log('Generate random bytes', 'success', "{$n} bytes");
            } else {
                Output::info('Unknown selection');
            }
        }
    }

    private function menuAudit(): void
    {
        Output::section("Security Audit & System Check");

        Output::writeln("");
        Output::writeln("Extensions:");
        Output::writeln("  OpenSSL: " . (extension_loaded('openssl') ? "✓ available" : "✗ missing"));
        Output::writeln("  Sodium: " . (extension_loaded('sodium') ? "✓ available" : "✗ missing"));

        Output::writeln("\nCipher Support:");
        $ciphers = ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'];
        foreach ($ciphers as $c) {
            $avail = in_array($c, openssl_get_cipher_methods() ?? []);
            Output::writeln("  {$c}: " . ($avail ? "✓ available" : "✗ missing"));
        }

        Output::writeln("\nHash Algorithms:");
        $hashes = ['sha256', 'sha512', 'sha3-512', 'blake2b512'];
        foreach ($hashes as $h) {
            $avail = in_array($h, hash_algos());
            Output::writeln("  {$h}: " . ($avail ? "✓ available" : "✗ missing"));
        }

        Output::writeln("\nPassword Hashing:");
        Output::writeln("  bcrypt: " . (CRYPT_BLOWFISH ? "✓ available" : "✗ missing"));
        Output::writeln("  Argon2id: " . (defined('PASSWORD_ARGON2ID') ? "✓ available" : "✗ missing"));

        Output::writeln("\n");
        $score = $this->calculateSecurityScore();
        Output::highlight("Security Score: {$score}");

        Output::writeln("\nRecommendations:");
        Output::writeln("  • Avoid SHA-1, MD5 - use SHA-256 or better");
        Output::writeln("  • Prefer AEAD ciphers (GCM, Poly1305, ChaCha20)");
        Output::writeln("  • Use RSA >= 2048 bits (4096 preferred)");
        Output::writeln("  • Use Argon2id for password hashing");

        $this->logger->log('Audit system', 'success');
    }

    
    private function calculateSecurityScore(): int
    {
        $score = 0;
        $total = 0;

        
        $exts = ['openssl', 'sodium'];
        foreach ($exts as $e) {
            $total++;
            if (extension_loaded($e)) $score++;
        }

        
        $ciphers = ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'];
        $availableCiphers = openssl_get_cipher_methods() ?: [];
        foreach ($ciphers as $c) {
            $total++;
            if (in_array($c, $availableCiphers, true)) $score++;
        }

        
        $hashes = ['sha256', 'sha512', 'sha3-512', 'blake2b512'];
        $availableHashes = hash_algos();
        foreach ($hashes as $h) {
            $total++;
            if (in_array($h, $availableHashes, true)) $score++;
        }

        
        $total += 2;
        if (defined('CRYPT_BLOWFISH') && CRYPT_BLOWFISH) $score++;
        if (defined('PASSWORD_ARGON2ID')) $score++;

        if ($total === 0) return 0;
        return (int)round(($score / $total) * 100);
    }

    private function menuSecrets(): void
    {
        while (true) {
            Output::section("Secret Lifecycle Management");
            Output::writeln("1) Generate secure password");
            Output::writeln("2) Generate API token");
            Output::writeln("3) Generate cryptographic salt");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
                case '1':
                    $pwd = bin2hex(random_bytes(16));
                    Output::result('Secure Password', $pwd);
                    $this->logger->log('Generate secure password', 'success');
                    break;
                case '2':
                    $token = base64_encode(random_bytes(32));
                    Output::result('API Token', $token);
                    $this->logger->log('Generate API token', 'success');
                    break;
                case '3':
                    $salt = bin2hex(random_bytes(16));
                    Output::result('Cryptographic Salt', $salt);
                    $this->logger->log('Generate salt', 'success');
                    break;
                default:
                    Output::info('Returning to menu selection');
                    break;
            }
        }
    }

    private function menuEncryptor(): void
    {
        while (true) {
            Output::section("Encryptor");
            Output::writeln("1) View Data_encrypt folder contents");
            Output::writeln("2) Encrypt all files in Data_encrypt folder");
            Output::writeln("3) View Encrypted folder contents");
            Output::writeln("4) Folder statistics");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
                case '1':
                    $this->viewFolderContents('data');
                    break;
                case '2':
                    $this->performFolderEncryption();
                    break;
                case '3':
                    $this->viewFolderContents('encrypted');
                    break;
                case '4':
                    $this->viewFolderStats();
                    break;
                default:
                    Output::info('Returning to menu selection');
                    break;
            }
        }
    }

    private function viewFolderContents(string $type): void
    {
        if ($type === 'data') {
            $files = $this->folderEncrypt->listDataFiles();
            $dir = $this->folderEncrypt->getDataDir();
            $title = "Data Folder Contents";
        } else {
            $files = $this->folderEncrypt->listEncryptedFiles();
            $dir = $this->folderEncrypt->getEncryptedDir();
            $title = "Encrypted Folder Contents";
        }

        Output::section($title);
        Output::writeln("Location: {$dir}\n");

        if (empty($files)) {
            Output::info("Folder is empty");
            return;
        }

        foreach ($files as $file) {
            printf("  %-50s %10s  %s\n", $file['path'], $file['size'], $file['modified']);
        }

        Output::writeln("\nTotal files: " . count($files));
    }

    private function performFolderEncryption(): void
    {
        $dataFiles = $this->folderEncrypt->listDataFiles();
        if (empty($dataFiles)) {
            Output::warning("No files found in Data folder");
            return;
        }

        Output::info("Found " . count($dataFiles) . " file(s) ready to encrypt");
        $password = Input::prompt('Enter encryption password');
        
        Output::writeln("Encrypting...");
        $results = $this->folderEncrypt->encryptAll($password);

        Output::section("Encryption Results");
        Output::success("Successfully encrypted: " . $results['success'] . " file(s)");
        if ($results['failed'] > 0) {
            Output::error("Failed to encrypt: " . $results['failed'] . " file(s)");
        }

        if (!empty($results['errors'])) {
            Output::warning("Errors encountered:");
            foreach ($results['errors'] as $err) {
                Output::writeln("  - {$err}");
            }
        }

        $this->logger->logFolderEncryption($this->folderEncrypt->getDataDir(), $results['success'], $results['failed'] === 0);
    }

    private function performFolderDecryption(): void
    {
        $encFiles = $this->folderEncrypt->listEncryptedFiles();
        if (empty($encFiles)) {
            Output::warning("No encrypted files found");
            return;
        }

        Output::info("Found " . count($encFiles) . " encrypted file(s)");
        $password = Input::prompt('Enter decryption password');
        
        Output::writeln("Decrypting...");
        $results = $this->folderEncrypt->decryptAll($password);

        Output::section("Decryption Results");
        Output::success("Successfully decrypted: " . $results['success'] . " file(s)");
        if ($results['failed'] > 0) {
            Output::error("Failed to decrypt: " . $results['failed'] . " file(s)");
        }

        if (!empty($results['errors'])) {
            Output::warning("Errors encountered:");
            foreach ($results['errors'] as $err) {
                Output::writeln("  - {$err}");
            }
        }

        Output::info("Decrypted files saved to: {$this->folderEncrypt->getDecryptedDir()}");
        $this->logger->logFolderDecryption($this->folderEncrypt->getEncryptedDir(), $results['success'], $results['failed'] === 0);
    }

    private function menuDecryptorManager(): void
    {
        while (true) {
            Output::section("Decryptor Manager");
            Output::writeln("1) View Data_decrypt folder contents");
            Output::writeln("2) Bruteforce");
            Output::writeln("3) Decrypt all files in Data_decrypt");
            Output::writeln("4) View Decrypted folder contents");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
                case '1':
                    $this->viewDataDecryptContents();
                    break;
                case '2':
                    $this->performBruteforce();
                    break;
                case '3':
                    $pw = Input::prompt('Enter password to use for decrypting Data_decrypt files');
                    if (trim($pw) === '') {
                        Output::warning('Empty password, aborting');
                        break;
                    }
                    $res = $this->folderEncrypt->decryptDataDecryptAll($pw);
                    Output::section('Decryption Results');
                    Output::success('Successfully decrypted: ' . $res['success'] . ' file(s)');
                    if ($res['failed'] > 0) {
                        Output::error('Failed to decrypt: ' . $res['failed'] . ' file(s)');
                    }
                    if (!empty($res['errors'])) {
                        Output::warning('Errors encountered:');
                        foreach ($res['errors'] as $err) {
                            Output::writeln('  - ' . $err);
                        }
                    }
                    $this->logger->log('Decrypt Data_decrypt', 'completed');
                    break;
                case '4':
                    $this->viewDecryptedContents();
                    break;
                default:
                    Output::info('Returning to menu selection');
                    break;
            }
        }
    }

    private function performBruteforce(): void
    {
        Output::section("Bruteforce - Data_decrypt");
        $wl = __DIR__ . '/../../storage/wordlist.txt';
        Output::writeln("Using wordlist: storage/wordlist.txt");

        $bf = new Bruteforce();
        $results = $bf->attackDataDecrypt($wl);

        if (empty($results)) {
            Output::info('No passwords found or no files to test');
        } else {
            Output::section('Bruteforce Results');
            foreach ($results as $file => $r) {
                Output::writeln("  - {$file} => found after {$r['attempts']} attempts");
            }
        }

        $this->logger->log('Bruteforce attack', 'completed');
    }

    private function viewDataDecryptContents(): void
    {
        Output::section("Data_decrypt Folder Contents");
        $files = $this->folderEncrypt->getDataDecryptDir();
        Output::writeln("Location: {$files}\n");

        $list = [];
        if (is_dir($files)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($files, \RecursiveDirectoryIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f->isFile()) {
                    $list[] = $f->getPathname();
                }
            }
        }

        if (empty($list)) {
            Output::info('Folder is empty');
            return;
        }

        foreach ($list as $f) {
            Output::writeln('  ' . $f);
        }
    }

    private function viewDecryptedContents(): void
    {
        Output::section("Decrypted Folder Contents");
        $dir = $this->folderEncrypt->getDecryptedDir();
        Output::writeln("Location: {$dir}\n");

        $list = [];
        if (is_dir($dir)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f->isFile()) {
                    $list[] = $f->getPathname();
                }
            }
        }

        if (empty($list)) {
            Output::info('Folder is empty');
            return;
        }

        foreach ($list as $f) {
            Output::writeln('  ' . $f);
        }
    }

    private function viewFolderStats(): void
    {
        Output::section("Folder Encryption Statistics");
        
        $dataSize = $this->folderEncrypt->getDataDirSize();
        $dataFiles = count($this->folderEncrypt->listDataFiles());
        
        $encSize = $this->folderEncrypt->getEncryptedDirSize();
        $encFiles = count($this->folderEncrypt->listEncryptedFiles());
        
        Output::writeln("\nData Folder:");
        Output::writeln("  Files: {$dataFiles}");
        Output::writeln("  Total size: {$dataSize}");
        
        Output::writeln("\nEncrypted Folder:");
        Output::writeln("  Files: {$encFiles}");
        Output::writeln("  Total size: {$encSize}");
        
        if ($dataFiles > 0 && $encFiles > 0) {
            $ratio = ($dataFiles > 0) ? round(($encFiles / $dataFiles) * 100, 2) : 0;
            Output::writeln("\nEncryption status: {$ratio}% complete");
        }
        
        $this->logger->log('View folder statistics', 'success');
    }

    private function menuActivityLog(): void
    {
        while (true) {
            Output::section("Activity Log Management");
            Output::writeln("1) View recent logs (last 20)");
            Output::writeln("2) View all logs");
            Output::writeln("3) Export log as base64");
            Output::writeln("4) Clear logs");
            Output::writeln("5) Log statistics");
            Output::writeln("0) Back");

            $c = Input::prompt('Choice');
            if (trim($c) === '0') return;
            switch ($c) {
                case '1':
                    $this->displayRecentLogs(20);
                    break;
                case '2':
                    $this->displayAllLogs();
                    break;
                case '3':
                    $this->exportLogs();
                    break;
                case '4':
                    $this->clearLogs();
                    break;
                case '5':
                    $this->showLogStats();
                    break;
                default:
                    Output::info('Returning to menu selection');
                    break;
            }
        }
    }

    private function displayRecentLogs(int $count): void
    {
        $entries = $this->logger->getLastEntries($count);
        
        if (empty($entries)) {
            Output::info("No log entries found");
            return;
        }

        Output::section("Recent Activity Logs");
        Output::writeln("");
        
        foreach ($entries as $entry) {
            $time = $entry['timestamp'];
            $status = strtoupper($entry['status']);
            $action = $entry['action'];
            $details = $entry['details'] ? " ({$entry['details']})" : "";
            
            printf("[%s] %-10s %s%s\n", $time, $status, $action, $details);
        }
    }

    private function displayAllLogs(): void
    {
        $entries = $this->logger->getEntries();
        
        if (empty($entries)) {
            Output::info("No log entries found");
            return;
        }

        Output::section("Complete Activity Log");
        Output::writeln("Total entries: " . count($entries) . "\n");
        
        foreach ($entries as $entry) {
            $time = $entry['timestamp'];
            $status = strtoupper($entry['status']);
            $action = $entry['action'];
            $details = $entry['details'] ? " ({$entry['details']})" : "";
            
            printf("[%s] %-10s %s%s\n", $time, $status, $action, $details);
        }
    }

    private function exportLogs(): void
    {
        $exported = $this->logger->export();
        
        Output::section("Log Export (Base64)");
        Output::writeln("");
        Output::result("Encoded Log Data", $exported);
        Output::writeln("\nThis data is base64-encoded and can be stored safely or shared.");
        
        $this->logger->log('Export activity log', 'success');
    }

    private function clearLogs(): void
    {
        $confirm = Input::prompt('Are you sure? This cannot be undone (yes/no)');
        
        if (strtolower(trim($confirm)) === 'yes') {
            $this->logger->clear();
            Output::success('Activity logs cleared');
        } else {
            Output::info('Operation cancelled');
        }
    }

    private function showLogStats(): void
    {
        $count = $this->logger->count();
        $size = $this->logger->getFileSize();

        Output::section("Log Statistics");
        Output::writeln("Total entries: {$count}");
        Output::writeln("Log file size: {$size}");
        Output::writeln("Log status: " . ($count > 0 ? "Active" : "Empty"));

        if ($count > 0) {
            $entries = $this->logger->getEntries();
            $firstEntry = reset($entries);
            $lastEntry = end($entries);

            Output::writeln("First entry: {$firstEntry['timestamp']}");
            Output::writeln("Last entry: {$lastEntry['timestamp']}");
        }
    }

    private function menuInfo(): void
    {
        Output::section("Application Info");
        Output::writeln("Version: 0.3.0");
        Output::writeln("Author: Muh. Agus Tri Ananda");
    }

    private function menuHelp(): void
    {
        Output::section("Help & Documentation");
        Output::writeln("Bahll - Educational Cryptography Toolkit v0.3.0");
        Output::writeln("");
        Output::writeln("━━━ CORE MODULES ━━━");
        Output::writeln("");
        Output::writeln("  1) HASHING & KEY DERIVATION");
        Output::writeln("     Cryptographic hash functions (SHA-1, SHA-256, SHA-512, SHA3-512)");
        Output::writeln("     BLAKE2/BLAKE3 support, HMAC, PBKDF2, bcrypt, scrypt, Argon2id");
        Output::writeln("");
        Output::writeln("  2) SYMMETRIC ENCRYPTION");
        Output::writeln("     AES-256-GCM (AEAD, authenticated encryption)");
        Output::writeln("     AES-256-CBC with HMAC for authenticated encryption");
        Output::writeln("     ChaCha20-Poly1305 support (libsodium)");
        Output::writeln("");
        Output::writeln("  3) ASYMMETRIC CRYPTOGRAPHY");
        Output::writeln("     RSA keypair generation (2048, 3072, 4096 bit)");
        Output::writeln("     Ed25519 signatures (modern elliptic curve)");
        Output::writeln("     Sign/verify operations with base64 output");
        Output::writeln("");
        Output::writeln("  4) KEYRING MANAGEMENT");
        Output::writeln("     Encrypted key storage with XChaCha20-Poly1305");
        Output::writeln("     Initialize, add, list, export, and remove keys");
        Output::writeln("     Passphrase-protected access control");
        Output::writeln("");
        Output::writeln("  5) ENCODING & OBFUSCATION");
        Output::writeln("     Base64 encoding (standard and URL-safe)");
        Output::writeln("     Hexadecimal encoding/decoding");
        Output::writeln("");
        Output::writeln("  6) RANDOMNESS & ENTROPY");
        Output::writeln("     Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)");
        Output::writeln("     Generate random bytes in configurable sizes");
        Output::writeln("");
        Output::writeln("  7) SECURITY AUDIT");
        Output::writeln("     System capability assessment");
        Output::writeln("     Cipher support detection, hash algorithm availability");
        Output::writeln("     Security score calculation and recommendations");
        Output::writeln("");
        Output::writeln("  8) SECRET LIFECYCLE");
        Output::writeln("     Generate secure passwords, API tokens, and cryptographic salts");
        Output::writeln("");
        Output::writeln("  9) ENCRYPTOR MANAGER");
        Output::writeln("     Batch encrypt files/folders recursively");
        Output::writeln("     Preserves directory structure with .enc suffix");
        Output::writeln("");
        Output::writeln("  10) DECRYPTOR MANAGER");
        Output::writeln("      Password-based decryption with single password");
        Output::writeln("      Wordlist-based brute-force attack (~500 common passwords)");
        Output::writeln("      Automatic password discovery and bulk decryption");
        Output::writeln("");
        Output::writeln("  11) ACTIVITY LOG");
        Output::writeln("      Real-time security event tracking");
        Output::writeln("      Export logs, view statistics, audit trails");
        Output::writeln("");
        Output::writeln("━━━ QUICK REFERENCE ━━━");
        Output::writeln("");
        Output::writeln("  h) Help - Show this detailed help message");
        Output::writeln("  i) Info - Show version and author information");
        Output::writeln("  q) Exit - Quit Bahll");
        Output::writeln("");
        Output::writeln("━━━ NAVIGATION TIPS ━━━");
        Output::writeln("");
        Output::writeln("  • Type 0 (Back) in any submenu to return to main menu");
        Output::writeln("  • Type 'clear' to clear terminal screen");
        Output::writeln("  • All cryptographic operations are logged for audit trails");
        Output::writeln("  • Passwords are never stored; only hashes are kept");
        Output::writeln("");
        Output::writeln("━━━ EXAMPLES ━━━");
        Output::writeln("");
        Output::writeln("  Hash a message with SHA-256:");
        Output::writeln("    [1] → [2] → enter message → get SHA-256 hash");
        Output::writeln("");
        Output::writeln("  Encrypt a file with password:");
        Output::writeln("    [9] → place file in storage/Data_encrypt → [2] → enter password");
        Output::writeln("");
        Output::writeln("  Brute-force decrypt a file:");
        Output::writeln("    [10] → place encrypted file in storage/Data_decrypt → [2] (Bruteforce)");
        Output::writeln("");
        Output::writeln("For more information, visit: https://github.com/yourusername/bahll");
    }
}
