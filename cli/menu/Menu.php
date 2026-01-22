<?php
namespace Bahll\CLI;

use Bahll\CLI\Input;
use Bahll\CLI\Output;
use Bahll\Core\Crypto\Hash;
use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Keyring\Keyring;

class Menu
{
    public function run(): void
    {
        $this->clearScreen();
        Output::banner();
        $keyring = new Keyring();

        while (true) {
            Output::writeln("\nMain Menu:");
            Output::writeln("1) Hashing & KDF");
            Output::writeln("2) Symmetric Encryption");
            Output::writeln("3) Asymmetric Crypto");
            Output::writeln("4) Keyring / Key Management");
            Output::writeln("5) Encoding / Obfuscation");
            Output::writeln("6) Randomness & Entropy");
            Output::writeln("7) Audit & Validation");
            Output::writeln("8) Secret Lifecycle");
            Output::writeln("9) Dev & CI Utilities");
            Output::writeln("10) Plugins");
            Output::writeln("0) Exit");

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
                    Output::writeln("Dev & CI utilities are available in the CLI.");
                    break;
                case '10':
                    Output::writeln("Plugins folder: scan available in plugins/ (safe load skeleton)");
                    break;
                case '0':
                    Output::writeln("Bye.");
                    exit(0);
                default:
                    Output::writeln("Invalid selection, try again.");
            }
        }
    }

    private function clearScreen(): void
    {
        if (DIRECTORY_SEPARATOR === '/') {
            echo "\033[2J\033[H";
        } else {
            @system("cls");
        }
    }

    private function menuHash(): void
    {
        Output::writeln("\nHashing & KDF Menu:");
        Output::writeln("1) SHA-1 (deprecated)");
        Output::writeln("2) SHA-256");
        Output::writeln("3) SHA-512");
        Output::writeln("4) SHA3-512");
        Output::writeln("5) BLAKE2");
        Output::writeln("6) BLAKE3 (if supported)");
        Output::writeln("7) HMAC");
        Output::writeln("8) PBKDF2");
        Output::writeln("9) bcrypt");
        Output::writeln("10) scrypt");
        Output::writeln("11) Argon2id");
        Output::writeln("0) Back");

        $c = Input::prompt('Choice');
        switch ($c) {
            case '1':
                $d = Input::prompt('Data to hash');
                Output::writeln(Hash::sha1($d));
                break;
            case '2':
                $d = Input::prompt('Data to hash');
                Output::writeln(Hash::sha256($d));
                break;
            case '3':
                $d = Input::prompt('Data to hash');
                Output::writeln(Hash::sha512($d));
                break;
            case '4':
                $d = Input::prompt('Data to hash');
                Output::writeln(Hash::sha3($d));
                break;
            case '5':
                $d = Input::prompt('Data to hash');
                Output::writeln(Hash::blake2($d));
                break;
            case '6':
                Output::writeln(Hash::blake3(''));
                break;
            case '7':
                $d = Input::prompt('Data');
                $k = Input::prompt('Key');
                Output::writeln(Hash::hmac('sha256', $d, $k));
                break;
            case '8':
                $p = Input::prompt('Password');
                $s = Input::prompt('Salt (leave blank to auto)');
                $iter = (int)Input::prompt('Iterations (e.g. 100000)');
                Output::writeln(Hash::pbkdf2($p, $s ?: null, $iter ?: 100000));
                break;
            case '9':
                $p = Input::prompt('Password');
                Output::writeln(Hash::bcrypt($p));
                break;
            case '10':
                Output::writeln(Hash::scrypt('')); 
                break;
            case '11':
                $p = Input::prompt('Password');
                Output::writeln(Hash::argon2id($p));
                break;
            default:
                return;
        }
    }

    private function menuSymmetric(): void
    {
        Output::writeln("\nSymmetric Menu:");
        Output::writeln("1) AES-256-GCM encrypt string");
        Output::writeln("2) AES-256-GCM decrypt string");
        Output::writeln("3) AES-CBC (with MAC)");
        Output::writeln("4) ChaCha20-Poly1305 (if available)");
        Output::writeln("0) Back");

        $c = Input::prompt('Choice');
        switch ($c) {
            case '1':
                $pt = Input::prompt('Plaintext');
                $pw = Input::prompt('Password (leave blank to use random key)');
                $res = Symmetric::encryptAesGcm($pt, $pw ?: null);
                Output::writeln($res);
                break;
            case '2':
                $blob = Input::prompt('Cipher blob (json)');
                $pw = Input::prompt('Password (if used)');
                $out = Symmetric::decryptAesGcm($blob, $pw ?: null);
                Output::writeln($out === false ? '✖ Decryption failed' : $out);
                break;
            default:
                return;
        }
    }

    private function menuAsymmetric(): void
    {
        Output::writeln("\nAsymmetric Menu:");
        Output::writeln("1) Generate RSA keypair");
        Output::writeln("2) Generate Ed25519 keypair");
        Output::writeln("3) Sign/Verify using Ed25519");
        Output::writeln("0) Back");

        $c = Input::prompt('Choice');
        switch ($c) {
            case '1':
                $bits = (int)Input::prompt('Key size (2048/3072/4096)');
                $p = Input::prompt('Passphrase (optional)');
                $kp = Asymmetric::generateRsa($bits ?: 2048, $p ?: null);
                Output::writeln(json_encode($kp, JSON_PRETTY_PRINT));
                break;
            case '2':
                $kp = Asymmetric::generateEd25519();
                Output::writeln(json_encode($kp, JSON_PRETTY_PRINT));
                break;
            case '3':
                $action = Input::prompt('sign/verify');
                if (trim($action) === 'sign') {
                    $sk = Input::prompt('Private key (hex/base64)');
                    $msg = Input::prompt('Message');
                    $sig = Asymmetric::signEd25519($sk, $msg);
                    Output::writeln(base64_encode($sig));
                } else {
                    $pk = Input::prompt('Public key (hex/base64)');
                    $msg = Input::prompt('Message');
                    $sig = base64_decode(Input::prompt('Signature (base64)'));
                    $ok = Asymmetric::verifyEd25519($pk, $msg, $sig);
                    Output::writeln($ok ? 'Signature VALID' : 'Signature INVALID');
                }
                break;
            default:
                return;
        }
    }

    private function menuKeyring(Keyring $k): void
    {
        Output::writeln("\nKeyring Menu:");
        Output::writeln("1) Initialize keyring");
        Output::writeln("2) Add key");
        Output::writeln("3) List keys");
        Output::writeln("4) Export key");
        Output::writeln("0) Back");

        $c = Input::prompt('Choice');
        switch ($c) {
            case '1':
                $pw = Input::prompt('Set passphrase for keyring');
                $k->init($pw);
                Output::writeln('Keyring initialized');
                break;
            case '2':
                $alias = Input::prompt('Alias');
                $data = Input::prompt('Key data (PEM/json/base64)');
                $pw = Input::prompt('Keyring passphrase');
                $k->addKey($alias, $data, $pw);
                Output::writeln('Key added');
                break;
            case '3':
                $pw = Input::prompt('Keyring passphrase');
                $list = $k->listKeys($pw);
                Output::writeln(json_encode($list, JSON_PRETTY_PRINT));
                break;
            case '4':
                $alias = Input::prompt('Alias');
                $pw = Input::prompt('Keyring passphrase');
                $out = $k->exportKey($alias, $pw);
                Output::writeln($out === false ? '✖ Not found or bad passphrase' : $out);
                break;
            default:
                return;
        }
    }

    private function menuEncoding(): void
    {
        Output::writeln('\nEncoding Menu: base64, base32, base58, hex');
        $d = Input::prompt('Data');
        if ($d === null) return;
        Output::writeln('Base64: ' . base64_encode($d));
        Output::writeln('URL-safe Base64: ' . rtrim(strtr(base64_encode($d), '+/', '-_'), '='));
        Output::writeln('Hex: ' . bin2hex($d));
    }

    private function menuRandom(): void
    {
        Output::writeln('\nRandomness:');
        $n = (int)Input::prompt('Bytes to generate (default 32)');
        $n = $n > 0 ? $n : 32;
        $tok = random_bytes($n);
        Output::writeln('CSPRNG (hex): ' . bin2hex($tok));
        Output::writeln('Password (secure): ' . bin2hex(random_bytes(16)));
    }

    private function menuAudit(): void
    {
        Output::writeln('\nAudit: basic checks');
        Output::writeln('\n- Checking OpenSSL ciphers and sodium availability');
        Output::writeln('OpenSSL: ' . (extension_loaded('openssl') ? 'available' : 'missing'));
        Output::writeln('Sodium: ' . (extension_loaded('sodium') ? 'available' : 'missing'));
        Output::writeln('Advice: avoid SHA-1, prefer AEAD ciphers, RSA >= 2048');

        Output::writeln('\n- Cipher availability:');
        $ciphers = ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'];
        foreach ($ciphers as $c) {
            $avail = in_array($c, openssl_get_cipher_methods() ?? []) || function_exists('sodium_crypto_aead_chacha20poly1305_encrypt');
            Output::writeln("  $c: " . ($avail ? 'available' : 'missing'));
        }

        Output::writeln('\n- Hash algorithms:');
        $hashes = ['sha256', 'sha3-512', 'blake2b512'];
        foreach ($hashes as $h) {
            Output::writeln("  $h: " . (in_array($h, hash_algos()) ? 'available' : 'missing'));
        }

        Output::writeln('\n- Security score: ' . $this->calculateSecurityScore());
    }

    private function calculateSecurityScore(): string
    {
        $score = 0;
        $max = 10;
        if (extension_loaded('openssl')) $score += 3;
        if (extension_loaded('sodium')) $score += 3;
        if (in_array('aes-256-gcm', openssl_get_cipher_methods() ?? [])) $score += 2;
        if (defined('PASSWORD_ARGON2ID')) $score += 2;
        return "$score/$max (higher is better)";
    }

    private function menuSecrets(): void
    {
        Output::writeln('\nSecrets lifecycle helpers');
        Output::writeln('Detecting secrets is available via scanning (not implemented full scan).');
    }
}
