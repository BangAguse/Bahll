<?php
namespace Bahll\Core\Keyring;

use Bahll\Utils\Utils;

class Keyring
{
    private string $path;
    private string $saltPath;

    public function __construct()
    {
        $base = __DIR__ . '/../../storage';
        if (!is_dir($base)) @mkdir($base, 0700, true);
        $this->path = $base . '/keyring.json.enc';
        $this->saltPath = $base . '/keyring.salt';
    }

    public function init(string $passphrase): bool
    {
        
        $nonce = random_bytes(24);
        file_put_contents($this->saltPath, $nonce);
        $data = ['keys' => []];
        return $this->writeEncrypted(json_encode($data), $passphrase);
    }

    public function addKey(string $alias, string $data, string $passphrase): bool
    {
        $decoded = $this->readAll($passphrase);
        if ($decoded === false) return false;
        $decoded['keys'][$alias] = ['data' => $data, 'added' => time()];
        return $this->writeEncrypted(json_encode($decoded), $passphrase);
    }

    public function listKeys(string $passphrase)
    {
        $decoded = $this->readAll($passphrase);
        if ($decoded === false) return [];
        $out = [];
        foreach ($decoded['keys'] ?? [] as $k => $v) {
            $out[$k] = ['added' => $v['added'] ?? 0];
        }
        return $out;
    }

    public function exportKey(string $alias, string $passphrase)
    {
        $decoded = $this->readAll($passphrase);
        if ($decoded === false) return false;
        return $decoded['keys'][$alias]['data'] ?? false;
    }

    private function readAll(string $passphrase)
    {
        if (!file_exists($this->path)) return ['keys' => []];
        $ct = file_get_contents($this->path);
        if ($ct === false) return false;
        
        
        $nonce = file_exists($this->saltPath) ? file_get_contents($this->saltPath) : random_bytes(24);
        if ($nonce === false || strlen($nonce) !== 24) {
            $nonce = random_bytes(24);
            @file_put_contents($this->saltPath, $nonce);
        }
        
        $key = sodium_crypto_pwhash(
            32,
            $passphrase,
            $nonce,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        
        $raw = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(base64_decode($ct), '', $nonce, $key);
        if ($raw === false) return false;
        return json_decode($raw, true);
    }

    private function writeEncrypted(string $plaintext, string $passphrase): bool
    {
        
        $nonce = file_get_contents($this->saltPath) ?: random_bytes(24);
        if (strlen($nonce) !== 24) {
            $nonce = random_bytes(24);
            file_put_contents($this->saltPath, $nonce);
        }
        
        $key = sodium_crypto_pwhash(
            32,
            $passphrase,
            $nonce,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);
        file_put_contents($this->path, base64_encode($ct));
        return true;
    }
}
