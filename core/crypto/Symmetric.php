<?php
namespace Bahll\Core\Crypto;

use Bahll\Utils\Utils;

class Symmetric
{
    public static function encryptAesGcm(string $plaintext, ?string $password = null): string
    {
        if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            return '✖ AES-256-GCM not available in OpenSSL on this system';
        }
        $key = $password ? hash('sha256', $password, true) : random_bytes(32);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) return '✖ Encryption failed';
        $out = base64_encode(json_encode([
            'cipher' => 'aes-256-gcm',
            'iv' => bin2hex($iv),
            'tag' => bin2hex($tag),
            'keyed' => $password ? true : false,
            'ct' => base64_encode($ciphertext),
        ]));
        return $out;
    }

    public static function decryptAesGcm(string $blob, ?string $password = null)
    {
        $json = json_decode(base64_decode($blob), true);
        if (!$json) return false;
        if ($json['cipher'] !== 'aes-256-gcm') return false;
        if (!isset($json['iv']) || !isset($json['tag']) || !isset($json['ct'])) return false;
        
        $iv = hex2bin($json['iv']);
        $tag = hex2bin($json['tag']);
        $keyed = $json['keyed'] ?? false;
        
        
        if ($keyed && !$password) return false;
        
        if (!$keyed) return false;
        
        $key = hash('sha256', $password, true);
        $ct = base64_decode($json['ct']);
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $pt === false ? false : $pt;
    }

    public static function encryptAesCbcWithHmac(string $plaintext, string $password): string
    {
        $key = hash('sha256', $password, true);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $mac = hash_hmac('sha256', $ciphertext, $key, true);
        return base64_encode(json_encode([
            'cipher' => 'aes-256-cbc', 'iv' => bin2hex($iv), 'ct' => base64_encode($ciphertext), 'mac' => bin2hex($mac)
        ]));
    }

    public static function decryptAesCbcWithHmac(string $blob, string $password)
    {
        $json = json_decode(base64_decode($blob), true);
        if (!$json) return false;
        if (!isset($json['iv']) || !isset($json['ct']) || !isset($json['mac'])) return false;
        
        $key = hash('sha256', $password, true);
        $ct = base64_decode($json['ct']);
        $mac = hex2bin($json['mac']);
        $calc = hash_hmac('sha256', $ct, $key, true);
        
        if (!Utils::constantTimeEquals($mac, $calc)) {
            fwrite(STDERR, "✖ Rejected by Bahll: Weak cryptographic configuration detected (MAC mismatch)\n");
            return false;
        }
        
        $iv = hex2bin($json['iv']);
        $pt = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return $pt === false ? false : $pt;
    }
}
