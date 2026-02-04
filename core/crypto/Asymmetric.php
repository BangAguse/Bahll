<?php
namespace Bahll\Core\Crypto;

class Asymmetric
{
    public static function generateRsa(int $bits = 2048, ?string $passphrase = null): array
    {
        if ($bits < 2048) {
            fwrite(STDERR, "✖ Rejected by Bahll: Weak cryptographic configuration detected (RSA < 2048)\n");
            return ['error' => 'RSA size too small'];
        }
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $priv, $passphrase);
        $pub = openssl_pkey_get_details($res)['key'];
        return ['private' => $priv, 'public' => $pub];
    }

    public static function generateEd25519(): array
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            return ['error' => 'libsodium not available'];
        }
        [$pk, $sk] = sodium_crypto_sign_keypair();
        return ['private_hex' => bin2hex($sk), 'public_hex' => bin2hex($pk)];
    }

    public static function signEd25519(string $secretHex, string $message): string
    {
        $sk = hex2bin($secretHex);
        if ($sk === false) return '';
        return sodium_crypto_sign_detached($message, $sk);
    }

    public static function verifyEd25519(string $public, string $message, string $signature): bool
    {
        $pk = hex2bin($public);
        if ($pk === false) return false;
        return sodium_crypto_sign_verify_detached($signature, $message, $pk);
    }
}
