<?php
namespace Bahll\Core\Crypto;

class Hash
{
    public static function sha1(string $data): string
    {
        fwrite(STDERR, "Warning: SHA-1 is deprecated and insecure\n");
        return hash('sha1', $data);
    }

    public static function sha256(string $data): string
    {
        return hash('sha256', $data);
    }

    public static function sha512(string $data): string
    {
        return hash('sha512', $data);
    }

    public static function sha3(string $data): string
    {
        $algo = 'sha3-512';
        if (!in_array($algo, hash_algos())) {
            return "✖ SHA3 not available on this PHP build";
        }
        return hash($algo, $data);
    }

    public static function blake2(string $data): string
    {
        if (in_array('blake2b512', hash_algos())) {
            return hash('blake2b512', $data);
        }
        return '✖ BLAKE2 not available';
    }

    public static function blake3(string $data): string
    {
        return '✖ BLAKE3 not supported by PHP builtins; use external tool or extension';
    }

    public static function hmac(string $algo, string $data, string $key): string
    {
        return hash_hmac($algo, $data, $key);
    }

    public static function pbkdf2(string $password, ?string $salt = null, int $iters = 100000, int $len = 64): string
    {
        $salt = $salt ?: bin2hex(random_bytes(16));
        return hash_pbkdf2('sha256', $password, $salt, $iters, $len);
    }

    public static function bcrypt(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public static function scrypt(string $password): string
    {
        return '✖ scrypt not available in core PHP; use libsodium or external binary';
    }

    public static function argon2id(string $password): string
    {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_hash($password, PASSWORD_ARGON2ID);
        }
        return '✖ Argon2id not available on this PHP build';
    }
}
