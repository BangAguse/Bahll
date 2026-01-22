<?php
namespace Bahll\Utils;

class Utils
{
    public static function constantTimeEquals(string $a, string $b): bool
    {
        if (function_exists('hash_equals')) return hash_equals($a, $b);
        if (strlen($a) !== strlen($b)) return false;
        $res = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $res |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $res === 0;
    }
}
