<?php
namespace Bahll\Core\Crypto;

use Bahll\CLI\Output;

class Bruteforce
{
    private FolderEncrypt $folder;

    public function __construct()
    {
        $this->folder = new FolderEncrypt();
    }

    
    public function attackDataDecrypt(string $wordlistPath): array
    {
        $results = [];

        $dir = $this->folder->getDataDecryptDir();
        if (!is_dir($dir)) {
            return $results;
        }

        $files = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile()) {
                $files[] = $f->getPathname();
            }
        }

        if (empty($files)) {
            return $results;
        }

        if (!is_file($wordlistPath)) {
            return $results;
        }

        $wordlist = file($wordlistPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($wordlist === false || empty($wordlist)) {
            return $results;
        }

        foreach ($files as $file) {
            $encrypted = file_get_contents($file);
            if ($encrypted === false) continue;

            $encrypted = trim($encrypted);
            $found = false;
            $attempts = 0;

            foreach ($wordlist as $pw) {
                $attempts++;
                $decrypted = Symmetric::decryptAesCbcWithHmac($encrypted, $pw);
                if ($decrypted === false) {
                    $decrypted = Symmetric::decryptAesGcm($encrypted, $pw);
                }
                if ($decrypted !== false) {
                    $results[basename($file)] = ['password' => $pw, 'attempts' => $attempts];
                    Output::success("Password found for " . basename($file) . ": {$pw}");
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                Output::warning("No password found for " . basename($file));
            }
        }

        
        $outPath = __DIR__ . '/../../storage/bruteforce_results.json';
        @file_put_contents($outPath, json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return $results;
    }
}
