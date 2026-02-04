<?php
namespace Bahll\Core\Crypto;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class FolderEncrypt
{
    private string $dataDir;
    private string $encryptedDir;

    public function __construct()
    {
        $base = __DIR__ . '/../../storage';
        if (!is_dir($base)) {
            @mkdir($base, 0700, true);
        }

        $this->dataDir = $base . '/Data';
        $this->encryptedDir = $base . '/Encrypted';

        if (!is_dir($this->dataDir)) {
            @mkdir($this->dataDir, 0700, true);
        }
        if (!is_dir($this->encryptedDir)) {
            @mkdir($this->encryptedDir, 0700, true);
        }
    }

    
    public function getDataDir(): string
    {
        return $this->dataDir;
    }

    
    public function getEncryptedDir(): string
    {
        return $this->encryptedDir;
    }

    
    public function encryptAll(string $password): array
    {
        $results = [
            'success' => 0,
            'failed' => 0,
            'errors' => [],
            'encrypted_files' => []
        ];

        if (!is_dir($this->dataDir) || count(glob($this->dataDir . '/*')) === 0) {
            $results['errors'][] = 'Data directory is empty';
            return $results;
        }

        
        $this->clearDirectory($this->encryptedDir);

        try {
            
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($this->dataDir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    if ($this->encryptFile($item->getPathname(), $password)) {
                        $results['success']++;
                        $relative = str_replace($this->dataDir . DIRECTORY_SEPARATOR, '', $item->getPathname());
                        $results['encrypted_files'][] = $relative;
                    } else {
                        $results['failed']++;
                        $relative = str_replace($this->dataDir . DIRECTORY_SEPARATOR, '', $item->getPathname());
                        $results['errors'][] = 'Failed to encrypt: ' . $relative;
                    }
                } elseif ($item->isDir()) {
                    $this->createEncryptedDirStructure($item->getPathname());
                }
            }
        } catch (\Exception $e) {
            $results['errors'][] = 'Exception: ' . $e->getMessage();
        }

        return $results;
    }

    
    public function encryptFile(string $filePath, string $password): bool
    {
        if (!file_exists($filePath) || !is_file($filePath)) {
            return false;
        }

        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return false;
            }

            $encrypted = Symmetric::encryptAesCbcWithHmac($content, $password);
            if ($encrypted === false || strpos($encrypted, '✖') === 0) {
                return false;
            }

            $relativePath = str_replace($this->dataDir . DIRECTORY_SEPARATOR, '', $filePath);
            $encryptedPath = $this->encryptedDir . DIRECTORY_SEPARATOR . $relativePath . '.enc';

            $dir = dirname($encryptedPath);
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }

            $result = file_put_contents($encryptedPath, $encrypted);
            if ($result === false) {
                return false;
            }

            @chmod($encryptedPath, 0600);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    
    public function decryptAll(string $password): array
    {
        $results = [
            'success' => 0,
            'failed' => 0,
            'errors' => [],
            'decrypted_files' => []
        ];

        if (!is_dir($this->encryptedDir) || count(glob($this->encryptedDir . '/*')) === 0) {
            $results['errors'][] = 'Encrypted directory is empty';
            return $results;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($this->encryptedDir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            $decryptDir = $this->dataDir . '_decrypted';
            if (!is_dir($decryptDir)) {
                @mkdir($decryptDir, 0700, true);
            }

            foreach ($iterator as $item) {
                if ($item->isFile() && $item->getExtension() === 'enc') {
                    $relativePath = str_replace($this->encryptedDir . DIRECTORY_SEPARATOR, '', $item->getPathname());
                    $relativePath = substr($relativePath, 0, -4); 

                    if ($this->decryptFile($item->getPathname(), $decryptDir . DIRECTORY_SEPARATOR . $relativePath, $password)) {
                        $results['success']++;
                        $results['decrypted_files'][] = $relativePath;
                    } else {
                        $results['failed']++;
                        $results['errors'][] = 'Failed to decrypt: ' . $relativePath;
                    }
                }
            }
        } catch (\Exception $e) {
            $results['errors'][] = 'Exception: ' . $e->getMessage();
        }

        return $results;
    }

    
    public function decryptFile(string $encryptedPath, string $outputPath, string $password): bool
    {
        if (!file_exists($encryptedPath) || !is_file($encryptedPath)) {
            return false;
        }

        try {
            $encrypted = file_get_contents($encryptedPath);
            if ($encrypted === false) {
                return false;
            }

            $decrypted = Symmetric::decryptAesCbcWithHmac($encrypted, $password);
            if ($decrypted === false) {
                return false;
            }

            $dir = dirname($outputPath);
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }

            $result = file_put_contents($outputPath, $decrypted);
            if ($result === false) {
                return false;
            }

            @chmod($outputPath, 0600);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    
    private function createEncryptedDirStructure(string $dirPath): void
    {
        $relativePath = str_replace($this->dataDir . DIRECTORY_SEPARATOR, '', $dirPath);
        $encryptedPath = $this->encryptedDir . DIRECTORY_SEPARATOR . $relativePath;

        if (!is_dir($encryptedPath)) {
            @mkdir($encryptedPath, 0700, true);
        }
    }

    
    private function clearDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }
    }

    
    public function listDataFiles(): array
    {
        $files = [];

        if (!is_dir($this->dataDir)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->dataDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isFile()) {
                $relative = str_replace($this->dataDir . DIRECTORY_SEPARATOR, '', $item->getPathname());
                $files[] = [
                    'path' => $relative,
                    'size' => $this->formatBytes($item->getSize()),
                    'modified' => date('Y-m-d H:i:s', $item->getMTime())
                ];
            }
        }

        return $files;
    }

    
    public function listEncryptedFiles(): array
    {
        $files = [];

        if (!is_dir($this->encryptedDir)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->encryptedDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isFile() && $item->getExtension() === 'enc') {
                $relative = str_replace($this->encryptedDir . DIRECTORY_SEPARATOR, '', $item->getPathname());
                $files[] = [
                    'path' => $relative,
                    'size' => $this->formatBytes($item->getSize()),
                    'modified' => date('Y-m-d H:i:s', $item->getMTime())
                ];
            }
        }

        return $files;
    }

    
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= (1 << (10 * $pow));

        return round($bytes, 2) . ' ' . $units[$pow];
    }

    
    public function getDataDirSize(): string
    {
        return $this->formatBytes($this->calculateDirSize($this->dataDir));
    }

    
    public function getEncryptedDirSize(): string
    {
        return $this->formatBytes($this->calculateDirSize($this->encryptedDir));
    }

    
    private function calculateDirSize(string $dir): int
    {
        $size = 0;

        if (!is_dir($dir)) {
            return $size;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isFile()) {
                $size += $item->getSize();
            }
        }

        return $size;
    }
}
