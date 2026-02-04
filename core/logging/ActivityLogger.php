<?php
namespace Bahll\Core\Logging;

class ActivityLogger
{
    private string $logFile;
    private array $entries = [];

    public function __construct()
    {
        $logDir = __DIR__ . '/../../storage';
        if (!is_dir($logDir)) {
            @mkdir($logDir, 0700, true);
        }
        $this->logFile = $logDir . '/activity.log';
        $this->loadExistingLog();
    }

    private function loadExistingLog(): void
    {
        if (file_exists($this->logFile)) {
            $content = file_get_contents($this->logFile);
            if ($content !== false && !empty($content)) {
                try {
                    $decoded = base64_decode($content, true);
                    if ($decoded !== false) {
                        $json = json_decode($decoded, true);
                        if (is_array($json)) {
                            $this->entries = $json;
                        }
                    }
                } catch (\Exception $e) {
                    
                }
            }
        }
    }

    
    public function log(string $action, string $status = 'success', ?string $details = null): void
    {
        $entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'unix_time' => time(),
            'action' => $this->sanitize($action),
            'status' => $status,
            'details' => $details ? $this->sanitize($details) : null
        ];

        $this->entries[] = $entry;
        $this->save();
    }

    
    public function logHash(string $algorithm, string $status = 'success'): void
    {
        $this->log("Hash operation - {$algorithm}", $status);
    }

    
    public function logEncryption(string $cipher, bool $success = true, ?string $mode = null): void
    {
        $status = $success ? 'success' : 'failed';
        $action = $mode ? "Encrypt {$cipher} ({$mode})" : "Encrypt {$cipher}";
        $this->log($action, $status);
    }

    
    public function logDecryption(string $cipher, bool $success = true, ?string $reason = null): void
    {
        $status = $success ? 'success' : 'failed';
        $action = "Decrypt {$cipher}";
        $details = $success ? null : "Reason: " . $this->sanitize($reason ?? 'Unknown');
        $this->log($action, $status, $details);
    }

    
    public function logKeyGeneration(string $keyType, int $size = 0): void
    {
        $action = $size > 0 ? "Generate {$keyType} ({$size} bits)" : "Generate {$keyType}";
        $this->log($action, 'success');
    }

    
    public function logFolderEncryption(string $folderPath, int $fileCount = 0, bool $success = true): void
    {
        $status = $success ? 'success' : 'failed';
        $folderName = basename($folderPath);
        $details = $fileCount > 0 ? "Encrypted {$fileCount} file(s)" : null;
        $this->log("Encrypt folder - {$folderName}", $status, $details);
    }

    
    public function logFolderDecryption(string $folderPath, int $fileCount = 0, bool $success = true): void
    {
        $status = $success ? 'success' : 'failed';
        $folderName = basename($folderPath);
        $details = $fileCount > 0 ? "Decrypted {$fileCount} file(s)" : null;
        $this->log("Decrypt folder - {$folderName}", $status, $details);
    }

    
    private function sanitize(string $data): string
    {
        
        $patterns = [
            '/password["\']?\s*[=:]\s*["\']?[^\s"\']+/i',
            '/key["\']?\s*[=:]\s*["\']?[^\s"\']+/i',
            '/secret["\']?\s*[=:]\s*["\']?[^\s"\']+/i',
            '/token["\']?\s*[=:]\s*["\']?[^\s"\']+/i',
            '/\b[0-9a-f]{40,}\b/i', 
            '/\b[A-Za-z0-9+\/]{64,}={0,2}\b/', 
        ];

        $sanitized = $data;
        foreach ($patterns as $pattern) {
            $sanitized = preg_replace($pattern, '[REDACTED]', $sanitized);
        }

        
        return preg_replace('/[^\w\s\-\.:,\[\]()\/]/', '', $sanitized);
    }

    
    public function getEntries(): array
    {
        return $this->entries;
    }

    
    public function format(): string
    {
        $output = "Activity Log\n";
        $output .= str_repeat("=", 80) . "\n\n";

        foreach ($this->entries as $entry) {
            $output .= "[{$entry['timestamp']}] ";
            $output .= strtoupper($entry['status']) . " ";
            $output .= "- {$entry['action']}";
            if ($entry['details']) {
                $output .= " ({$entry['details']})";
            }
            $output .= "\n";
        }

        $output .= "\n" . str_repeat("=", 80) . "\n";
        $output .= "Total entries: " . count($this->entries) . "\n";

        return $output;
    }

    
    public function getLastEntries(int $count = 10): array
    {
        return array_slice($this->entries, -$count);
    }

    
    public function export(): string
    {
        $json = json_encode($this->entries);
        return base64_encode($json);
    }

    
    public function clear(): void
    {
        $this->entries = [];
        $this->save();
    }

    
    private function save(): void
    {
        $json = json_encode($this->entries);
        $encoded = base64_encode($json);
        file_put_contents($this->logFile, $encoded);
        @chmod($this->logFile, 0600);
    }

    
    public function getFileSize(): string
    {
        if (!file_exists($this->logFile)) {
            return '0 bytes';
        }

        $bytes = filesize($this->logFile);
        if ($bytes < 1024) {
            return $bytes . ' bytes';
        } elseif ($bytes < 1048576) {
            return round($bytes / 1024, 2) . ' KB';
        } else {
            return round($bytes / 1048576, 2) . ' MB';
        }
    }

    
    public function count(): int
    {
        return count($this->entries);
    }
}
