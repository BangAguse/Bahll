<?php
declare(strict_types=1);

namespace Bahll\Api\Database;

use PDO;
use PDOException;

class Database
{
    private static ?PDO $connection = null;
    private string $dbPath;

    public function __construct(string $dbPath)
    {
        $this->dbPath = $dbPath;
    }

    public function connect(): PDO
    {
        if (self::$connection === null) {
            try {
                // Ensure directory exists
                $dir = dirname($this->dbPath);
                if (!is_dir($dir)) {
                    mkdir($dir, 0755, true);
                }

                self::$connection = new PDO(
                    'sqlite:' . $this->dbPath,
                    null,
                    null,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_TIMEOUT => 30,
                    ]
                );

                // Enable foreign keys
                self::$connection->exec('PRAGMA foreign_keys = ON');
            } catch (PDOException $e) {
                throw new \Exception('Database connection failed: ' . $e->getMessage());
            }
        }

        return self::$connection;
    }

    public function initialize(): void
    {
        $pdo = $this->connect();

        // Create API Keys table
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        ');

        // Create Audit Log table
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER,
                operation TEXT NOT NULL,
                status TEXT DEFAULT "success",
                input_summary TEXT,
                error_message TEXT,
                execution_time REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
            )
        ');

        // Create Rate Limit table
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER,
                request_count INTEGER DEFAULT 1,
                window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(api_key_id, window_start),
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
            )
        ');

        // Create indexes
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_logs_api_key_id ON audit_logs(api_key_id)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_rate_limits_api_key_id ON rate_limits(api_key_id)');
    }

    public static function getInstance(): ?PDO
    {
        return self::$connection;
    }

    public static function disconnect(): void
    {
        self::$connection = null;
    }
}
