<?php
declare(strict_types=1);

return [
    // Server Configuration
    'server' => [
        'host' => getenv('BAHLL_API_HOST') ?: '0.0.0.0',
        'port' => (int)(getenv('BAHLL_API_PORT') ?: 8000),
        'timeout' => 60, // seconds
    ],

    // JWT Configuration
    'jwt' => [
        'secret' => getenv('BAHLL_JWT_SECRET') ?: 'bahll-development-secret-change-in-production',
        'algorithm' => 'HS256',
        'expiration' => 86400, // 24 hours in seconds
    ],

    // Rate Limiting
    'rate_limit' => [
        'enabled' => true,
        'requests_per_minute' => 100,
        'storage' => getenv('BAHLL_RATE_LIMIT_STORAGE') ?: 'memory', // 'memory' or 'file'
        'storage_path' => '/tmp/bahll-rate-limit.json',
    ],

    // Database Configuration
    'database' => [
        'type' => 'sqlite',
        'path' => getenv('BAHLL_DB_PATH') ?: __DIR__ . '/../../storage/bahll.db',
        'timeout' => 30,
    ],

    // Logging Configuration
    'logging' => [
        'enabled' => true,
        'level' => getenv('BAHLL_LOG_LEVEL') ?: 'info', // debug, info, warning, error
        'file' => getenv('BAHLL_LOG_FILE') ?: __DIR__ . '/../../storage/api.log',
        'max_size' => 10 * 1024 * 1024, // 10MB
        'backup_count' => 5,
    ],

    // CORS Configuration
    'cors' => [
        'enabled' => true,
        'allowed_origins' => explode(',', getenv('BAHLL_CORS_ORIGINS') ?: '*'),
        'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-API-Key'],
        'max_age' => 86400,
    ],

    // API Versions
    'api' => [
        'version' => '1.0.0',
        'prefix' => '/api',
        'default_format' => 'json',
    ],
];
