#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Bahll REST API Server
 * 
 * Main entry point for the Bahll API server using Slim Framework
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

// Set root directory
define('BAHLL_ROOT', dirname(__DIR__));
chdir(BAHLL_ROOT);

// Load configuration
$config = require_once __DIR__ . '/config/config.php';

// Autoloader
require_once BAHLL_ROOT . '/vendor/autoload.php';

// Import Slim and dependencies
use Slim\Factory\AppFactory;
use Slim\Middleware\ErrorMiddleware;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Bahll\Api\Database\Database;
use Bahll\Api\Middleware\JwtAuthMiddleware;
use Bahll\Api\Middleware\RateLimitMiddleware;
use Bahll\Api\Routes\ApiRoutes;

// Initialize database
$database = new Database($config['database']['path']);
$pdo = $database->connect();
$database->initialize();

// Create Slim app
$app = AppFactory::create();

// Add middleware
$app->addMiddleware(new ErrorMiddleware(
    $app->getCallableResolver(),
    $app->getResponseFactory(),
    true,
    false,
    true
));

// Add custom middlewares AFTER error handling
$app->add(new RateLimitMiddleware(
    $config['rate_limit']['requests_per_minute'],
    $pdo
));

$app->add(new JwtAuthMiddleware($config['jwt']['secret']));

// Add CORS middleware
if ($config['cors']['enabled']) {
    $app->add(function (Request $request, $next) use ($config) {
        $response = $next->handle($request);

        // Handle preflight requests
        if ($request->getMethod() === 'OPTIONS') {
            return $response
                ->withHeader('Access-Control-Allow-Origin', implode(',', $config['cors']['allowed_origins']))
                ->withHeader('Access-Control-Allow-Methods', implode(',', $config['cors']['allowed_methods']))
                ->withHeader('Access-Control-Allow-Headers', implode(',', $config['cors']['allowed_headers']))
                ->withHeader('Access-Control-Max-Age', (string)$config['cors']['max_age']);
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', implode(',', $config['cors']['allowed_origins']))
            ->withHeader('Access-Control-Allow-Methods', implode(',', $config['cors']['allowed_methods']))
            ->withHeader('Access-Control-Allow-Headers', implode(',', $config['cors']['allowed_headers']));
    });
}

// Register routes
ApiRoutes::register($app, $pdo, $config['jwt']['secret'], $config['jwt']['expiration']);

// Set up signal handlers for graceful shutdown
$running = true;
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, function () use (&$running) {
        $running = false;
        echo "\n\n✋ Shutdown signal received. Gracefully shutting down...\n";
    });

    pcntl_signal(SIGINT, function () use (&$running) {
        $running = false;
        echo "\n\n✋ Interrupt signal received. Gracefully shutting down...\n";
    });
}

try {
    // Get server configuration
    $host = $config['server']['host'];
    $port = $config['server']['port'];

    // Display startup information
    echo "\n";
    echo "╔════════════════════════════════════════╗\n";
    echo "║     🔐 Bahll REST API Server v1.1     ║\n";
    echo "╚════════════════════════════════════════╝\n\n";

    echo "📋 Server Configuration:\n";
    echo "   Host: $host\n";
    echo "   Port: $port\n";
    echo "   Database: {$config['database']['path']}\n";
    echo "   Auth: JWT (HS256)\n";
    echo "   Rate Limit: {$config['rate_limit']['requests_per_minute']} req/min\n";
    echo "   CORS: " . ($config['cors']['enabled'] ? 'Enabled' : 'Disabled') . "\n";
    echo "\n";

    // Run the app
    echo "🚀 Starting server at http://$host:$port\n";
    echo "📚 API Base: http://$host:$port/api\n";
    echo "✅ Press Ctrl+C to stop\n\n";

    // Check if running from CLI
    if (php_sapi_name() !== 'cli-server' && php_sapi_name() !== 'cli') {
        echo "⚠️  Warning: This script should be run from CLI\n\n";
    }

    // For development, use PHP built-in server
    if (in_array(php_sapi_name(), ['cli-server', 'cli'])) {
        // Start PHP built-in server
        $publicDir = BAHLL_ROOT . '/public';
        if (!is_dir($publicDir)) {
            mkdir($publicDir, 0755, true);
        }

        // Create a public/index.php if not exists
        $publicIndex = $publicDir . '/index.php';
        if (!file_exists($publicIndex)) {
            file_put_contents($publicIndex, <<<'PHP'
<?php
require_once __DIR__ . '/../api/index.php';
PHP
            );
        }

        $cmd = sprintf(
            'php -S %s:%d -t %s',
            $host,
            $port,
            escapeshellarg($publicDir)
        );

        echo "Running command: $cmd\n\n";
        passthru($cmd);
    }
} catch (\Throwable $e) {
    echo "\n❌ Error: {$e->getMessage()}\n";
    echo "File: {$e->getFile()}\n";
    echo "Line: {$e->getLine()}\n\n";

    exit(1);
}
