<?php
declare(strict_types=1);

namespace Bahll\Api\Routes;

use Slim\App;
use Bahll\Api\Controllers\{
    CryptoController,
    AuthController,
    KeyringController,
    AuditController
};
use PDO;

class ApiRoutes
{
    public static function register(App $app, PDO $pdo, string $jwtSecret, int $jwtExpiration): void
    {
        $app->group('/api', function ($group) use ($pdo, $jwtSecret, $jwtExpiration) {
            // ==================== Authentication Routes ====================
            $group->post('/auth/generate-key', function ($request, $response) use ($pdo, $jwtSecret, $jwtExpiration) {
                $controller = new AuthController($jwtSecret, $jwtExpiration, $pdo);
                return $controller->generateKey($request, $response);
            })->setName('auth.generateKey');

            $group->post('/auth/token', function ($request, $response) use ($pdo, $jwtSecret, $jwtExpiration) {
                $controller = new AuthController($jwtSecret, $jwtExpiration, $pdo);
                return $controller->getToken($request, $response);
            })->setName('auth.getToken');

            $group->get('/auth/keys', function ($request, $response) use ($pdo, $jwtSecret, $jwtExpiration) {
                $controller = new AuthController($jwtSecret, $jwtExpiration, $pdo);
                return $controller->listKeys($request, $response);
            })->setName('auth.listKeys');

            $group->delete('/auth/keys/{key_id}', function ($request, $response, $args) use ($pdo, $jwtSecret, $jwtExpiration) {
                $controller = new AuthController($jwtSecret, $jwtExpiration, $pdo);
                return $controller->revokeKey($request, $response, $args);
            })->setName('auth.revokeKey');

            // ==================== Symmetric Crypto Routes ====================
            $group->post('/crypto/encrypt-symmetric', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->encryptSymmetric($request, $response);
            })->setName('crypto.encryptSymmetric');

            $group->post('/crypto/decrypt-symmetric', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->decryptSymmetric($request, $response);
            })->setName('crypto.decryptSymmetric');

            // ==================== Asymmetric Crypto Routes ====================
            $group->post('/crypto/encrypt-asymmetric', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->encryptAsymmetric($request, $response);
            })->setName('crypto.encryptAsymmetric');

            $group->post('/crypto/decrypt-asymmetric', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->decryptAsymmetric($request, $response);
            })->setName('crypto.decryptAsymmetric');

            // ==================== Hashing Routes ====================
            $group->post('/crypto/hash', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->hash($request, $response);
            })->setName('crypto.hash');

            $group->post('/crypto/verify-hash', function ($request, $response) use ($pdo) {
                $controller = new CryptoController($pdo);
                return $controller->verifyHash($request, $response);
            })->setName('crypto.verifyHash');

            // ==================== Keyring Routes ====================
            $group->post('/keyring/generate-keypair', function ($request, $response) use ($pdo) {
                $controller = new KeyringController($pdo);
                return $controller->generateKeyPair($request, $response);
            })->setName('keyring.generateKeyPair');

            $group->post('/keyring/validate-key', function ($request, $response) use ($pdo) {
                $controller = new KeyringController($pdo);
                return $controller->validateKey($request, $response);
            })->setName('keyring.validateKey');

            $group->post('/keyring/get-key-details', function ($request, $response) use ($pdo) {
                $controller = new KeyringController($pdo);
                return $controller->getKeyDetails($request, $response);
            })->setName('keyring.getKeyDetails');

            // ==================== Audit Log Routes ====================
            $group->get('/audit/logs', function ($request, $response) use ($pdo) {
                $controller = new AuditController($pdo);
                return $controller->getLogs($request, $response);
            })->setName('audit.getLogs');

            $group->get('/audit/logs/{log_id}', function ($request, $response, $args) use ($pdo) {
                $controller = new AuditController($pdo);
                return $controller->getLog($request, $response, $args);
            })->setName('audit.getLog');

            $group->get('/audit/stats', function ($request, $response) use ($pdo) {
                $controller = new AuditController($pdo);
                return $controller->getStats($request, $response);
            })->setName('audit.getStats');

            $group->delete('/audit/logs', function ($request, $response) use ($pdo) {
                $controller = new AuditController($pdo);
                return $controller->clearLogs($request, $response);
            })->setName('audit.clearLogs');

            // ==================== Health Checks ====================
            $group->get('/health', function ($request, $response) {
                $response->getBody()->write(json_encode([
                    'status' => 'healthy',
                    'timestamp' => date('c'),
                    'version' => '1.1.0',
                ]));
                return $response->withHeader('Content-Type', 'application/json');
            })->setName('health');

            $group->get('/status', function ($request, $response) {
                $response->getBody()->write(json_encode([
                    'status' => 'running',
                    'timestamp' => date('c'),
                    'version' => '1.1.0',
                    'uptime' => 'N/A',
                ]));
                return $response->withHeader('Content-Type', 'application/json');
            })->setName('status');
        });
    }
}
