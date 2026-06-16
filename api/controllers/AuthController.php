<?php
declare(strict_types=1);

namespace Bahll\Api\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Firebase\JWT\JWT;
use PDO;

class AuthController
{
    private string $jwtSecret;
    private int $jwtExpiration;
    private PDO $pdo;

    public function __construct(string $jwtSecret, int $jwtExpiration, PDO $pdo)
    {
        $this->jwtSecret = $jwtSecret;
        $this->jwtExpiration = $jwtExpiration;
        $this->pdo = $pdo;
    }

    // Generate new API key
    public function generateKey(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['key_name'])) {
                return $this->jsonError(
                    $response,
                    'Missing required field: key_name',
                    400
                );
            }

            // Generate random key
            $apiKey = bin2hex(random_bytes(32));
            $keyHash = hash('sha256', $apiKey);

            // Store key hash in database
            $stmt = $this->pdo->prepare('
                INSERT INTO api_keys (key_hash, key_name)
                VALUES (?, ?)
            ');
            $stmt->execute([$keyHash, $data['key_name']]);
            $keyId = (int)$this->pdo->lastInsertId();

            // Generate JWT token for this key
            $token = $this->generateToken($keyId);

            return $this->jsonSuccess($response, [
                'api_key' => $apiKey,
                'key_id' => $keyId,
                'key_name' => $data['key_name'],
                'token' => $token,
                'expires_in' => $this->jwtExpiration,
                'note' => 'Save your API key securely. You will not see it again!',
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Get token from API key
    public function getToken(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['api_key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required field: api_key',
                    400
                );
            }

            $keyHash = hash('sha256', $data['api_key']);

            $stmt = $this->pdo->prepare('
                SELECT id FROM api_keys
                WHERE key_hash = ? AND is_active = 1
            ');
            $stmt->execute([$keyHash]);
            $result = $stmt->fetch();

            if (!$result) {
                return $this->jsonError(
                    $response,
                    'Invalid or inactive API key',
                    401
                );
            }

            $keyId = (int)$result['id'];

            // Update last_used_at
            $updateStmt = $this->pdo->prepare('
                UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ');
            $updateStmt->execute([$keyId]);

            $token = $this->generateToken($keyId);

            return $this->jsonSuccess($response, [
                'token' => $token,
                'expires_in' => $this->jwtExpiration,
                'token_type' => 'Bearer',
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // List all API keys (admin only - for now unrestricted)
    public function listKeys(Request $request, Response $response): Response
    {
        try {
            $stmt = $this->pdo->prepare('
                SELECT id, key_name, created_at, last_used_at, is_active
                FROM api_keys
                ORDER BY created_at DESC
            ');
            $stmt->execute();
            $keys = $stmt->fetchAll();

            return $this->jsonSuccess($response, [
                'keys' => $keys,
                'total' => count($keys),
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Revoke API key
    public function revokeKey(Request $request, Response $response, array $args): Response
    {
        try {
            $keyId = (int)$args['key_id'];

            $stmt = $this->pdo->prepare('
                UPDATE api_keys SET is_active = 0
                WHERE id = ?
            ');
            $stmt->execute([$keyId]);

            return $this->jsonSuccess($response, [
                'message' => 'API key revoked successfully',
                'key_id' => $keyId,
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    private function generateToken(int $keyId): string
    {
        $issuedAt = time();
        $expire = $issuedAt + $this->jwtExpiration;

        $payload = [
            'iat' => $issuedAt,
            'exp' => $expire,
            'kid' => $keyId,
            'iss' => 'bahll-api',
        ];

        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    private function jsonSuccess(Response $response, array $data): Response
    {
        $response->getBody()->write(json_encode([
            'status' => 'success',
            'data' => $data,
            'timestamp' => date('c'),
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function jsonError(Response $response, string $message, int $statusCode): Response
    {
        $response = $response->withStatus($statusCode);
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => $message,
            'code' => $statusCode,
            'timestamp' => date('c'),
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
