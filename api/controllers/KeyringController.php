<?php
declare(strict_types=1);

namespace Bahll\Api\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Bahll\Core\Keyring\Keyring;
use PDO;

class KeyringController
{
    private Keyring $keyring;
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->keyring = new Keyring();
        $this->pdo = $pdo;
    }

    // Generate key pair
    public function generateKeyPair(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();
            $keySize = (int)($data['key_size'] ?? 2048);

            if ($keySize < 2048) {
                return $this->jsonError(
                    $response,
                    'Key size must be at least 2048 bits',
                    400
                );
            }

            $startTime = microtime(true);

            $keyPair = $this->keyring->generateKeyPair($keySize);

            $this->logOperation(
                $request,
                'generate_keypair',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'public_key' => $keyPair['public_key'],
                'private_key' => $keyPair['private_key'],
                'key_size' => $keySize,
                'algorithm' => 'RSA',
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'generate_keypair',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Validate key format
    public function validateKey(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required field: key',
                    400
                );
            }

            $keyType = $data['key_type'] ?? 'auto';

            $isValid = $this->keyring->validateKey($data['key'], $keyType);

            $this->logOperation(
                $request,
                'validate_key',
                'success',
                0
            );

            return $this->jsonSuccess($response, [
                'valid' => $isValid,
                'key_type' => $keyType,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'validate_key',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Get key details
    public function getKeyDetails(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required field: key',
                    400
                );
            }

            $details = $this->keyring->getKeyDetails($data['key']);

            $this->logOperation(
                $request,
                'get_key_details',
                'success',
                0
            );

            return $this->jsonSuccess($response, [
                'details' => $details,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'get_key_details',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    private function logOperation(
        Request $request,
        string $operation,
        string $status,
        float $executionTime,
        ?string $errorMessage = null
    ): void {
        try {
            $apiKeyId = $request->getAttribute('api_key_id');

            $stmt = $this->pdo->prepare('
                INSERT INTO audit_logs (api_key_id, operation, status, execution_time, error_message)
                VALUES (?, ?, ?, ?, ?)
            ');

            $stmt->execute([
                $apiKeyId,
                $operation,
                $status,
                $executionTime,
                $errorMessage,
            ]);
        } catch (\Exception $e) {
            error_log('Failed to log operation: ' . $e->getMessage());
        }
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
