<?php
declare(strict_types=1);

namespace Bahll\Api\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Bahll\Core\Crypto\Symmetric;
use Bahll\Core\Crypto\Asymmetric;
use Bahll\Core\Crypto\Hash;
use PDO;

class CryptoController
{
    private Symmetric $symmetric;
    private Asymmetric $asymmetric;
    private Hash $hash;
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->symmetric = new Symmetric();
        $this->asymmetric = new Asymmetric();
        $this->hash = new Hash();
        $this->pdo = $pdo;
    }

    // Symmetric Encryption
    public function encryptSymmetric(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['plaintext']) || !isset($data['key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required fields: plaintext, key',
                    400
                );
            }

            $startTime = microtime(true);

            $encrypted = $this->symmetric->encrypt(
                $data['plaintext'],
                $data['key']
            );

            $this->logOperation(
                $request,
                'symmetric_encrypt',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'ciphertext' => $encrypted,
                'algorithm' => 'AES-256-CBC',
                'encoding' => 'base64',
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'symmetric_encrypt',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Symmetric Decryption
    public function decryptSymmetric(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['ciphertext']) || !isset($data['key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required fields: ciphertext, key',
                    400
                );
            }

            $startTime = microtime(true);

            $decrypted = $this->symmetric->decrypt(
                $data['ciphertext'],
                $data['key']
            );

            $this->logOperation(
                $request,
                'symmetric_decrypt',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'plaintext' => $decrypted,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'symmetric_decrypt',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Asymmetric Encryption
    public function encryptAsymmetric(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['plaintext']) || !isset($data['public_key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required fields: plaintext, public_key',
                    400
                );
            }

            $startTime = microtime(true);

            $encrypted = $this->asymmetric->encrypt(
                $data['plaintext'],
                $data['public_key']
            );

            $this->logOperation(
                $request,
                'asymmetric_encrypt',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'ciphertext' => $encrypted,
                'algorithm' => 'RSA-2048',
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'asymmetric_encrypt',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Asymmetric Decryption
    public function decryptAsymmetric(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['ciphertext']) || !isset($data['private_key'])) {
                return $this->jsonError(
                    $response,
                    'Missing required fields: ciphertext, private_key',
                    400
                );
            }

            $startTime = microtime(true);

            $decrypted = $this->asymmetric->decrypt(
                $data['ciphertext'],
                $data['private_key']
            );

            $this->logOperation(
                $request,
                'asymmetric_decrypt',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'plaintext' => $decrypted,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'asymmetric_decrypt',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Hashing
    public function hash(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['data'])) {
                return $this->jsonError(
                    $response,
                    'Missing required field: data',
                    400
                );
            }

            $algorithm = $data['algorithm'] ?? 'sha256';
            $startTime = microtime(true);

            $hash = $this->hash->hash($data['data'], $algorithm);

            $this->logOperation(
                $request,
                'hash',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'hash' => $hash,
                'algorithm' => $algorithm,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'hash',
                'error',
                0,
                $e->getMessage()
            );
            return $this->jsonError($response, $e->getMessage(), 400);
        }
    }

    // Hash Verification
    public function verifyHash(Request $request, Response $response): Response
    {
        try {
            $data = $request->getParsedBody();

            if (!isset($data['data']) || !isset($data['hash'])) {
                return $this->jsonError(
                    $response,
                    'Missing required fields: data, hash',
                    400
                );
            }

            $algorithm = $data['algorithm'] ?? 'sha256';
            $startTime = microtime(true);

            $isValid = $this->hash->verify($data['data'], $data['hash'], $algorithm);

            $this->logOperation(
                $request,
                'verify_hash',
                'success',
                microtime(true) - $startTime
            );

            return $this->jsonSuccess($response, [
                'valid' => $isValid,
                'algorithm' => $algorithm,
            ]);
        } catch (\Exception $e) {
            $this->logOperation(
                $request,
                'verify_hash',
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
