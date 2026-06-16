<?php
declare(strict_types=1);

namespace Bahll\Api\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use PDO;

class AuditController
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    // Get audit logs
    public function getLogs(Request $request, Response $response): Response
    {
        try {
            $queryParams = $request->getQueryParams();
            $limit = (int)($queryParams['limit'] ?? 100);
            $offset = (int)($queryParams['offset'] ?? 0);
            $operation = $queryParams['operation'] ?? null;
            $status = $queryParams['status'] ?? null;
            $apiKeyId = (int)$request->getAttribute('api_key_id');

            $query = 'SELECT * FROM audit_logs WHERE api_key_id = ?';
            $params = [$apiKeyId];

            if ($operation) {
                $query .= ' AND operation = ?';
                $params[] = $operation;
            }

            if ($status) {
                $query .= ' AND status = ?';
                $params[] = $status;
            }

            $query .= ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            $params[] = $limit;
            $params[] = $offset;

            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            $logs = $stmt->fetchAll();

            // Get total count
            $countQuery = 'SELECT COUNT(*) as total FROM audit_logs WHERE api_key_id = ?';
            $countParams = [$apiKeyId];

            if ($operation) {
                $countQuery .= ' AND operation = ?';
                $countParams[] = $operation;
            }

            if ($status) {
                $countQuery .= ' AND status = ?';
                $countParams[] = $status;
            }

            $countStmt = $this->pdo->prepare($countQuery);
            $countStmt->execute($countParams);
            $total = $countStmt->fetch()['total'];

            return $this->jsonSuccess($response, [
                'logs' => $logs,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset,
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Get audit log by ID
    public function getLog(Request $request, Response $response, array $args): Response
    {
        try {
            $logId = (int)$args['log_id'];
            $apiKeyId = (int)$request->getAttribute('api_key_id');

            $stmt = $this->pdo->prepare('
                SELECT * FROM audit_logs
                WHERE id = ? AND api_key_id = ?
            ');
            $stmt->execute([$logId, $apiKeyId]);
            $log = $stmt->fetch();

            if (!$log) {
                return $this->jsonError(
                    $response,
                    'Log not found',
                    404
                );
            }

            return $this->jsonSuccess($response, ['log' => $log]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Get statistics
    public function getStats(Request $request, Response $response): Response
    {
        try {
            $apiKeyId = (int)$request->getAttribute('api_key_id');

            // Total operations
            $totalStmt = $this->pdo->prepare('
                SELECT COUNT(*) as total FROM audit_logs
                WHERE api_key_id = ?
            ');
            $totalStmt->execute([$apiKeyId]);
            $totalOps = $totalStmt->fetch()['total'];

            // Success rate
            $successStmt = $this->pdo->prepare('
                SELECT COUNT(*) as total FROM audit_logs
                WHERE api_key_id = ? AND status = "success"
            ');
            $successStmt->execute([$apiKeyId]);
            $successOps = $successStmt->fetch()['total'];

            $successRate = $totalOps > 0 ? ($successOps / $totalOps) * 100 : 0;

            // Average execution time
            $avgStmt = $this->pdo->prepare('
                SELECT AVG(execution_time) as avg_time FROM audit_logs
                WHERE api_key_id = ? AND status = "success"
            ');
            $avgStmt->execute([$apiKeyId]);
            $avgTime = (float)($avgStmt->fetch()['avg_time'] ?? 0);

            // Operations breakdown
            $operationsStmt = $this->pdo->prepare('
                SELECT operation, COUNT(*) as count, 
                       SUM(CASE WHEN status = "success" THEN 1 ELSE 0 END) as success_count
                FROM audit_logs
                WHERE api_key_id = ?
                GROUP BY operation
                ORDER BY count DESC
            ');
            $operationsStmt->execute([$apiKeyId]);
            $operations = $operationsStmt->fetchAll();

            return $this->jsonSuccess($response, [
                'total_operations' => $totalOps,
                'successful_operations' => $successOps,
                'failed_operations' => $totalOps - $successOps,
                'success_rate_percent' => round($successRate, 2),
                'average_execution_time_seconds' => round($avgTime, 4),
                'operations_breakdown' => $operations,
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
        }
    }

    // Clear logs (for specific API key)
    public function clearLogs(Request $request, Response $response): Response
    {
        try {
            $apiKeyId = (int)$request->getAttribute('api_key_id');

            $stmt = $this->pdo->prepare('
                DELETE FROM audit_logs
                WHERE api_key_id = ?
            ');
            $stmt->execute([$apiKeyId]);

            return $this->jsonSuccess($response, [
                'message' => 'Audit logs cleared successfully',
                'rows_deleted' => $stmt->rowCount(),
            ]);
        } catch (\Exception $e) {
            return $this->jsonError($response, $e->getMessage(), 500);
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
