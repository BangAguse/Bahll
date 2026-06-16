<?php
declare(strict_types=1);

namespace Bahll\Api\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use PDO;

class RateLimitMiddleware implements MiddlewareInterface
{
    private int $requestsPerMinute;
    private PDO $pdo;

    public function __construct(int $requestsPerMinute, PDO $pdo)
    {
        $this->requestsPerMinute = $requestsPerMinute;
        $this->pdo = $pdo;
    }

    public function process(Request $request, RequestHandler $handler): Response
    {
        $apiKeyId = $request->getAttribute('api_key_id');

        // Skip rate limiting for unauthenticated requests
        if (!$apiKeyId) {
            return $handler->handle($request);
        }

        if (!$this->checkRateLimit($apiKeyId)) {
            return $this->rateLimitExceededResponse();
        }

        $response = $handler->handle($request);

        // Add rate limit headers
        return $response
            ->withHeader('X-RateLimit-Limit', (string)$this->requestsPerMinute)
            ->withHeader('X-RateLimit-Remaining', (string)$this->getRemainingRequests($apiKeyId))
            ->withHeader('X-RateLimit-Reset', (string)$this->getRateLimitReset($apiKeyId));
    }

    private function checkRateLimit(int $apiKeyId): bool
    {
        try {
            $now = time();
            $windowStart = $now - 60; // 1 minute window

            // Clean old entries
            $this->pdo->exec('DELETE FROM rate_limits WHERE window_start < datetime("now", "-2 minutes")');

            // Get current count for this minute
            $stmt = $this->pdo->prepare('
                SELECT request_count FROM rate_limits
                WHERE api_key_id = ? AND window_start > datetime(?, "unixepoch")
            ');
            $stmt->execute([$apiKeyId, $windowStart]);
            $result = $stmt->fetch();

            if ($result) {
                $count = $result['request_count'];
                if ($count >= $this->requestsPerMinute) {
                    return false;
                }

                // Increment counter
                $updateStmt = $this->pdo->prepare('
                    UPDATE rate_limits
                    SET request_count = request_count + 1
                    WHERE api_key_id = ? AND window_start > datetime(?, "unixepoch")
                ');
                $updateStmt->execute([$apiKeyId, $windowStart]);
            } else {
                // Create new window entry
                $insertStmt = $this->pdo->prepare('
                    INSERT INTO rate_limits (api_key_id, request_count)
                    VALUES (?, 1)
                ');
                $insertStmt->execute([$apiKeyId]);
            }

            return true;
        } catch (\Exception $e) {
            // Log error but allow request if DB fails
            error_log('Rate limit check failed: ' . $e->getMessage());
            return true;
        }
    }

    private function getRemainingRequests(int $apiKeyId): int
    {
        try {
            $windowStart = time() - 60;

            $stmt = $this->pdo->prepare('
                SELECT request_count FROM rate_limits
                WHERE api_key_id = ? AND window_start > datetime(?, "unixepoch")
            ');
            $stmt->execute([$apiKeyId, $windowStart]);
            $result = $stmt->fetch();

            if ($result) {
                return max(0, $this->requestsPerMinute - $result['request_count']);
            }

            return $this->requestsPerMinute;
        } catch (\Exception $e) {
            return $this->requestsPerMinute;
        }
    }

    private function getRateLimitReset(int $apiKeyId): int
    {
        try {
            $stmt = $this->pdo->prepare('
                SELECT window_start FROM rate_limits
                WHERE api_key_id = ?
                ORDER BY window_start DESC
                LIMIT 1
            ');
            $stmt->execute([$apiKeyId]);
            $result = $stmt->fetch();

            if ($result) {
                $windowStart = strtotime($result['window_start']);
                return $windowStart + 60;
            }

            return time() + 60;
        } catch (\Exception $e) {
            return time() + 60;
        }
    }

    private function rateLimitExceededResponse(): Response
    {
        $response = new \GuzzleHttp\Psr7\Response(429);
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => 'Rate limit exceeded. Maximum ' . $this->requestsPerMinute . ' requests per minute.',
            'code' => 429,
        ]));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('X-RateLimit-Limit', (string)$this->requestsPerMinute);
    }
}
