<?php
declare(strict_types=1);

namespace Bahll\Api\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class JwtAuthMiddleware implements MiddlewareInterface
{
    private string $secret;
    private array $excludedPaths = [
        '/api/health',
        '/api/status',
        '/api/auth/generate-key',
        '/api/docs',
    ];

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function process(Request $request, RequestHandler $handler): Response
    {
        $path = $request->getUri()->getPath();

        // Check if path is excluded
        if ($this->isPathExcluded($path)) {
            return $handler->handle($request);
        }

        try {
            $authHeader = $request->getHeaderLine('Authorization');

            if (empty($authHeader)) {
                return $this->errorResponse(
                    'Missing Authorization header',
                    401
                );
            }

            // Extract token from "Bearer <token>" format
            if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
                return $this->errorResponse(
                    'Invalid Authorization header format',
                    401
                );
            }

            $token = $matches[1];

            // Decode JWT
            $decoded = JWT::decode(
                $token,
                new Key($this->secret, 'HS256')
            );

            // Add decoded token to request
            $request = $request->withAttribute('token', $decoded);
            $request = $request->withAttribute('api_key_id', $decoded->kid ?? null);

            return $handler->handle($request);

        } catch (ExpiredException $e) {
            return $this->errorResponse(
                'Token expired',
                401
            );
        } catch (SignatureInvalidException $e) {
            return $this->errorResponse(
                'Invalid token signature',
                401
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Invalid token: ' . $e->getMessage(),
                401
            );
        }
    }

    private function isPathExcluded(string $path): bool
    {
        foreach ($this->excludedPaths as $excludedPath) {
            if ($path === $excludedPath || strpos($path, $excludedPath) === 0) {
                return true;
            }
        }
        return false;
    }

    private function errorResponse(string $message, int $statusCode): Response
    {
        $response = new \GuzzleHttp\Psr7\Response($statusCode);
        $response->getBody()->write(json_encode([
            'status' => 'error',
            'message' => $message,
            'code' => $statusCode,
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
