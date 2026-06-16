# Bahll REST API Documentation

**Version**: 1.1.0  
**Base URL**: `http://localhost:8000/api`

## Table of Contents

1. [Authentication](#authentication)
2. [Encryption/Decryption](#encryptiondecryption)
3. [Hashing](#hashing)
4. [Key Management](#key-management)
5. [Audit Logs](#audit-logs)
6. [Response Format](#response-format)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)
9. [Examples](#examples)

---

## Authentication

### Generate API Key

Creates a new API key for accessing the API.

**Endpoint**: `POST /api/auth/generate-key`

**Request**:
```json
{
  "key_name": "My Application"
}
```

**Response** (201):
```json
{
  "status": "success",
  "data": {
    "api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z",
    "key_id": 1,
    "key_name": "My Application",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 86400,
    "note": "Save your API key securely. You will not see it again!"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Get Token from API Key

Exchange an API key for a JWT token.

**Endpoint**: `POST /api/auth/token`

**Request**:
```json
{
  "api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 86400,
    "token_type": "Bearer"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### List API Keys

List all API keys (requires authentication).

**Endpoint**: `GET /api/auth/keys`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "keys": [
      {
        "id": 1,
        "key_name": "My Application",
        "created_at": "2026-06-16 10:30:45",
        "last_used_at": "2026-06-16 10:35:20",
        "is_active": 1
      }
    ],
    "total": 1
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Revoke API Key

Deactivate an API key.

**Endpoint**: `DELETE /api/auth/keys/{key_id}`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "message": "API key revoked successfully",
    "key_id": 1
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Encryption/Decryption

### Encrypt (Symmetric - AES-256-CBC)

Encrypt data using symmetric encryption.

**Endpoint**: `POST /api/crypto/encrypt-symmetric`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "plaintext": "Hello, World!",
  "key": "my-secure-encryption-key-32-chars"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "ciphertext": "U2FsdGVkX1+X...",
    "algorithm": "AES-256-CBC",
    "encoding": "base64"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Decrypt (Symmetric)

Decrypt data using symmetric encryption.

**Endpoint**: `POST /api/crypto/decrypt-symmetric`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "ciphertext": "U2FsdGVkX1+X...",
  "key": "my-secure-encryption-key-32-chars"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "plaintext": "Hello, World!"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Encrypt (Asymmetric - RSA-2048)

Encrypt data using public key.

**Endpoint**: `POST /api/crypto/encrypt-asymmetric`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "plaintext": "Secret message",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...\n-----END PUBLIC KEY-----"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "ciphertext": "BASE64_ENCODED_CIPHERTEXT",
    "algorithm": "RSA-2048"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Decrypt (Asymmetric)

Decrypt data using private key.

**Endpoint**: `POST /api/crypto/decrypt-asymmetric`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "ciphertext": "BASE64_ENCODED_CIPHERTEXT",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "plaintext": "Secret message"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Hashing

### Create Hash

Generate hash of data.

**Endpoint**: `POST /api/crypto/hash`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "data": "some data to hash",
  "algorithm": "sha256"
}
```

**Supported Algorithms**: `md5`, `sha1`, `sha256`, `sha512`, `bcrypt`

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "hash": "d5579c46dfb686704f11a3e3d88b1f4d63c68dc40a63c84aa03cc4b76b47a3f0",
    "algorithm": "sha256"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Verify Hash

Verify if data matches a hash.

**Endpoint**: `POST /api/crypto/verify-hash`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "data": "some data to hash",
  "hash": "d5579c46dfb686704f11a3e3d88b1f4d63c68dc40a63c84aa03cc4b76b47a3f0",
  "algorithm": "sha256"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "valid": true,
    "algorithm": "sha256"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Key Management

### Generate Key Pair

Generate a new RSA key pair.

**Endpoint**: `POST /api/keyring/generate-keypair`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "key_size": 2048
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    "key_size": 2048,
    "algorithm": "RSA"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Validate Key

Check if a key is valid.

**Endpoint**: `POST /api/keyring/validate-key`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "key_type": "public"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "valid": true,
    "key_type": "public"
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Get Key Details

Get information about a key.

**Endpoint**: `POST /api/keyring/get-key-details`

**Headers**:
```
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request**:
```json
{
  "key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "details": {
      "type": "RSA",
      "bits": 2048,
      "valid": true
    }
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Audit Logs

### Get Audit Logs

Retrieve audit logs for your API key.

**Endpoint**: `GET /api/audit/logs`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Query Parameters**:
- `limit` (optional, default: 100): Number of logs to return
- `offset` (optional, default: 0): Pagination offset
- `operation` (optional): Filter by operation type
- `status` (optional): Filter by status (success/error)

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "logs": [
      {
        "id": 1,
        "api_key_id": 1,
        "operation": "symmetric_encrypt",
        "status": "success",
        "execution_time": 0.0245,
        "created_at": "2026-06-16 10:30:45"
      }
    ],
    "total": 1,
    "limit": 100,
    "offset": 0
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Get Single Log

Retrieve a specific audit log.

**Endpoint**: `GET /api/audit/logs/{log_id}`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "log": {
      "id": 1,
      "api_key_id": 1,
      "operation": "symmetric_encrypt",
      "status": "success",
      "execution_time": 0.0245,
      "created_at": "2026-06-16 10:30:45"
    }
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Get Statistics

Get audit statistics for your API key.

**Endpoint**: `GET /api/audit/stats`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "total_operations": 150,
    "successful_operations": 148,
    "failed_operations": 2,
    "success_rate_percent": 98.67,
    "average_execution_time_seconds": 0.0342,
    "operations_breakdown": [
      {
        "operation": "symmetric_encrypt",
        "count": 75,
        "success_count": 75
      },
      {
        "operation": "hash",
        "count": 50,
        "success_count": 50
      }
    ]
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

### Clear Logs

Delete all audit logs for your API key.

**Endpoint**: `DELETE /api/audit/logs`

**Headers**:
```
Authorization: Bearer <TOKEN>
```

**Response** (200):
```json
{
  "status": "success",
  "data": {
    "message": "Audit logs cleared successfully",
    "rows_deleted": 150
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Response Format

### Success Response

```json
{
  "status": "success",
  "data": {
    "/* response data */": null
  },
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

### Error Response

```json
{
  "status": "error",
  "message": "Error description",
  "code": 400,
  "timestamp": "2026-06-16T10:30:45+00:00"
}
```

---

## Error Handling

### HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid authentication
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### Common Errors

| Code | Message |
|------|---------|
| 401 | Missing Authorization header |
| 401 | Invalid Authorization header format |
| 401 | Token expired |
| 401 | Invalid token signature |
| 429 | Rate limit exceeded. Maximum 100 requests per minute. |
| 400 | Missing required fields |
| 500 | Database connection failed |

---

## Rate Limiting

- **Limit**: 100 requests per minute per API key
- **Headers**: 
  - `X-RateLimit-Limit`: Maximum requests per minute
  - `X-RateLimit-Remaining`: Requests remaining in current window
  - `X-RateLimit-Reset`: Unix timestamp when limit resets

---

## Examples

### Example 1: Symmetric Encryption Workflow

```bash
# 1. Generate API key
curl -X POST http://localhost:8000/api/auth/generate-key \
  -H "Content-Type: application/json" \
  -d '{"key_name": "Web App"}'

# 2. Get token
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_API_KEY"}'

# 3. Encrypt data
curl -X POST http://localhost:8000/api/crypto/encrypt-symmetric \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "Sensitive data",
    "key": "my-secure-32-char-encryption-key"
  }'

# 4. Decrypt data
curl -X POST http://localhost:8000/api/crypto/decrypt-symmetric \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "ENCRYPTED_DATA",
    "key": "my-secure-32-char-encryption-key"
  }'
```

### Example 2: Hashing Workflow

```bash
# 1. Create hash
curl -X POST http://localhost:8000/api/crypto/hash \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "password123",
    "algorithm": "sha256"
  }'

# 2. Verify hash
curl -X POST http://localhost:8000/api/crypto/verify-hash \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "password123",
    "hash": "HASH_VALUE",
    "algorithm": "sha256"
  }'
```

### Example 3: Key Pair Workflow

```bash
# 1. Generate key pair
curl -X POST http://localhost:8000/api/keyring/generate-keypair \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_size": 2048}'

# 2. Encrypt with public key
curl -X POST http://localhost:8000/api/crypto/encrypt-asymmetric \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "Secret",
    "public_key": "PUBLIC_KEY_FROM_STEP_1"
  }'

# 3. Decrypt with private key
curl -X POST http://localhost:8000/api/crypto/decrypt-asymmetric \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "ENCRYPTED_DATA",
    "private_key": "PRIVATE_KEY_FROM_STEP_1"
  }'
```

---

## Health Check

### Check API Status

**Endpoint**: `GET /api/health` or `GET /api/status`

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-06-16T10:30:45+00:00",
  "version": "1.0.0"
}
```

---

## Support

For issues or questions, visit: https://github.com/BangAguse/Bahll
