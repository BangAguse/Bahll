# Bahll REST API - Quick Start Guide

## Installation & Setup

### Prerequisites
- PHP 7.4 or 8.0+
- Composer
- OpenSSL extension
- PDO extension

### Step 1: Install Dependencies

```bash
cd /home/k1ng5/Mylab/Bahll
composer install
```

### Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
nano .env
```

### Step 3: Start the API Server

```bash
# Option A: Using PHP built-in server
php api/index.php

# Option B: Using Docker
docker-compose up -d

# Option C: Using Docker Compose with custom port
BAHLL_API_PORT=9000 docker-compose up -d
```

### Step 4: Verify Server is Running

```bash
# Check health endpoint
curl http://localhost:8000/api/health

# Expected response:
# {"status":"healthy","timestamp":"2026-06-16T10:30:45+00:00","version":"1.1.0"}
```

---

## Common Workflows

### 1️⃣ Get Started with Authentication

```bash
# Generate your first API key
curl -X POST http://localhost:8000/api/auth/generate-key \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "My First App"
  }'

# Save the api_key and token from response
# You'll use this token for all subsequent requests!
```

### 2️⃣ Encrypt Data (Symmetric)

```bash
# Get token first (see above)
TOKEN="your-token-here"

curl -X POST http://localhost:8000/api/crypto/encrypt-symmetric \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "Hello, World!",
    "key": "my-secret-key-at-least-32-chars"
  }'
```

### 3️⃣ Decrypt Data (Symmetric)

```bash
TOKEN="your-token-here"
CIPHERTEXT="from-previous-response"

curl -X POST http://localhost:8000/api/crypto/decrypt-symmetric \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "'$CIPHERTEXT'",
    "key": "my-secret-key-at-least-32-chars"
  }'
```

### 4️⃣ Create & Verify Hashes

```bash
TOKEN="your-token-here"

# Create hash
HASH_RESPONSE=$(curl -s -X POST http://localhost:8000/api/crypto/hash \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "password123",
    "algorithm": "sha256"
  }')

echo "$HASH_RESPONSE"

# Extract hash from response and verify
# {
#   "status": "success",
#   "data": {
#     "hash": "ef92b778bafe771e89245d171bafbee4ff06f8f38eed6e1983ad1e8e8c7b052e",
#     "algorithm": "sha256"
#   }
# }

# Verify
curl -X POST http://localhost:8000/api/crypto/verify-hash \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "password123",
    "hash": "ef92b778bafe771e89245d171bafbee4ff06f8f38eed6e1983ad1e8e8c7b052e",
    "algorithm": "sha256"
  }'
```

### 5️⃣ Generate & Use Key Pairs

```bash
TOKEN="your-token-here"

# Generate RSA key pair
KEYPAIR=$(curl -s -X POST http://localhost:8000/api/keyring/generate-keypair \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_size": 2048}')

echo "$KEYPAIR"

# Extract keys from response
# {
#   "status": "success",
#   "data": {
#     "public_key": "-----BEGIN PUBLIC KEY-----\n...",
#     "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
#     "key_size": 2048,
#     "algorithm": "RSA"
#   }
# }

# Use public key to encrypt
curl -X POST http://localhost:8000/api/crypto/encrypt-asymmetric \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "Secret message",
    "public_key": "PUBLIC_KEY_HERE"
  }'

# Use private key to decrypt
curl -X POST http://localhost:8000/api/crypto/decrypt-asymmetric \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "CIPHERTEXT_HERE",
    "private_key": "PRIVATE_KEY_HERE"
  }'
```

### 6️⃣ View Audit Logs

```bash
TOKEN="your-token-here"

# Get all logs
curl -X GET "http://localhost:8000/api/audit/logs?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Get specific log
curl -X GET "http://localhost:8000/api/audit/logs/1" \
  -H "Authorization: Bearer $TOKEN"

# Get statistics
curl -X GET "http://localhost:8000/api/audit/stats" \
  -H "Authorization: Bearer $TOKEN"

# Filter logs by operation
curl -X GET "http://localhost:8000/api/audit/logs?operation=symmetric_encrypt&status=success" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Docker Usage

### Start Container

```bash
# Build and start
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f bahll-api
```

### Stop Container

```bash
docker-compose down
```

### Rebuild Image

```bash
docker-compose build --no-cache
docker-compose up -d
```

### Environment Variables in Docker

```bash
# Create .env file
cat > .env << EOF
BAHLL_API_PORT=8000
BAHLL_JWT_SECRET=your-super-secret-key
BAHLL_LOG_LEVEL=info
BAHLL_CORS_ORIGINS=*
EOF

# Start with custom config
docker-compose up -d
```

---

## Advanced Configuration

### Using PostgreSQL (Production)

1. Uncomment PostgreSQL section in `docker-compose.yml`
2. Update `api/config/config.php` to use PostgreSQL
3. Set database credentials in `.env`
4. Run: `docker-compose up -d`

### Rate Limiting

Default: **100 requests per minute** per API key

Modify in `api/config/config.php`:
```php
'rate_limit' => [
    'requests_per_minute' => 200, // Change this value
],
```

### Custom JWT Secret

```bash
# Generate secure random secret
php -r "echo bin2hex(random_bytes(32));"

# Add to .env
BAHLL_JWT_SECRET=your-generated-secret-here
```

### Enable CORS for Specific Origins

```bash
# Set in .env
BAHLL_CORS_ORIGINS=https://example.com,https://app.example.com
```

---

## Troubleshooting

### Port Already in Use

```bash
# Change port in .env or docker-compose.yml
BAHLL_API_PORT=9000

# Or kill process on port 8000
lsof -ti:8000 | xargs kill -9
```

### Database Connection Error

```bash
# Ensure storage directory exists
mkdir -p storage
chmod 777 storage

# Reset database
rm storage/bahll.db
php api/index.php  # Will recreate on startup
```

### Token Expired

Generate new token:
```bash
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_API_KEY"}'
```

### Rate Limit Hit

Wait 1 minute or check remaining requests:
- Header: `X-RateLimit-Remaining`
- Header: `X-RateLimit-Reset`

---

## Performance Tips

1. **Use connection pooling** in production
2. **Enable caching** for frequently used operations
3. **Monitor audit logs** regularly (clear old entries)
4. **Use shorter keys** when possible (asymmetric crypto is slower)
5. **Batch operations** to reduce API calls

---

## Security Best Practices

1. ✅ Change `BAHLL_JWT_SECRET` in production
2. ✅ Use HTTPS in production (enable TLS/SSL)
3. ✅ Store API keys securely (never commit to git)
4. ✅ Rotate API keys periodically
5. ✅ Monitor audit logs for suspicious activity
6. ✅ Use rate limiting to prevent abuse
7. ✅ Validate input data on client side
8. ✅ Keep PHP and dependencies updated

---

## API Documentation

Full API documentation: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## Support & Issues

- GitHub: https://github.com/BangAguse/Bahll
- Issues: https://github.com/BangAguse/Bahll/issues
- Documentation: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
