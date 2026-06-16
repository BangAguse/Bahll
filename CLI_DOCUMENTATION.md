# Bahll CLI Documentation

## Overview

Bahll Cryptography Suite sekarang dapat diakses melalui **Command Line Interface (CLI)** selain mode interaktif. Ini memungkinkan Anda untuk mengintegrasikan Bahll ke dalam skrip, automasi, atau tools lainnya di mana pun Anda membutuhkannya.

## Quick Start

### Interactive Mode (Default)
```bash
php bahll.php
```
Menjalankan Bahll dalam mode interaktif seperti sebelumnya.

### CLI Command Mode
```bash
php bahll.php [COMMAND] [OPTIONS]
```

## Global Options

| Option | Alias | Deskripsi |
|--------|-------|-----------|
| `--help` | `-h` | Tampilkan bantuan |
| `--version` | `-v` | Tampilkan versi |
| `help` | - | Tampilkan bantuan umum |
| `version` | - | Tampilkan informasi versi |

## Main Commands

### 1. Hash & Key Derivation (hash)

Melakukan hashing dan key derivation pada data.

**Syntax:**
```bash
php bahll.php hash [ALGORITHM] [DATA]
```

**Algorithms:**
- `sha1` - SHA-1 (deprecated)
- `sha256` - SHA-256
- `sha512` - SHA-512
- `sha3` - SHA3-512
- `blake2` - BLAKE2
- `blake3` - BLAKE3
- `hmac` - HMAC
- `pbkdf2` - PBKDF2
- `bcrypt` - bcrypt
- `argon2` - Argon2id
- `scrypt` - scrypt

**Examples:**
```bash
# SHA-256 hash
php bahll.php hash sha256 "Hello World"

# Argon2 password hashing
php bahll.php hash argon2 "MyPassword123" "65536"

# HMAC-SHA256
php bahll.php hash hmac sha256 "Hello World" "secret-key"

# PBKDF2 derivation
php bahll.php hash pbkdf2 "password" "salt123" "100000"

# bcrypt hashing
php bahll.php hash bcrypt "MySecurePassword"
```

**Help:**
```bash
php bahll.php hash --help
php bahll.php hash -h
```

---

### 2. Encryption (encrypt)

Melakukan enkripsi data dengan algoritma simetrik.

**Syntax:**
```bash
php bahll.php encrypt [ALGORITHM] [PLAINTEXT] [KEY]
```

**Algorithms:**
- `aes-256-gcm` - AES-256-GCM (recommended)
- `aes-256-cbc` - AES-256-CBC with HMAC

**Examples:**
```bash
# AES-256-GCM encryption
php bahll.php encrypt aes-256-gcm "Secret message" "MySecureKey123"

# AES-256-CBC encryption
php bahll.php encrypt aes-256-cbc "Secret data" "MyPassword"
```

**Help:**
```bash
php bahll.php encrypt --help
```

---

### 3. Decryption (decrypt)

Melakukan dekripsi data yang dienkripsi dengan algoritma simetrik.

**Syntax:**
```bash
php bahll.php decrypt [ALGORITHM] [CIPHERTEXT] [KEY]
```

**Examples:**
```bash
# AES-256-GCM decryption
php bahll.php decrypt aes-256-gcm "[encrypted-data]" "MySecureKey123"

# AES-256-CBC decryption
php bahll.php decrypt aes-256-cbc "[encrypted-data]" "MyPassword"
```

**Help:**
```bash
php bahll.php decrypt --help
```

---

### 4. Asymmetric Cryptography (asymmetric)

Melakukan operasi kriptografi asimetrik seperti key generation, signing, dan verification.

**Syntax:**
```bash
php bahll.php asymmetric [ACTION] [OPTIONS...]
```

**Actions:**
- `generate [TYPE]` - Generate key pair
- `sign [PRIVKEY] [MESSAGE]` - Sign message
- `verify [PUBKEY] [MESSAGE] [SIGNATURE]` - Verify signature

**Examples:**
```bash
# Generate RSA-2048 keypair
php bahll.php asymmetric generate rsa-2048

# Generate Ed25519 keypair
php bahll.php asymmetric generate ed25519

# Sign message with private key
php bahll.php asymmetric sign "[private-key-hex]" "Message to sign"

# Verify signature
php bahll.php asymmetric verify "[public-key-hex]" "Message" "[signature-base64]"
```

**Help:**
```bash
php bahll.php asymmetric --help
```

---

### 5. Keyring Management (keyring)

Mengelola keyring dan key material.

**Syntax:**
```bash
php bahll.php keyring [ACTION] [OPTIONS...]
```

**Actions:**
- `create` - Create new keyring
- `list` - List all keys
- `add [NAME]` - Add new key
- `remove [NAME]` - Remove key
- `export [NAME]` - Export key
- `import [NAME]` - Import key

**Help:**
```bash
php bahll.php keyring --help
```

---

### 6. Encoding & Obfuscation (encoding)

Melakukan encoding dan obfuscation data.

**Syntax:**
```bash
php bahll.php encoding [TYPE] [DATA]
```

**Types:**
- `base64` - Base64 encoding
- `base32` - Base32 encoding
- `hex` - Hexadecimal encoding
- `url` - URL-safe encoding
- `html` - HTML entity encoding
- `json` - JSON encoding

**Examples:**
```bash
# Base64 encode
php bahll.php encoding base64 "Hello World"

# Hexadecimal encode
php bahll.php encoding hex "data"

# URL-safe encode
php bahll.php encoding url "path with spaces"

# HTML entity encode
php bahll.php encoding html "<script>alert('xss')</script>"
```

**Help:**
```bash
php bahll.php encoding --help
```

---

### 7. Random Data Generation (random)

Generate random data dan entropy.

**Syntax:**
```bash
php bahll.php random [TYPE] [LENGTH]
```

**Types:**
- `bytes` - Random bytes
- `int` - Random integer
- `string` - Random string
- `uuid` - UUID generation
- `password` - Secure password
- `token` - Secure token
- `hex` - Random hex string

**Examples:**
```bash
# Generate 32 random bytes
php bahll.php random bytes 32

# Generate random string (20 characters)
php bahll.php random string 20

# Generate random integer (0-100)
php bahll.php random int 100

# Generate UUID v4
php bahll.php random uuid v4

# Generate secure password (16 characters)
php bahll.php random password 16
```

**Help:**
```bash
php bahll.php random --help
```

---

### 8. Audit & Validation (audit)

Melakukan audit dan validasi sistem keamanan.

**Syntax:**
```bash
php bahll.php audit [ACTION] [OPTIONS...]
```

**Actions:**
- `check` - System security check
- `hash-file [PATH]` - Hash file
- `validate [PATH]` - Validate file integrity

**Examples:**
```bash
# Security system check
php bahll.php audit check

# Hash file with SHA-256
php bahll.php audit hash-file "/path/to/file" "sha256"
```

**Help:**
```bash
php bahll.php audit --help
```

---

### 9. Secret Lifecycle (secrets)

Mengelola secret lifecycle.

**Syntax:**
```bash
php bahll.php secrets [ACTION] [OPTIONS...]
```

**Actions:**
- `store [NAME]` - Store secret
- `retrieve [NAME]` - Retrieve secret
- `list` - List secrets
- `delete [NAME]` - Delete secret
- `rotate [NAME]` - Rotate secret

**Help:**
```bash
php bahll.php secrets --help
```

---

### 10. Encryptor Manager (encryptor)

Mengelola enkripsi folder dan file.

**Syntax:**
```bash
php bahll.php encryptor [ACTION] [OPTIONS...]
```

**Actions:**
- `encrypt [PATH]` - Encrypt file/folder
- `view` - View encrypted contents
- `list` - List encrypted items
- `status` - Show status

**Examples:**
```bash
# Encrypt a folder
php bahll.php encryptor encrypt "/path/to/folder"

# View encrypted contents
php bahll.php encryptor view

# List encrypted items
php bahll.php encryptor list
```

**Help:**
```bash
php bahll.php encryptor --help
```

---

### 11. Decryptor Manager (decryptor)

Mengelola dekripsi folder dan file.

**Syntax:**
```bash
php bahll.php decryptor [ACTION] [OPTIONS...]
```

**Actions:**
- `decrypt [PATH]` - Decrypt file/folder
- `bruteforce [PATH]` - Bruteforce decrypt
- `view` - View decrypted contents
- `list` - List decrypted items

**Examples:**
```bash
# Decrypt a file
php bahll.php decryptor decrypt "/path/to/encrypted-file"

# Bruteforce with wordlist
php bahll.php decryptor bruteforce "/path" --wordlist "wordlist.txt"

# View decrypted contents
php bahll.php decryptor view
```

**Help:**
```bash
php bahll.php decryptor --help
```

---

### 12. Activity Logs (logs)

Mengelola dan melihat activity logs.

**Syntax:**
```bash
php bahll.php logs [ACTION] [OPTIONS...]
```

**Actions:**
- `view` - View recent logs
- `list` - List all logs
- `export` - Export logs
- `stats` - Show statistics
- `clear` - Clear logs

**Examples:**
```bash
# View recent logs (default 10)
php bahll.php logs view

# View all logs
php bahll.php logs list

# Export logs
php bahll.php logs export

# Show statistics
php bahll.php logs stats

# Clear all logs
php bahll.php logs clear
```

**Help:**
```bash
php bahll.php logs --help
```

---

## Integration Examples

### Using in Shell Scripts

```bash
#!/bin/bash

# Hash input file
FILE_HASH=$(php bahll.php hash sha256 "$(cat /path/to/file)")
echo "SHA-256: $FILE_HASH"

# Generate secure password
PASSWD=$(php bahll.php random password 16)
echo "Generated password: $PASSWD"

# Encrypt sensitive data
ENCRYPTED=$(php bahll.php encrypt aes-256-gcm "sensitive" "key")
echo "Encrypted: $ENCRYPTED"
```

### Using in PHP Applications

```php
<?php
$output = shell_exec('php /path/to/bahll.php hash sha256 "data"');
echo $output;
?>
```

### Using in CI/CD Pipelines

```yaml
# GitHub Actions Example
- name: Generate secure token
  run: php bahll.php random token 32 > token.txt

- name: Hash dependencies
  run: php bahll.php audit hash-file composer.lock sha256 > hash.txt
```

---

## Common Use Cases

### 1. Generate API Key
```bash
php bahll.php random token 32
```

### 2. Hash Password
```bash
php bahll.php hash argon2 "password123" 65536
```

### 3. Encrypt Configuration
```bash
php bahll.php encrypt aes-256-gcm "$(cat config.php)" "master-key"
```

### 4. Generate RSA Keypair
```bash
php bahll.php asymmetric generate rsa-4096
```

### 5. Check System Security
```bash
php bahll.php audit check
```

---

## Error Handling

Semua commands akan menampilkan pesan error jika terjadi masalah:

```bash
$ php bahll.php hash unknown "data"
✗ Unknown hash algorithm: unknown
```

---

## Tips & Best Practices

1. **Always use quoting** - Gunakan quotes untuk data yang mengandung spaces
   ```bash
   php bahll.php hash sha256 "Hello World"  # ✓ Correct
   php bahll.php hash sha256 Hello World    # ✗ Wrong
   ```

2. **Use strong keys** - Untuk encryption, gunakan key yang cukup panjang
   ```bash
   # Good
   php bahll.php encrypt aes-256-gcm "data" "MyVeryLongAndComplexSecretKey123456"
   
   # Poor
   php bahll.php encrypt aes-256-gcm "data" "123"
   ```

3. **Save encrypted data safely** - Simpan output encrypted dalam file
   ```bash
   php bahll.php encrypt aes-256-gcm "secret" "key" > encrypted.txt
   ```

4. **Use environment variables** - Jangan hardcode sensitive data
   ```bash
   php bahll.php encrypt aes-256-gcm "$SECRET_DATA" "$SECRET_KEY"
   ```

5. **Check system status** - Pastikan extensions yang diperlukan terinstall
   ```bash
   php bahll.php audit check
   ```

---

## Version History

- **v1.1** - REST API Server integration
  - REST API with 22 endpoints
  - JWT authentication
  - Rate limiting and audit logging
  - Docker support
  - Full backward compatibility with v1.0

- **v1.0** - Stable release with full CLI and interactive modes
  - All hash algorithms
  - Symmetric encryption/decryption
  - Asymmetric cryptography
  - Key management
  - Encoding/decoding
  - Random generation
  - Audit tools
  - Activity logging

---

## Support

Untuk bantuan lebih lanjut atau melaporkan issue:
- GitHub: https://github.com/BangAguse/Bahll
- Issues: https://github.com/BangAguse/Bahll/issues
