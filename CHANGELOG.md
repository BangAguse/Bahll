# Bahll Cryptography Suite - Changelog

All notable changes to the Bahll project will be documented in this file.

---

## [1.1] - 2026-06-16

### 🎯 **RELEASE HIGHLIGHTS - REST API Integration**

**Bahll v1.1: Enterprise-Ready REST API Server**

Bahll v1.1 introduces a **production-ready REST API server**, enabling seamless integration with web applications, microservices, and cloud platforms. The tool now operates in **three modes**: Interactive CLI, Direct CLI Commands, and REST API.

**What's New:**
- ✅ **22 REST API endpoints** for all cryptographic operations
- ✅ **JWT Authentication** with API key management
- ✅ **Rate Limiting** (100 requests/minute per key)
- ✅ **Audit Logging** with detailed operation tracking
- ✅ **SQLite Database** for persistence (PostgreSQL ready)
- ✅ **Docker Support** with docker-compose configuration
- ✅ **CORS Protection** for web application security
- ✅ Full backward compatibility with v1.0

### ✨ **NEW FEATURES**

#### 1. REST API Server
- Slim Framework 4.12-based lightweight HTTP API
- Endpoints for encryption, decryption, hashing, and key management
- Health checks and status monitoring
- Complete API documentation with examples

#### 2. Authentication & Authorization
- API key generation and management
- JWT tokens with 24-hour expiration
- Secure key hashing (SHA256)
- API key revocation without deletion

#### 3. Rate Limiting & Tracking
- Per-key rate limiting (100 req/min)
- Response headers showing usage statistics
- Automatic window cleanup

#### 4. Audit Logging
- Complete operation history
- Execution time tracking
- Success/failure status
- Error message capture
- Statistics and analytics

#### 5. Docker Support
- Lightweight Alpine PHP 8.1 image
- Docker Compose orchestration
- Health checks built-in
- Easy deployment and scaling

### 📦 **DEPENDENCIES ADDED**
- slim/slim: ^4.12 - HTTP framework
- slim/psr7: ^1.6 - PSR-7 support
- firebase/php-jwt: ^6.9 - JWT handling

### 📚 **DOCUMENTATION**
- `API_DOCUMENTATION.md` - Complete API reference
- `API_QUICKSTART.md` - Quick start guide with examples
- `API_INTEGRATION_SUMMARY.md` - Implementation details

---

## [1.0] - 2026-02-13

### 🎯 **RELEASE HIGHLIGHTS - Major Feature Release**

**Bahll v1.0: From Interactive-Only to Hybrid Dual-Mode Tool**

Bahll v1.0 is a **production-ready milestone** introducing a massive shift in capability: adding **direct CLI command execution** alongside the traditional interactive menu, without any changes to core source code. This version also enables **system-wide executable installation**, making `bahll` a first-class citizen in terminal environments.

**What Changed:**
- ✅ Users can now run crypto operations **without navigating menus**
- ✅ Supports modern **flag-style commands** (`--hash`, `--encrypt`, `--decrypt`, etc.)
- ✅ Can be **installed as a system command** (no `php` prefix needed)
- ✅ Fully **backward compatible** with interactive mode
- ✅ All cryptographic operations are **fully tested and verified**
- ✅ Production-ready code with **cleaned comments** and **zero syntax errors**

### ✨ **NEW FEATURES - Major CLI Overhaul**

#### 1. Dual-Mode Operation (Interactive + Direct CLI)
The same Bahll tool now works in two ways:

**Interactive Mode (Original)**
```bash
php bahll.php                    # Full menu-driven interface
```

**Direct CLI Mode (NEW)**
```bash
# Modern flag-based commands
bahll --hash --algo=sha256 --data="hello"
bahll --encrypt --algo=aes-256-gcm --data=/path/to/file --key=pass
bahll --decrypt --algo=aes-256-gcm --data=/path/to/file.bahll --key=pass
bahll --random --type=bytes --length=32
bahll --bruteforce --path=/path/to/encrypted_folder
```

**Positional Mode (Legacy, Still Supported)**
```bash
php bahll.php hash sha256 "data"
php bahll.php encrypt aes-256-gcm "data" "key"
php bahll.php decrypt aes-256-gcm "blob" "key"
```

#### 2. System Command Installation (Executable Setup)
Bahll can now be installed as a native terminal command:

**System-Wide Installation**
```bash
chmod +x /path/to/Bahll/bahll.php
sudo ln -sf /path/to/Bahll/bahll.php /usr/local/bin/bahll
```

**Per-User Installation (No sudo)**
```bash
mkdir -p "$HOME/bin"
cat > "$HOME/bin/bahll" <<'EOF'
#!/bin/sh
php /path/to/Bahll/bahll.php "$@"
EOF
chmod +x "$HOME/bin/bahll"
```

After installation, use Bahll like any CLI tool:
```bash
bahll --help
bahll --version
bahll --hash --algo=sha256 --data="test"
```

#### 3. Enhanced CLI Features
- **Long-flag Parsing** - Recommended modern style: `--algo=sha256`, `--data=value`
- **File-based Workflows** - Pass file paths → auto-confirmation + optional passphrase
- **Smart Output Naming** - Encrypted: `.bahll`, Decrypted: `.dec` (extracted from original name)
- **Directory Bruteforce** - Safe traversal, ethical confirmation prompt, remote wordlist download
- **Integrated Help** - Install instructions built into `--help` output

#### 4. Menu & Manager Improvements
- **Decryptor Manager** - Advanced decryption with wordlist brute-force (~500 passwords)
- **Keyring Enhancements** - Key removal, improved security handling
- **Storage Restructuring** - Organized encryption workflow directories

### 🔧 **IMPROVEMENTS**

- Enhanced Help menu with detailed module descriptions and examples
- Improved menu text clarity (removed repetitive descriptions)
- Fixed Keyring salt handling for correct libsodium compliance
- AEAD nonce separation from password hashing salt
- **Code cleanup:** All comments removed from 20 PHP files, syntax verified
- **Consistent versioning:** All version references updated to 1.0
- Unified version output across CLI, interactive menu, and info display
- Installation instructions integrated into help system

### 🐛 **BUG FIXES**

- Fixed `sodium_crypto_pwhash` salt length validation
- Fixed XChaCha20-Poly1305 nonce handling in Keyring
- Fixed Audit menu infinite loop
- Fixed Help and Info menus looping behavior
- Fixed file prompt helpers (`askYesNo`, `askOptionalPassphrase`)
- Fixed decrypted file naming to strip `.bahll` extension properly
- Fixed stray code and restored proper method declarations

### 📚 **Documentation Updates**

- README.md: Added comprehensive CLI usage section with examples
- CHANGELOG.md: Detailed release notes for v1.0 milestone
- CLI_DOCUMENTATION.md: Complete CLI reference and examples
- CLI_QUICK_REFERENCE.md: Quick lookup for common commands

---

## [0.2.1] - 2026-02-05

### 🔴 **CRITICAL BUG FIXES**

#### Fixed: Symmetric Encryption AES-GCM Decryption
- **Issue:** Could not decrypt data encrypted with random key (no password)
- **Root Cause:** Attempted decryption without proper key tracking
- **Solution:** Added `keyed` flag in encryption payload to track password usage
- **Impact:** All AES-256-GCM operations now fully functional
- **File:** `core/crypto/Symmetric.php`

#### Fixed: Ed25519 Keypair Generation
- **Issue:** Function used wrong libsodium API causing runtime errors
- **Root Cause:** Used `sodium_crypto_sign_publickey/secretkey()` on wrong type
- **Solution:** Implemented proper list destructuring `[$pk, $sk] = sodium_crypto_sign_keypair()`
- **Impact:** Ed25519 key generation now works correctly
- **File:** `core/crypto/Asymmetric.php`

#### Fixed: Keyring XChaCha20 Nonce Size
- **Issue:** Using 16-byte salt as nonce for XChaCha20-Poly1305 (protocol requires 24 bytes)
- **Root Cause:** Incorrect cipher specification implementation
- **Solution:** Updated all nonce generation to 24 bytes + added validation
- **Impact:** Keyring now fully compatible with XChaCha20-Poly1305 AEAD cipher
- **File:** `core/keyring/Keyring.php`

#### Fixed: Symmetric Encryption Menu Incomplete
- **Issue:** Menu offered 4 cipher options but only implemented 2
- **Root Cause:** Missing case statements for AES-CBC with HMAC
- **Solution:** Implemented cases for encryption/decryption with AES-256-CBC
- **Impact:** All symmetric encryption options now functional
- **File:** `cli/menu/Menu.php`

---

### ✨ **NEW FEATURES**

#### 1. Activity Logging System
**File:** `core/logging/ActivityLogger.php`

Comprehensive non-sensitive activity tracking for audit trails.

**Features:**
- ✅ Automatic logging of cryptographic operations
- ✅ Data sanitization (removes sensitive info: passwords, keys, tokens)
- ✅ Base64-encoded storage (`storage/activity.log`)
- ✅ Dedicated logging methods for different operation types:
  - `logHash($algorithm, $status)`
  - `logEncryption($cipher, $success, $mode)`
  - `logDecryption($cipher, $success, $reason)`
  - `logKeyGeneration($keyType, $size)`
  - `logFolderEncryption($path, $fileCount, $success)`
  - `logFolderDecryption($path, $fileCount, $success)`
- ✅ Query methods: `getEntries()`, `getLastEntries($count)`, `export()`
- ✅ Statistics: `count()`, `getFileSize()`, `format()`
- ✅ Management: `clear()`, `save()`

**Security:** 
- Patterns removed: hex strings (>40 chars), base64 (>64 chars)
- File permissions: 0600 (readable by owner only)
- No actual passwords, keys, or sensitive data logged

**Storage Format:** Base64-encoded JSON array

#### 2. Folder Encryption Manager
**File:** `core/crypto/FolderEncrypt.php`

Secure encryption system for entire folder structures.

**Features:**
- ✅ Recursive directory encryption/decryption
- ✅ AES-256-CBC with HMAC-SHA256 authentication
- ✅ Automatic folder structure preservation
- ✅ Methods:
  - `encryptAll($password)` - Encrypt all files in Data folder
  - `decryptAll($password)` - Decrypt all files in Encrypted folder
  - `listDataFiles()` / `listEncryptedFiles()` - List with metadata
  - `getDataDirSize()` / `getEncryptedDirSize()` - Size statistics
- ✅ File metadata tracking: size, modified time
- ✅ Secure file permissions: 0600
- ✅ Directory structure: storage/Data → storage/Encrypted

**Security:**
- Key derivation: SHA-256(password)
- Cipher: AES-256-CBC (OPENSSL_RAW_DATA)
- Authentication: HMAC-SHA256 for integrity verification
- Permissions: Files 0600, Directories 0700

**Supported Operations:**
```php
encryptAll()  → storage/Data/ → storage/Encrypted/
decryptAll()  → storage/Encrypted/ → storage/Data_decrypted/
```

---

### 🎨 **UI/UX IMPROVEMENTS**

#### Enhanced Output Formatting
**File:** `cli/output/Output.php`

New color-coded output methods for better terminal UX.

**New Methods:**
```php
section($title)              // ━━━ Decorative section header ━━━
success($msg)                // ✓ Green success message
error($msg)                  // ✗ Red error message
warning($msg)                // ⚠ Yellow warning message
info($msg)                   // ℹ Blue info message
highlight($msg)              // Magenta for important text
result($title, $content)     // Formatted result display
```

**Visual Improvements:**
- Color-coded status indicators (✓✗⚠ℹ)
- Decorative section separators
- Better visual hierarchy
- Improved readability for long outputs

#### Enhanced Menu System
**File:** `cli/menu/Menu.php`

Completely refactored menu system with new features and better UX.

**Menu Enhancements:**
1. All menus now use `Output::section()` for consistency
2. Better error messages with visual distinction
3. Added logging throughout all operations
4. Improved output formatting for results

**New Menu Options:**
- **Menu Item 9: Folder Encryption** (NEW)
  - View Data folder contents
  - Encrypt all files
  - View Encrypted folder contents
  - Decrypt all files
  - Folder statistics

- **Menu Item 10: Activity Log** (NEW)
  - View recent logs
  - View all logs
  - Export log as base64
  - Clear logs
  - Log statistics

- **Menu Item 8: Secret Lifecycle** (Enhanced)
  - Generate secure password
  - Generate API token
  - Generate cryptographic salt

---

### 🔒 **SECURITY ENHANCEMENTS**

#### Non-Sensitive Logging
- Activity logs contain only operation types, not actual data
- Automatic pattern-matching sanitization
- Base64 encoding for additional obfuscation
- Secure file permissions (0600)

#### Improved Cryptography
- Fixed nonce size in XChaCha20-Poly1305 (24 bytes)
- Proper password-based key derivation
- HMAC verification for data integrity
- Fail-closed error handling

#### Better Key Management
- Ed25519 keypair generation now fully functional
- RSA key size enforcement (≥2048 bits)
- Secure password hashing with bcrypt/Argon2id

---

### 📊 **TESTING & VALIDATION**

#### Syntax Validation
- ✅ All modified files pass PHP syntax check
- ✅ No critical errors or warnings

#### Functional Testing
- ✅ AES-256-GCM encryption/decryption
- ✅ AES-256-CBC with HMAC
- ✅ Ed25519 keypair generation
- ✅ SHA256/SHA512 hashing
- ✅ Activity logger entry tracking
- ✅ Folder encryption setup
- ✅ Keyring 24-byte nonce implementation

#### Files Added for Testing
- `tests/unit-tests.php` - Comprehensive test suite
- `tests/quick-test.php` - Quick validation script

---

### 📝 **DOCUMENTATION UPDATES**

#### New Documentation Files
- `UPDATES.md` - Detailed changelog with code examples
- `IMPLEMENTATION_SUMMARY.md` - Complete implementation guide
- Enhanced `README.md` with new features section

#### Documentation Quality
- Before/after code comparisons
- Usage examples for new features
- Security best practices documented
- File structure diagrams

---

### 🚀 **MIGRATION NOTES**

#### For Existing Users
- **No breaking changes** - All existing functionality preserved
- **Backward compatible** - Old crypto operations still work
- **New features are opt-in** - Existing workflows unaffected

#### Recommended Actions
1. Update to v2.0.0 for critical bug fixes
2. Review new Activity Log menu for audit trail setup
3. Test Folder Encryption for batch file operations
4. Check enhanced output formatting in menus

---

### 🏆 **VERSION METRICS**

| Metric | Value |
|--------|-------|
| Critical Bugs Fixed | 4 |
| New Major Features | 2 |
| Files Modified | 5 |
| Files Created | 4 |
| Lines of Code Added | ~2,500 |
| Test Coverage | Core operations |
| Security Improvements | 5+ |

---

### 📞 **SUPPORT & COMPATIBILITY**

- **PHP Version:** 8.0+
- **Extensions Required:** openssl, sodium
- **Status:** ✅ Production Ready
- **Stability:** Stable

---

## [0.1.0] - 2026-01-22

### Initial Release
- Basic cryptographic operations (hashing, symmetric, asymmetric)
- Interactive CLI menu system
- Keyring key management
- Basic audit features
- Plugin system framework

---

**Last Updated:** 4 Februari 2026  
**Maintainer:** Bahll Development Team  
**License:** MIT
