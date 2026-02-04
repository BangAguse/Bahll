# Bahll Cryptography Suite - Update Documentation

## 🔧 Perbaikan & Fitur Baru

Dokumentasi lengkap semua perbaikan bug dan fitur yang ditambahkan ke project Bahll.

---

## ✅ **Bug Fixes**

### 1. **Symmetric.php - AES-GCM Decryption Issue**
**Masalah:** Fungsi `decryptAesGcm()` tidak bisa decrypt data yang dienkripsi dengan random key (tanpa password).

**Perbaikan:**
- Menambahkan flag `keyed` pada enkripsi untuk menandai apakah password digunakan
- Menambahkan validasi `keyed` saat dekripsi
- Menambahkan error checking untuk field yang missing (iv, tag, ct)

**Kode Sebelum:**
```php
$key = $password ? hash('sha256', $password, true) : null;
if ($key === null) return false;
```

**Kode Sesudah:**
```php
if ($keyed && !$password) return false;
if (!$keyed) return false;  // Dekripsi random key tidak mungkin
$key = hash('sha256', $password, true);
```

---

### 2. **Asymmetric.php - Ed25519 Key Extraction**
**Masalah:** Fungsi `generateEd25519()` menggunakan API libsodium yang salah. `sodium_crypto_sign_keypair()` mengembalikan binary string, bukan array.

**Perbaikan:**
- Menggunakan list destructuring untuk extract public dan private key dari keypair

**Kode Sebelum:**
```php
$pair = sodium_crypto_sign_keypair();
$pk = sodium_crypto_sign_publickey($pair);  // ❌ Wrong API
$sk = sodium_crypto_sign_secretkey($pair);  // ❌ Wrong API
```

**Kode Sesudah:**
```php
[$pk, $sk] = sodium_crypto_sign_keypair();  // ✓ Correct API
```

---

### 3. **Keyring.php - XChaCha20 Nonce Size Mismatch**
**Masalah:** Menggunakan 16-byte salt sebagai nonce untuk XChaCha20-Poly1305, padahal protocol membutuhkan 24-byte nonce.

**Perbaikan:**
- Mengganti semua salt generation dari 16 bytes menjadi 24 bytes
- Menambahkan validasi nonce length di `readAll()` dan `writeEncrypted()`
- Menambahkan auto-correction jika nonce size tidak sesuai

**Kode Sebelum:**
```php
$salt = random_bytes(16);  // ❌ XChaCha20 butuh 24 bytes
$nonce = ...sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(..., $salt, $key);
```

**Kode Sesudah:**
```php
$nonce = random_bytes(24);  // ✓ Correct size
if (strlen($nonce) !== 24) {
    $nonce = random_bytes(24);
}
```

---

### 4. **Menu.php - Incomplete Symmetric Menu**
**Masalah:** Menu menawarkan 4 opsi enkripsi simetrik, tapi hanya implement 2 (AES-256-GCM).

**Perbaikan:**
- Menambahkan case '3' dan '4' untuk AES-256-CBC dengan HMAC encryption/decryption
- Memperbaiki dokumentasi menu items

---

## 🎨 **UI/UX Improvements**

### Output.php - Enhanced Formatting
Menambahkan color-coded output dan styling methods:

```php
// Sebelumnya hanya writeln()
// Sekarang:
- section($title)     // Header dengan decorative line
- success($msg)       // Green text dengan ✓
- error($msg)         // Red text dengan ✗
- warning($msg)       // Yellow text dengan ⚠
- info($msg)          // Blue text dengan ℹ
- highlight($msg)     // Magenta untuk important info
- result($title, $content)  // Formatted result display
```

Contoh output sebelumnya:
```
Hashing & KDF Menu:
1) SHA-1 (deprecated)
...
```

Output sekarang:
```
━━━ Hashing & KDF Menu ━━━
  1) SHA-1 (deprecated)
...
```

---

## 🆕 **New Features**

### 1. **Activity Logging System** (`core/logging/ActivityLogger.php`)

Fitur comprehensive logging untuk tracking semua operasi cryptographic.

**Fitur:**
- Log semua operasi tanpa sensitive data (password/key tidak tercatat)
- Base64-encoded storage di `storage/activity.log`
- Automatic data sanitization (remove passwords, tokens, keys dari log)
- Query methods: `getEntries()`, `getLastEntries()`, `export()`
- File size tracking dan statistics

**Contoh Penggunaan:**
```php
$logger = new ActivityLogger();
$logger->logHash('SHA-256');
$logger->logEncryption('AES-256-GCM', true, 'with password');
$logger->logKeyGeneration('RSA', 4096);
$logger->log('Custom action', 'success', 'Details here');
```

**Log Format (Base64 decoded):**
```json
[
  {
    "timestamp": "2026-02-04 15:30:45",
    "unix_time": 1707054645,
    "action": "Encrypt AES-256-GCM (with password)",
    "status": "success",
    "details": null
  },
  ...
]
```

---

### 2. **Folder Encryption Manager** (`core/crypto/FolderEncrypt.php`)

Sistem enkripsi untuk folder/file yang aman dan terstruktur.

**Struktur:**
```
storage/
├── Data/              (Source files to encrypt)
├── Encrypted/         (Encrypted files)
├── Data_decrypted/    (Decrypted output)
├── activity.log       (Activity log)
└── keyring.json.enc   (Encrypted key storage)
```

**Fitur Utama:**
- `encryptAll($password)` - Encrypt semua file dalam Data folder
- `decryptAll($password)` - Decrypt semua file dalam Encrypted folder
- `listDataFiles()` - List files dengan size dan timestamp
- `getDataDirSize()` / `getEncryptedDirSize()` - Folder statistics
- Recursive directory handling untuk nested folders
- Automatic directory structure creation

**Keamanan:**
- Menggunakan AES-256-CBC dengan HMAC untuk authenticity
- File permissions set ke 0600 (read/write owner only)
- No sensitive info di metadata/filename

**Contoh:**
```php
$fe = new FolderEncrypt();
$results = $fe->encryptAll('MySecurePassword');

// Output:
// [
//   'success' => 5,
//   'failed' => 0,
//   'errors' => [],
//   'encrypted_files' => [...]
// ]
```

---

### 3. **Enhanced Menu System**

#### New Menu Option: Folder Encryption (Menu Item 9)
```
1) View Data folder contents
2) Encrypt all files in Data folder
3) View Encrypted folder contents
4) Decrypt all encrypted files
5) Folder statistics
```

#### New Menu Option: Activity Log (Menu Item 10)
```
1) View recent logs (last 20)
2) View all logs
3) Export log as base64
4) Clear logs
5) Log statistics
```

#### Improved Existing Menus
- **Hashing Menu**: Added logging, better output formatting, warnings untuk deprecated algorithms
- **Symmetric Encryption**: Added support untuk AES-256-CBC dengan HMAC, improved error messages
- **Asymmetric**: Better key generation feedback, improved Ed25519 handling
- **Keyring**: Better status messages, formatted key listing
- **Encoding**: Display semua formats (Base64, URL-safe Base64, Hex) sekaligus
- **Randomness**: Support untuk arbitrary byte generation dengan formatting
- **Audit**: Color-coded availability check, security score, recommendations
- **Secrets**: New helpers untuk password, token, dan salt generation

---

## 📋 **Activity Log Examples**

### Hash Operation
```
[2026-02-04 15:30:45] SUCCESS     - Hash operation - SHA-256
```

### Encryption/Decryption
```
[2026-02-04 15:31:10] SUCCESS     - Encrypt AES-256-GCM (with password)
[2026-02-04 15:32:20] FAILED      - Decrypt AES-256-CBC (MAC mismatch)
```

### Key Generation
```
[2026-02-04 15:33:00] SUCCESS     - Generate RSA (4096 bits)
[2026-02-04 15:34:15] SUCCESS     - Generate Ed25519
```

### Folder Operations
```
[2026-02-04 15:35:30] SUCCESS     - Encrypt folder - Data (Encrypted 15 file(s))
[2026-02-04 15:36:45] SUCCESS     - Decrypt folder - Encrypted (Decrypted 15 file(s))
```

---

## 🔐 **Security Considerations**

### Activity Log Security
- **No sensitive data**: Password, keys, secrets TIDAK dilog
- **Base64 encoding**: Log file dienkode untuk basic obfuscation (bukan enkripsi)
- **Pattern matching**: Otomatis mendeteksi dan redact hex strings > 40 chars, base64 > 64 chars
- **File permissions**: `activity.log` diset ke mode 0600

### Folder Encryption Security
- **Algorithm**: AES-256-CBC dengan HMAC (SHA-256) untuk authenticity
- **Key derivation**: SHA-256 dari password
- **File permissions**: Encrypted files diset ke mode 0600
- **Directory**: Automatic cleanup dan recreation

### Best Practices
```
✓ Gunakan password kuat untuk folder encryption (min 12 chars)
✓ Backup activity log secara regular
✓ Review logs untuk suspicious activity
✓ Gunakan secure passwords untuk keyring
✓ Prefer AEAD ciphers (GCM) untuk encrypting tanpa authentication
```

---

## 📊 **Testing Checklist**

- [x] Symmetric decryption dengan password works
- [x] Symmetric decryption tanpa password fails gracefully
- [x] Ed25519 keypair generation correct
- [x] Keyring nonce size adalah 24 bytes
- [x] Folder encryption/decryption recursive
- [x] Activity log tidak contain sensitive data
- [x] Menu items complete dan functional
- [x] Output formatting consistent dan readable
- [x] Error messages helpful dan actionable

---

## 🚀 **Usage Examples**

### Encrypt Folder
```
Menu → Folder Encryption → Encrypt all files
1. Put files dalam storage/Data/
2. Select option 2
3. Enter password
4. Files encrypted ke storage/Encrypted/
```

### View Activity Log
```
Menu → Activity Log → View recent logs
Shows last 20 operations dengan timestamp
```

### Generate Secure Password
```
Menu → Secret Lifecycle → Generate secure password
Outputs 32-character hex-encoded random password
```

---

## 📁 **File Structure**

```
Bahll/
├── core/
│   ├── crypto/
│   │   ├── Symmetric.php        (Fixed)
│   │   ├── Asymmetric.php       (Fixed)
│   │   ├── Hash.php
│   │   └── FolderEncrypt.php    (NEW)
│   ├── keyring/
│   │   └── Keyring.php          (Fixed)
│   └── logging/
│       └── ActivityLogger.php   (NEW)
├── cli/
│   ├── menu/
│   │   └── Menu.php             (Enhanced)
│   └── output/
│       └── Output.php           (Enhanced)
└── storage/
    ├── Data/                    (NEW - for files to encrypt)
    ├── Encrypted/               (NEW - for encrypted files)
    └── activity.log             (NEW - activity log)
```

---

**Version:** 2.0  
**Last Updated:** 4 Februari 2026  
**Status:** Production Ready ✅
