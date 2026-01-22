
<div align="center">
  <h1>🔐 Bahll Cryptography Suite</h1>
  <p><em>Authority over your cryptography.</em></p>

  <p>
    <img alt="PHP" src="https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg" />
    <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange.svg" />
    <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" />
    <img alt="Build" src="https://img.shields.io/github/actions/workflow/status/BangAguse/bahll/ci.yml" />
  </p>

  <p>
    <img src="https://media.giphy.com/media/3oEjI6SIIHBdRxXI40/giphy.gif" alt="Bahll" width="480" />
  </p>

  <p>
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#security">Security</a> •
    <a href="#contributing">Contributing</a>
  </p>
</div>

---

## Overview

Bahll is a **terminal-first, defensive cryptography toolkit** designed for developers who need reliable, secure crypto operations without the complexity of custom implementations. Built with PHP, it provides an interactive CLI menu for hashing, encryption, key management, auditing, and more — all while enforcing secure-by-default practices.

Whether you're a developer integrating crypto into your app, a security engineer auditing secrets, or just experimenting with cryptography, Bahll gives you authority over your crypto workflows.

## Features

Bahll offers a comprehensive suite of cryptographic tools, organized into intuitive categories:

### 🔑 Hashing & Key Derivation Functions (KDF)
- **SHA-1** (with deprecation warning)
- **SHA-256, SHA-512**
- **SHA3** (when available)
- **BLAKE2 / BLAKE3** (availability checked)
- **HMAC** for message authentication
- **PBKDF2** for password-based key derivation
- **bcrypt** and **scrypt** for secure password hashing
- **Argon2id** for modern KDF

### 🔒 Symmetric Encryption
- **AES-256-GCM** (default, AEAD mode)
- **AES-CBC** (with HMAC, warned as insecure without AEAD)
- **ChaCha20-Poly1305** (when libsodium available)
- Password-based encryption with automatic IV/salt handling
- File and string encryption/decryption

### 🔐 Asymmetric Cryptography
- **RSA** keypair generation (2048+ bits enforced)
- **Ed25519** for fast, secure signing
- **ECDSA** support
- **X25519** for key exchange
- Sign and verify files/messages
- Key strength validation

### 🗝️ Key Management
- **Encrypted local keyring** with passphrase protection
- Import/export keys securely
- Key rotation and expiration
- List keys with metadata
- Enforce strong passphrase policies

### 📝 Encoding & Obfuscation
- **Base64** (standard and URL-safe)
- **Base32** and **Base58**
- **Hex** encoding/decoding
- **ASCII armor** for PEM-like formats

### 🎲 Randomness & Entropy
- **CSPRNG** token generation
- Secure password generator
- Entropy warnings for weak sources

### 🔍 Crypto Audit & Validation
- Detect weak keys and insecure ciphers
- Warn on deprecated algorithms
- Human-readable security reports
- Score your crypto configurations

### 🔄 Secret Lifecycle Management
- Scan files for secrets
- Mask and rotate secrets
- Revoke keys and enforce expiration
- Pre-commit hooks for security scans

### 🛠️ Dev & CI Utilities
- Pre-commit security scanning
- Artifact signing and verification
- Release integrity checks
- Machine-readable CI output

### 🔌 Plugin System
- Extensible architecture for custom crypto components
- Safe module loading
- Folder-based plugin discovery

## Requirements

- **PHP 7.4+** or **8.0+**
- **OpenSSL extension** (recommended)
- **Sodium extension** (for advanced features like Ed25519, ChaCha20)
- **Composer** (optional, for autoloading)

Bahll will check for these during setup and guide you on missing dependencies.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BangAguse/bahll.git
   cd bahll
   ```

2. **Run the setup script:**
   ```bash
   php setup.php
   ```
   This checks extensions, creates necessary directories, and generates `composer.json`.

3. **Install dependencies (if using Composer):**
   ```bash
   composer install
   ```

That's it! Bahll has no external PHP dependencies — it uses only built-in extensions.

## Usage

Start the interactive CLI:

```bash
php bahll.php
```

You'll see the ASCII banner, then a main menu with categories. Navigate using numbers, enter data as prompted, and results are displayed inline.

### Example: Hash a string
1. Select "1) Hashing & KDF"
2. Choose "2) SHA-256"
3. Enter your string
4. Get the hash output

### Example: Encrypt a file
1. Select "2) Symmetric Encryption"
2. Choose "1) AES-256-GCM encrypt string"
3. Provide plaintext and optional password
4. Receive a base64-encoded blob for decryption

### Example: Generate RSA keys
1. Select "3) Asymmetric Crypto"
2. Choose "1) Generate RSA keypair"
3. Specify key size (2048+)
4. Get PEM-formatted keys

For automation, Bahll can be scripted or integrated into CI pipelines via its CLI output.

## Security

Bahll is built with a **fail-closed, defensive mindset**:
- Rejects weak configurations (e.g., RSA < 2048 bits) with clear error messages like "✖ Rejected by Bahll: Weak cryptographic configuration detected"
- Uses constant-time comparisons for sensitive operations
- Prefers AEAD modes (GCM, Poly1305) over vulnerable CBC
- Warns on deprecated algorithms (SHA-1)
- No custom crypto — only audited, standard primitives

Always verify outputs and use in production with caution. Bahll is alpha software.

## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repo and clone locally
2. Run `php setup.php` and `composer install`
3. Make changes, add tests in `tests/`
4. Run `php bahll.php` to test interactively
5. Submit a PR with a clear description

For bugs or features, open an issue. Follow PHP PSR-12 coding standards.

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for secure development workflows.*
