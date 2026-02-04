# Contributing to Bahll

Thank you for your interest in contributing to Bahll! We welcome contributions from the community to make this cryptography toolkit even better.

## How to Contribute

### 1. Fork and Clone
- Fork the repository on GitHub.
- Clone your fork locally: `git clone https://github.com/BangAguse/Bahll.git`

### 2. Set Up Development Environment
```bash
cd bahll
php setup.php
composer install  # if you have Composer
```

### 3. Make Changes
- Follow PSR-12 coding standards.
- Add tests for new features in `tests/`.
- Ensure no syntax errors: `find . -name '*.php' -exec php -l {} \;`
- Test interactively: `php bahll.php`

### 4. Commit and Push
- Use clear, descriptive commit messages.
- Push to your fork.

### 5. Submit a Pull Request
- Open a PR against the main branch.
- Describe your changes and why they're needed.
- Reference any related issues.

## Guidelines

- **Security First**: All crypto-related changes must be reviewed for security implications.
- **Fail-Closed**: Maintain defensive programming practices.
- **No Custom Crypto**: Stick to audited primitives (OpenSSL, Sodium).
- **Documentation**: Update README or docs for new features.
- **Testing**: Add unit tests where possible.

## Reporting Issues

- Use GitHub Issues for bugs or feature requests.
- Provide steps to reproduce, expected vs. actual behavior.
- Include PHP version and extensions.

## Code of Conduct

Be respectful and constructive in all interactions. Let's build secure tools together! 🚀
