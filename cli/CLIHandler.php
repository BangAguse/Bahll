<?php
namespace Bahll\CLI;

use Bahll\CLI\Menu;
use Bahll\CLI\Output;
use Bahll\Core\Crypto\Symmetric;

class CLIHandler
{
    private array $argv;
    private Menu $menu;

    public function __construct(array $argv)
    {
        $this->argv = $argv;
        $this->menu = new Menu();
    }

    public function handle(): void
    {
        
        array_shift($this->argv);

        
        if (empty($this->argv)) {
            Output::banner();
            $this->menu->run();
            return;
        }

        $command = $this->argv[0] ?? null;

      
      if ($command === '--help' || $command === '-h' || $command === 'help') {
        $this->showHelp();
        return;
      }

      if ($command === '--info' || $command === '-i' || $command === 'version' || $command === '--version') {
        $this->showVersion();
        return;
      }

      
      if (is_string($command) && str_starts_with($command, '--')) {
        $this->handleFlagCommand($command);
        return;
      }

      
      Output::banner();

      
      match ($command) {
        'hash' => $this->handleHash(),
        'encrypt' => $this->handleSymmetricEncrypt(),
        'decrypt' => $this->handleSymmetricDecrypt(),
        'asymmetric' => $this->handleAsymmetric(),
        'keyring' => $this->handleKeyring(),
        'encoding' => $this->handleEncoding(),
        'random' => $this->handleRandom(),
        'audit' => $this->handleAudit(),
        'secrets' => $this->handleSecrets(),
        'encryptor' => $this->handleEncryptor(),
        'decryptor' => $this->handleDecryptor(),
        'logs' => $this->handleLogs(),
        'interactive' => $this->menu->run(),
        default => $this->showCommandNotFound($command),
      };
    }

    private function handleFlagCommand(string $flag): void
    {
      
      [$flags, $positionals] = $this->parseLongFlags($this->argv);

      
      switch ($flag) {
        case '--hash':
          Output::section("Hashing & KDF Commands");
          $algo = $flags['algo'] ?? $flags['algorithm'] ?? $positionals[0] ?? null;
          $data = $flags['data'] ?? $positionals[1] ?? null;
          if (!$algo) { $this->showHashHelp(); return; }
          $this->menu->executeHashCommand($algo, null, $data);
          return;

        case '--encrypt':
          Output::section("Symmetric Encryption");
          $algorithm = $flags['algo'] ?? $flags['algorithm'] ?? $positionals[0] ?? null;
          $plaintext = $flags['data'] ?? $flags['text'] ?? $positionals[1] ?? null;
          $key = $flags['key'] ?? $positionals[2] ?? null;
          if (!$algorithm) { $this->showSymmetricHelp(); return; }
          if (is_string($plaintext) && is_file($plaintext)) {
            $confirm = $this->askYesNo("Encrypt file $plaintext? (Y/n): ");
            if (!$confirm) { Output::writeln("Operation cancelled by user."); return; }
            $pass = $this->askOptionalPassphrase("Enter passphrase (leave empty to skip): ");
            if ($pass !== null && $pass !== '') { $key = $pass; }
            $plain = file_get_contents($plaintext);
            if ($plain === false) { Output::error("Failed to read file: $plaintext"); return; }
            if (strtolower($algorithm) === 'aes-256-gcm') {
              $out = Symmetric::encryptAesGcm($plain, $key ?: null);
            } elseif (strtolower($algorithm) === 'aes-256-cbc') {
              $out = Symmetric::encryptAesCbcWithHmac($plain, $key ?: '');
            } else { Output::error("Unknown algorithm: $algorithm"); return; }
            $outPath = $plaintext . '.bahll';
            if (file_put_contents($outPath, $out) === false) { Output::error("Failed to write encrypted file: $outPath"); return; }
            Output::result('Encrypted File', $outPath);
            return;
          }
          $this->menu->executeSymmetricCommand('encrypt', $algorithm, $plaintext, $key);
          return;

        case '--decrypt':
          Output::section("Symmetric Decryption");
          $algorithm = $flags['algo'] ?? $flags['algorithm'] ?? $positionals[0] ?? null;
          $ciphertext = $flags['data'] ?? $flags['text'] ?? $positionals[1] ?? null;
          $key = $flags['key'] ?? $positionals[2] ?? null;
          if (!$algorithm) { $this->showSymmetricHelp(); return; }
          if (is_string($ciphertext) && is_file($ciphertext)) {
            $confirm = $this->askYesNo("Decrypt file $ciphertext? (Y/n): ");
            if (!$confirm) { Output::writeln("Operation cancelled by user."); return; }
            $pass = $this->askOptionalPassphrase("Enter passphrase (leave empty to skip): ");
            if ($pass !== null && $pass !== '') { $key = $pass; }
            $blob = file_get_contents($ciphertext);
            if ($blob === false) { Output::error("Failed to read file: $ciphertext"); return; }
            if (strtolower($algorithm) === 'aes-256-gcm') {
              $out = Symmetric::decryptAesGcm($blob, $key ?: null);
            } elseif (strtolower($algorithm) === 'aes-256-cbc') {
              $out = Symmetric::decryptAesCbcWithHmac($blob, $key ?: '');
            } else { Output::error("Unknown algorithm: $algorithm"); return; }
            if ($out === false) { Output::error('Decryption failed - wrong password or corrupted data'); return; }
            $outPath = $this->makeDecryptedPath($ciphertext);
            if (file_put_contents($outPath, $out) === false) { Output::error("Failed to write decrypted file: $outPath"); return; }
            Output::result('Decrypted File', $outPath);
            return;
          }
          $this->menu->executeSymmetricCommand('decrypt', $algorithm, $ciphertext, $key);
          return;

        case '--random':
          Output::section("Randomness & Entropy");
          $type = $flags['type'] ?? $positionals[0] ?? null;
          $len = $flags['length'] ?? $flags['len'] ?? $positionals[1] ?? null;
          if (!$type) { $this->showRandomHelp(); return; }
          $this->menu->executeRandomCommand($type, $len);
          return;

        case '--encoding':
        case '--encode':
          Output::section("Encoding & Obfuscation");
          $enc = $flags['type'] ?? $flags['format'] ?? $positionals[0] ?? null;
          $data = $flags['data'] ?? $positionals[1] ?? null;
          if (!$enc) { $this->showEncodingHelp(); return; }
          $this->menu->executeEncodingCommand($enc, $data);
          return;

        case '--audit':
          Output::section("Audit & Validation");
          $action = $flags['action'] ?? $positionals[0] ?? null;
          if (!$action) { $this->showAuditHelp(); return; }
          $this->menu->executeAuditCommand($action, $positionals ? array_slice($positionals,1) : []);
          return;

        case '--asymmetric':
          Output::section("Asymmetric Cryptography");
          $action = $flags['action'] ?? $positionals[0] ?? null;
          if (!$action) { $this->showAsymmetricHelp(); return; }
          $this->menu->executeAsymmetricCommand($action, $positionals ? array_slice($positionals,1) : []);
          return;

        case '--keyring':
          Output::section("Keyring Management");
          $action = $flags['action'] ?? $positionals[0] ?? null;
          if (!$action) { $this->showKeyringHelp(); return; }
          $this->menu->executeKeyringCommand($action, $positionals ? array_slice($positionals,1) : []);
          return;

        case '--bruteforce':
          Output::section("Bruteforce (Directory)");
          $target = $flags['path'] ?? $positionals[0] ?? null;
          if (!$target) { Output::error('Missing target directory for bruteforce'); return; }
          if (!is_dir($target)) { Output::error('Bruteforce target must be a directory'); return; }

          $confirm = $this->askYesNo("Bruteforce target is a directory. Do you confirm you have authorization and this is for ethical use? (Y/n): ");
          if (!$confirm) { Output::writeln('Operation cancelled by user.'); return; }

          
          $wordlistUrl = 'https://raw.githubusercontent.com/BangAguse/Bahll/refs/heads/main/storage/wordlist.txt';
          $tmp = sys_get_temp_dir() . '/bahll_wordlist_' . uniqid() . '.txt';
          $wl = $this->downloadRemoteWordlist($wordlistUrl);
          if ($wl === false) {
            Output::error('Failed to download remote wordlist from ' . $wordlistUrl);
            return;
          }
          file_put_contents($tmp, $wl);

          
          $results = [];
          $files = $this->safeListFiles($target);
          if (empty($files)) { Output::warning('No files found in target directory'); @unlink($tmp); return; }

          $wordlist = file($tmp, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
          if ($wordlist === false || empty($wordlist)) { Output::error('Downloaded wordlist is empty'); @unlink($tmp); return; }

          foreach ($files as $file) {
            $enc = @file_get_contents($file);
            if ($enc === false) continue;
            $enc = trim($enc);
            $found = false;
            $attempts = 0;
            foreach ($wordlist as $pw) {
              $attempts++;
              $dec = \Bahll\Core\Crypto\Symmetric::decryptAesCbcWithHmac($enc, $pw);
              if ($dec === false) {
                $dec = \Bahll\Core\Crypto\Symmetric::decryptAesGcm($enc, $pw);
              }
              if ($dec !== false) {
                $results[basename($file)] = ['password' => $pw, 'attempts' => $attempts];
                Output::success('Password found for ' . basename($file) . ': ' . $pw);
                $found = true;
                break;
              }
            }
            if (!$found) {
              Output::warning('No password found for ' . basename($file));
            }
          }

          $outPath = __DIR__ . '/../../storage/bruteforce_results.json';
          @file_put_contents($outPath, json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
          Output::result('Bruteforce results written', $outPath);
          @unlink($tmp);
          return;

        case '--logs':
          Output::section("Activity Logs");
          $action = $flags['action'] ?? $positionals[0] ?? null;
          if (!$action) { $this->showLogsHelp(); return; }
          $this->menu->executeLogsCommand($action, $positionals ? array_slice($positionals,1) : []);
          return;

        case '--help':
        case '-h':
          $this->showHelp();
          return;

        case '--info':
        case '-i':
        case '--version':
          $this->showVersion();
          return;

        default:
          $this->showCommandNotFound($flag);
          return;
      }
    }

    
    private function parseLongFlags(array $argv): array
    {
      $flags = [];
      $positionals = [];
      
      foreach ($argv as $i => $arg) {
        if ($i === 0) continue; 
        if (!is_string($arg)) continue;
        if (str_starts_with($arg, '--')) {
          
          if (str_contains($arg, '=')) {
            [$name, $val] = explode('=', substr($arg, 2), 2);
            $flags[$name] = $val;
          } else {
            $name = substr($arg, 2);
            
            $nextIdx = $i + 1;
            $next = $argv[$nextIdx] ?? null;
            if (is_string($next) && !str_starts_with($next, '--')) {
              $flags[$name] = $next;
            } else {
              $flags[$name] = true;
            }
          }
        } elseif (str_starts_with($arg, '-')) {
          
          $trim = ltrim($arg, '-');
          if (str_contains($trim, '=')) {
            [$name, $val] = explode('=', $trim, 2);
            $flags[$name] = $val;
          } else {
            $nextIdx = $i + 1;
            $next = $argv[$nextIdx] ?? null;
            if (is_string($next) && !str_starts_with($next, '-')) {
              $flags[$trim] = $next;
            } else {
              $flags[$trim] = true;
            }
          }
        } else {
          $positionals[] = $arg;
        }
      }

      return [$flags, $positionals];
    }

    
    private function safeListFiles(string $dir): array
    {
      $files = [];
      $stack = [$dir];
      while (!empty($stack)) {
        $current = array_pop($stack);
        if (!is_dir($current) || !is_readable($current)) continue;
        $entries = @scandir($current);
        if ($entries === false) continue;
        foreach ($entries as $e) {
          if ($e === '.' || $e === '..') continue;
          $path = $current . DIRECTORY_SEPARATOR . $e;
          if (is_dir($path)) {
            $stack[] = $path;
          } elseif (is_file($path) && is_readable($path)) {
            $files[] = $path;
          }
        }
      }
      return $files;
    }

    
    private function downloadRemoteWordlist(string $url)
    {
      
      $content = @file_get_contents($url);
      if ($content !== false) return $content;

      
      if (function_exists('curl_version')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        $data = curl_exec($ch);
        $err = curl_errno($ch);
        curl_close($ch);
        if ($err === 0 && $data !== false) return $data;
      }

      return false;
    }

    
    private function askYesNo(string $prompt): bool
    {
      if (defined('STDOUT')) {
        fwrite(STDOUT, $prompt);
      } else {
        echo $prompt;
      }
      $handle = fopen('php://stdin', 'r');
      $line = fgets($handle);
      if ($line === false) return false;
      $val = trim($line);
      if ($val === '') return true;
      $c = strtolower($val[0]);
      return in_array($c, ['y','1','t'], true);
    }

    
    private function askOptionalPassphrase(string $prompt): ?string
    {
      if (defined('STDOUT')) {
        fwrite(STDOUT, $prompt);
      } else {
        echo $prompt;
      }
      $handle = fopen('php://stdin', 'r');
      $line = fgets($handle);
      if ($line === false) return null;
      return rtrim($line, "\r\n");
    }

    
    private function makeDecryptedPath(string $cipherPath): string
    {
      if (str_ends_with($cipherPath, '.bahll')) {
        return substr($cipherPath, 0, -6) . '.dec';
      }
      if (str_ends_with($cipherPath, '.enc')) {
        return substr($cipherPath, 0, -4) . '.dec';
      }
      return $cipherPath . '.dec';
    }

    private function handleHash(): void
    {
        Output::section("Hashing & KDF Commands");

        
        array_shift($this->argv);

        $hashType = $this->argv[0] ?? null;
        $data = $this->argv[1] ?? null;

        if (!$hashType || $hashType === '--help' || $hashType === '-h') {
            $this->showHashHelp();
            return;
        }

        $this->menu->executeHashCommand($hashType, null, $data);
    }

    private function handleSymmetricEncrypt(): void
    {
        Output::section("Symmetric Encryption");

        array_shift($this->argv);
        $algorithm = $this->argv[0] ?? null;
        $plaintext = $this->argv[1] ?? null;
        $key = $this->argv[2] ?? null;

        if (!$algorithm || $algorithm === '--help' || $algorithm === '-h') {
            $this->showSymmetricHelp();
            return;
        }

      
      if (is_string($plaintext) && is_file($plaintext)) {
        $confirm = $this->askYesNo("Encrypt file $plaintext? (Y/n): ");
        if (!$confirm) {
          Output::writeln("Operation cancelled by user.");
          return;
        }
        $pass = $this->askOptionalPassphrase("Enter passphrase (leave empty to skip): ");
        if ($pass !== null && $pass !== '') {
          $key = $pass;
        }

        
        $plain = file_get_contents($plaintext);
        if ($plain === false) {
          Output::error("Failed to read file: $plaintext");
          return;
        }

        if (strtolower($algorithm) === 'aes-256-gcm') {
          $out = Symmetric::encryptAesGcm($plain, $key ?: null);
        } elseif (strtolower($algorithm) === 'aes-256-cbc') {
          $out = Symmetric::encryptAesCbcWithHmac($plain, $key ?: '');
        } else {
          Output::error("Unknown algorithm: $algorithm");
          return;
        }

        $outPath = $plaintext . '.bahll';
        $w = file_put_contents($outPath, $out);
        if ($w === false) {
          Output::error("Failed to write encrypted file: $outPath");
          return;
        }
        Output::result('Encrypted File', $outPath);
        return;
      }

      $this->menu->executeSymmetricCommand('encrypt', $algorithm, $plaintext, $key);
    }

    private function handleSymmetricDecrypt(): void
    {
        Output::section("Symmetric Decryption");

        array_shift($this->argv);
        $algorithm = $this->argv[0] ?? null;
        $ciphertext = $this->argv[1] ?? null;
        $key = $this->argv[2] ?? null;

        if (!$algorithm || $algorithm === '--help' || $algorithm === '-h') {
            $this->showSymmetricHelp();
            return;
        }

      
      if (is_string($ciphertext) && is_file($ciphertext)) {
        $confirm = $this->askYesNo("Decrypt file $ciphertext? (Y/n): ");
        if (!$confirm) {
          Output::writeln("Operation cancelled by user.");
          return;
        }
        $pass = $this->askOptionalPassphrase("Enter passphrase (leave empty to skip): ");
        if ($pass !== null && $pass !== '') {
          $key = $pass;
        }

        
        $blob = file_get_contents($ciphertext);
        if ($blob === false) {
          Output::error("Failed to read file: $ciphertext");
          return;
        }

        if (strtolower($algorithm) === 'aes-256-gcm') {
          $out = Symmetric::decryptAesGcm($blob, $key ?: null);
        } elseif (strtolower($algorithm) === 'aes-256-cbc') {
          $out = Symmetric::decryptAesCbcWithHmac($blob, $key ?: '');
        } else {
          Output::error("Unknown algorithm: $algorithm");
          return;
        }

        if ($out === false) {
          Output::error('Decryption failed - wrong password or corrupted data');
          return;
        }

        $outPath = $this->makeDecryptedPath($ciphertext);
        $w = file_put_contents($outPath, $out);
        if ($w === false) {
          Output::error("Failed to write decrypted file: $outPath");
          return;
        }
        Output::result('Decrypted File', $outPath);
        return;
      }

      $this->menu->executeSymmetricCommand('decrypt', $algorithm, $ciphertext, $key);
    }

    private function handleAsymmetric(): void
    {
        Output::section("Asymmetric Cryptography");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showAsymmetricHelp();
            return;
        }

        $this->menu->executeAsymmetricCommand($action, array_slice($this->argv, 1));
    }

    private function handleKeyring(): void
    {
        Output::section("Keyring Management");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showKeyringHelp();
            return;
        }

        $this->menu->executeKeyringCommand($action, array_slice($this->argv, 1));
    }

    private function handleEncoding(): void
    {
        Output::section("Encoding & Obfuscation");

        array_shift($this->argv);
        $encoding = $this->argv[0] ?? null;
        $data = $this->argv[1] ?? null;

        if (!$encoding || $encoding === '--help' || $encoding === '-h') {
            $this->showEncodingHelp();
            return;
        }

        $this->menu->executeEncodingCommand($encoding, $data);
    }

    private function handleRandom(): void
    {
        Output::section("Randomness & Entropy");

        array_shift($this->argv);
        $type = $this->argv[0] ?? null;
        $length = $this->argv[1] ?? null;

        if (!$type || $type === '--help' || $type === '-h') {
            $this->showRandomHelp();
            return;
        }

        $this->menu->executeRandomCommand($type, $length);
    }

    private function handleAudit(): void
    {
        Output::section("Audit & Validation");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showAuditHelp();
            return;
        }

        $this->menu->executeAuditCommand($action, array_slice($this->argv, 1));
    }

    private function handleSecrets(): void
    {
        Output::section("Secret Lifecycle");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showSecretsHelp();
            return;
        }

        $this->menu->executeSecretsCommand($action, array_slice($this->argv, 1));
    }

        private function handleEncryptor(): void
        {
          Output::section("Encryptor Manager");

          array_shift($this->argv);
          $action = $this->argv[0] ?? null;

          if (!$action || $action === '--help' || $action === '-h') {
            $this->showEncryptorHelp();
            return;
          }

          $this->menu->executeEncryptorCommand($action, array_slice($this->argv, 1));
        }

    private function handleDecryptor(): void
    {
        Output::section("Decryptor Manager");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showDecryptorHelp();
            return;
        }

        $this->menu->executeDecryptorCommand($action, array_slice($this->argv, 1));
    }

    private function handleLogs(): void
    {
        Output::section("Activity Logs");

        array_shift($this->argv);
        $action = $this->argv[0] ?? null;

        if (!$action || $action === '--help' || $action === '-h') {
            $this->showLogsHelp();
            return;
        }

        $this->menu->executeLogsCommand($action, array_slice($this->argv, 1));
    }

    private function showHelp(): void
    {
        Output::banner();
        Output::section("Bahll — Quick CLI Help");
        echo <<<'HELP'
Usage (overview):
  php bahll.php [positional-command] [args...]
  php bahll.php --<command> [--option=value] [positional...]

Core examples (copy & paste):
  # Hash (flag)
  php bahll.php --hash --algo=sha256 --data="Hello World"

  # Hash (positional)
  php bahll.php hash sha256 "Hello World"

  # Encrypt a file (prompts confirmation + optional passphrase)
  php bahll.php --encrypt --algo=aes-256-gcm --data=/path/to/file.txt

  # Decrypt a file (will write <file>.dec)
  php bahll.php --decrypt --algo=aes-256-gcm --data=/path/to/file.txt.bahll

  # Generate random bytes
  php bahll.php --random --type=bytes --length=32

  # Bruteforce a directory (ethical confirmation required)
  php bahll.php --bruteforce --path=/path/to/encrypted_folder
          $outPath = $this->makeDecryptedPath($plaintext);
Flags (long-form preferred):
  --hash        --algo=ALGO --data=VALUE        Hashes / KDFs
  --encrypt     --algo=ALGO --data=FILE_OR_TEXT --key=KEY
  --decrypt     --algo=ALGO --data=FILE_OR_TEXT --key=KEY
  --random      --type=TYPE --length=N          Random data
  --encoding    --type=TYPE --data=VALUE        Encode/decode helpers
  --asymmetric  --action=ACTION [options]       Asymmetric ops
  --keyring     --action=ACTION [options]       Keyring management
  --bruteforce  --path=DIR                      Directory-only bruteforce

Short aliases are reserved for help/info only:
  -h, --help     Show this help
  -i, --info     Show version & author

Tips:
  - For file workflows: pass the file path to --data; Bahll will ask
    for confirmation and an optional passphrase (press Enter to skip).
  - Encrypted files are written with a `.bahll` suffix; decrypted
    outputs are written with a `.dec` suffix.
  - Use `php bahll.php <command> --help` for command-specific details.

  Full docs: CLI_DOCUMENTATION.md or https://github.com/BangAguse/Bahll
HELP;
  Output::writeln("");
  $this->showInstallHint();
    }

    
    private function showInstallHint(): void
    {
        Output::section("Quick Install (run once)");
        echo <<<'HINT'
Install system-wide (recommended):
  # make script executable and symlink (requires sudo)
  chmod +x /path/to/Bahll/bahll.php
  sudo ln -sf /path/to/Bahll/bahll.php /usr/local/bin/bahll

Per-user (no sudo):
  mkdir -p "$HOME/bin"
  printf '#!/bin/sh\nphp /path/to/Bahll/bahll.php "$@"\n' > $HOME/bin/bahll
  chmod +x $HOME/bin/bahll

After install you can run: bahll --help
HINT;
        Output::writeln("");
    }

    private function showHashHelp(): void
    {
        echo <<<'HELP'
Hash & Key Derivation Functions - Detailed Help

SUBCOMMANDS:
  sha1 [data]             Hash using SHA-1
  sha256 [data]           Hash using SHA-256
  sha512 [data]           Hash using SHA-512
  sha3 [data]             Hash using SHA3-512
  blake2 [data]           Hash using BLAKE2 (512-bit)
  blake3 [data]           Hash using BLAKE3
  hmac [algorithm] [data] [key]  HMAC with specified algorithm
  pbkdf2 [data] [salt] [rounds]  PBKDF2 Key Derivation
  bcrypt [data] [cost]    bcrypt Password Hashing
  argon2 [data] [memory]  Argon2 Password Hashing
  scrypt [data] [n]       scrypt Key Derivation

EXAMPLES:
  # SHA-256 hash
  php bahll.php hash sha256 "Hello World"

  # HMAC-SHA256
  php bahll.php hash hmac sha256 "Hello World" "secret-key"

  # PBKDF2
  php bahll.php hash pbkdf2 "password" "salt123" "100000"

  # Argon2 hashing
  php bahll.php hash argon2 "mypassword" "65536"

OPTIONS:
  All hash operations support:
  --raw               Output raw binary data instead of hex
  --compare [hash]    Compare against existing hash
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showSymmetricHelp(): void
    {
        echo <<<'HELP'
Symmetric Encryption - Quick Help

Supported algorithms (examples):
  aes-256-gcm    Recommended for modern use (AEAD)
  aes-256-cbc    Legacy with HMAC (supported)

Usage (flag-style preferred):
  php bahll.php --encrypt --algo=aes-256-gcm --data="/path/to/file" [--key="passphrase"]
  php bahll.php --decrypt --algo=aes-256-gcm --data="/path/to/file.bahll" [--key="passphrase"]

Usage (positional):
  php bahll.php encrypt aes-256-gcm "/path/to/file" "optional-key"
  php bahll.php decrypt aes-256-gcm "/path/to/file.bahll" "optional-key"

File workflow behavior:
  - If `--data` points to a readable file, Bahll will prompt:
      "Encrypt file /path/to/file? (Y/n): " or
      "Decrypt file /path/to/file.bahll? (Y/n): "
  - After confirmation you may enter an optional passphrase (press Enter to skip).
  - Encrypted files are written as: <file>.bahll
  - Decrypted files are written as: <file>.dec

Examples:
  # Encrypt a local file (prompt + optional passphrase)
  php bahll.php --encrypt --algo=aes-256-gcm --data=/home/user/secret.txt

  # Decrypt and write output to .dec
  php bahll.php --decrypt --algo=aes-256-gcm --data=/home/user/secret.txt.bahll

Notes:
  - Prefer `aes-256-gcm` when possible. If you must use CBC, supply a key.
  - Use `--key` or positional key argument to provide a passphrase/key.
  - For programmatic usage (no prompts), supply file path and `--key`.

For more details on other commands, run:
  php bahll.php --help
  php bahll.php encrypt --help
HELP;
        Output::writeln("");
    }

    private function showAsymmetricHelp(): void
    {
        echo <<<'HELP'
Asymmetric Cryptography - Detailed Help

ACTIONS:
  generate            Generate new key pair
  encrypt [action]    Encrypt with public key
  decrypt [action]    Decrypt with private key
  sign [action]       Create digital signature
  verify [action]     Verify digital signature

ALGORITHMS:
  rsa-2048            RSA (2048-bit)
  rsa-4096            RSA (4096-bit)
  ecc-p256            ECC Elliptic Curve P-256
  ecc-p384            ECC Elliptic Curve P-384
  ecc-p521            ECC Elliptic Curve P-521

EXAMPLES:
  # Generate RSA-4096 key pair
  php bahll.php asymmetric generate rsa-4096

  # Encrypt with public key
  php bahll.php asymmetric encrypt rsa-2048 "message" "[public-key]"

  # Sign data with private key
  php bahll.php asymmetric sign rsa-2048 "data" "[private-key]"

  # Verify signature
  php bahll.php asymmetric verify rsa-2048 "[signature]" "[public-key]"

OPTIONS:
  --format [format]   Key format (PEM, DER, JWK)
  --armor             Export in ASCII armored format
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showKeyringHelp(): void
    {
        echo <<<'HELP'
Keyring Management - Detailed Help

ACTIONS:
  create              Create new keyring
  list                List all keys in keyring
  add [name]          Add new key to keyring
  remove [name]       Remove key from keyring
  get [name]          Retrieve specific key
  export [name]       Export key
  import [name]       Import key from file
  verify [name]       Verify key integrity
  rotate [name]       Rotate key material
  backup              Backup entire keyring
  restore [file]      Restore from backup

EXAMPLES:
  # Create new keyring
  php bahll.php keyring create

  # Add new key
  php bahll.php keyring add "my-api-key"

  # List all keys
  php bahll.php keyring list

  # Export key
  php bahll.php keyring export "my-api-key"

  # Backup keyring
  php bahll.php keyring backup

OPTIONS:
  --type [type]       Key type (symmetric, rsa, ecc, hmac)
  --encrypt           Encrypt key storage
  --format [format]   Export format (PEM, DER, JSON)
  --help              Show this help message

FEATURES:
  - Secure key storage
  - Encryption at rest
  - Key rotation support
  - Metadata management
  - Backup & restore

HELP;
        Output::writeln("");
    }

    private function showEncodingHelp(): void
    {
        echo <<<'HELP'
Encoding & Obfuscation - Detailed Help

ENCODINGS:
  base64              Base64 Encoding/Decoding
  base32              Base32 Encoding/Decoding
  hex                 Hexadecimal Encoding/Decoding
  url                 URL-Safe Encoding
  html                HTML Entity Encoding
  json                JSON Encoding/Decoding
  morse               Morse Code Encoding
  rot13               ROT13 Cipher
  atbash              Atbash Substitution Cipher
  ascii85             ASCII85 Encoding

EXAMPLES:
  # Base64 encode
  php bahll.php encoding base64 "Hello World"

  # Base64 decode
  php bahll.php encoding base64 "[base64-string]" --decode

  # Hex encode
  php bahll.php encoding hex "data"

  # URL-safe encoding
  php bahll.php encoding url "path with spaces"

OPTIONS:
  --decode            Decode instead of encode
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showRandomHelp(): void
    {
        echo <<<'HELP'
Randomness & Entropy - Detailed Help

TYPES:
  bytes               Generate random bytes
  int                 Generate random integer
  string              Generate random string
  uuid                Generate UUID (v1, v4, v5)
  password            Generate secure password
  token               Generate secure token
  nonce               Generate nonce
  hex                 Generate random hex string

EXAMPLES:
  # Generate 32 random bytes
  php bahll.php random bytes 32

  # Generate random integer (0-100)
  php bahll.php random int 0 100

  # Generate random string (length 20)
  php bahll.php random string 20

  # Generate UUID v4
  php bahll.php random uuid v4

  # Generate secure password
  php bahll.php random password 16

OPTIONS:
  --format [fmt]      Output format (hex, base64, raw)
  --urlencode         URL-encode output
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showAuditHelp(): void
    {
        echo <<<'HELP'
Audit & Validation - Detailed Help

ACTIONS:
  check               Check system security
  validate [file]     Validate file integrity
  test [algo]         Test algorithm performance
  benchmark [algo]    Benchmark operations
  report              Generate security report
  hash-file [file]    Hash file contents
  verify-file [file]  Verify file signature

EXAMPLES:
  # Security system check
  php bahll.php audit check

  # Validate file integrity
  php bahll.php audit validate "/path/to/file"

  # Benchmark AES-256
  php bahll.php audit benchmark aes-256

  # Hash file
  php bahll.php audit hash-file "/path/to/file" --algorithm sha256

OPTIONS:
  --algorithm [algo]  Specify algorithm
  --iterations [n]    Number of iterations
  --verbose           Show detailed output
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showSecretsHelp(): void
    {
        echo <<<'HELP'
Secret Lifecycle Management - Detailed Help

ACTIONS:
  store [name]        Store secret securely
  retrieve [name]     Retrieve secret
  list                List all stored secrets
  delete [name]       Delete secret
  rotate [name]       Rotate secret
  export [name]       Export secret with wrapping
  import [file]       Import secret from file
  secure-wipe [name]  Securely wipe secret

EXAMPLES:
  # Store new secret
  php bahll.php secrets store "api-key"

  # Retrieve secret
  php bahll.php secrets retrieve "api-key"

  # List all secrets
  php bahll.php secrets list

  # Rotate secret
  php bahll.php secrets rotate "api-key"

  # Securely wipe secret
  php bahll.php secrets secure-wipe "api-key"

OPTIONS:
  --encrypt           Encrypt stored secret
  --ttl [seconds]     Time-to-live for secret
  --usage [count]     Max usage count
  --help              Show this help message

FEATURES:
  - Secure storage
  - TTL support
  - Usage tracking
  - Secure wipe
  - Audit logging

HELP;
        Output::writeln("");
    }

    private function showEncryptorHelp(): void
    {
        echo <<<'HELP'
Encryptor Manager - Detailed Help

ACTIONS:
  encrypt [path]      Encrypt file or folder
  view                View encrypted contents
  list                List encrypted items
  status              Show encryption status
  export [path]       Export encrypted data

EXAMPLES:
  # Encrypt a folder
  php bahll.php encryptor encrypt "/path/to/folder"

  # View encrypted contents
  php bahll.php encryptor view

  # List encrypted items
  php bahll.php encryptor list

  # Check encryption status
  php bahll.php encryptor status

OPTIONS:
  --algorithm [algo]  Encryption algorithm
  --key [key]         Encryption key
  --passphrase        Use passphrase instead of key
  --recursive         Encrypt recursively
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showDecryptorHelp(): void
    {
        echo <<<'HELP'
Decryptor Manager - Detailed Help

ACTIONS:
  decrypt [path]      Decrypt file or folder
  bruteforce [path]   Attempt password bruteforce
  view                View decrypted contents
  list                List decrypted items
  status              Show decryption status

EXAMPLES:
  # Decrypt a file
  php bahll.php decryptor decrypt "/path/to/encrypted-file"

  # View decrypted contents
  php bahll.php decryptor view

  # List decrypted items
  php bahll.php decryptor list

  # Bruteforce attempt
  php bahll.php --bruteforce --path="/path/to/encrypted_folder"

Note:
  - The `--bruteforce` flag requires a directory (not a single file).
  - Bahll will prompt for ethical confirmation before proceeding and will use the
    remote wordlist hosted at:
    https://raw.githubusercontent.com/BangAguse/Bahll/refs/heads/main/storage/wordlist.txt

OPTIONS:
  --algorithm [algo]  Decryption algorithm
  --key [key]         Decryption key
  --passphrase        Use passphrase
  --wordlist [file]   Wordlist for bruteforce
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showLogsHelp(): void
    {
        echo <<<'HELP'
Activity Logs - Detailed Help

ACTIONS:
  view                View recent logs
  list                List all logs
  export              Export logs to file
  clear               Clear all logs
  stats               Show log statistics
  filter [type]       Filter logs by type

EXAMPLES:
  # View recent logs
  php bahll.php logs view

  # View all logs
  php bahll.php logs list

  # Export logs to file
  php bahll.php logs export

  # View statistics
  php bahll.php logs stats

  # Filter by activity type
  php bahll.php logs filter "encryption"

OPTIONS:
  --count [n]         Number of entries to show
  --format [fmt]      Output format (json, csv, text)
  --since [date]      Show logs since date
  --help              Show this help message

HELP;
        Output::writeln("");
    }

    private function showVersion(): void
    {
        Output::banner();
        Output::writeln("Bahll Cryptography Suite v1.0.0");
        Output::writeln("PHP Version: " . PHP_VERSION);
        Output::writeln("OpenSSL: " . (extension_loaded('openssl') ? 'Enabled' : 'Disabled'));
        Output::writeln("Sodium: " . (extension_loaded('sodium') ? 'Enabled' : 'Disabled'));
      Output::writeln("Author: Muh. Agus Tri Ananda (<https://github.com/BangAguse>)");
        Output::writeln("");
    }

    private function showCommandNotFound(string $command): void
    {
        Output::error("Command not found: $command");
        Output::writeln("\nRun 'php bahll.php --help' for usage information.");
    }
}
