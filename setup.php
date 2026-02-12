<?php
declare(strict_types=1);

chdir(__DIR__);

echo "Bahll setup - preparing environment\n";

$checks = [
    'php' => PHP_VERSION,
    'openssl' => extension_loaded('openssl'),
    'sodium' => extension_loaded('sodium'),
    'hash' => extension_loaded('hash'),
];

echo "\nEnvironment checks:\n";
foreach ($checks as $k => $v) {
    printf(" - %-10s : %s\n", $k, is_bool($v) ? ($v ? 'available' : 'missing') : $v);
}

$missing = [];
if (!$checks['openssl']) $missing[] = 'ext-openssl';
if (!$checks['sodium']) $missing[] = 'ext-sodium';

if (!empty($missing)) {
    echo "\n✖ Missing recommended extensions: " . implode(', ', $missing) . "\n";
    echo "Please install them for full functionality. Example (Debian/Ubuntu):\n";
    echo "  sudo apt-get install php-sodium php-openssl\n";
}

$dirs = ['storage', 'plugins', 'tests'];
foreach ($dirs as $d) {
    if (!is_dir($d)) {
        mkdir($d, 0700, true);
        echo "Created directory: $d\n";
    }
}

$composer = [
    'name' => 'bahll/cryptotool',
    'description' => 'Bahll Cryptography Suite - CLI',
    'type' => 'project',
    'require' => [
        'php' => '^7.4 || ^8.0',
        'ext-openssl' => '*',
    ],
    'autoload' => [
        'psr-4' => [
            'Bahll\\' => '',
        ],
    ],
];
file_put_contents('composer.json', json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "Wrote composer.json (no external packages).\n";

exec('composer --version 2>&1', $out, $rc);
if ($rc === 0) {
    echo "Running composer dump-autoload...\n";
    passthru('composer dump-autoload');
} else {
    echo "Composer not found; skip autoload generation. Install composer to enable autoloading.\n";
}

echo "\nSetup complete. To run Bahll: php bahll.php\n";

function promptYesNo(string $question): bool
{
    echo "$question (y/n): ";
    $handle = fopen('php://stdin', 'r');
    $input = trim(fgets($handle));
    return strtolower($input[0] ?? '') === 'y';
}

echo "\n" . str_repeat('=', 60) . "\n";
echo "OPTIONAL: Install as System Command\n";
echo str_repeat('=', 60) . "\n";
echo "Would you like to install 'bahll' as a system command?\n";
echo "This allows you to run: bahll --help\n";
echo "Instead of: php /path/to/bahll.php --help\n\n";

if (promptYesNo("Install as system command?")) {
    $scriptPath = __DIR__ . '/bahll.php';
    
    echo "\nChoose installation method:\n";
    echo "1) System-wide (requires sudo, available to all users)\n";
    echo "2) Per-user (no sudo, only for \$HOME/bin)\n";
    echo "3) Skip\n";
    echo "Choice (1-3): ";
    
    $handle = fopen('php://stdin', 'r');
    $choice = trim(fgets($handle) ?: '3');
    
    if ($choice === '1') {
        echo "\nSystem-wide installation:\n";
        echo " - Making bahll.php executable...\n";
        exec("chmod +x '$scriptPath'", $out, $rc);
        if ($rc !== 0) {
            echo " ✗ Failed to chmod\n";
        } else {
            echo " ✓ Made executable\n";
        }
        
        echo " - Creating symlink at /usr/local/bin/bahll (requires sudo)...\n";
        exec("sudo ln -sf '$scriptPath' /usr/local/bin/bahll 2>&1", $out, $rc);
        if ($rc === 0) {
            echo " ✓ Successfully installed!\n";
            echo "\n   You can now run: bahll --help\n";
        } else {
            echo " ✗ Failed to create symlink\n";
            echo "   Error: " . implode("\n   ", $out) . "\n";
            echo "\n   You can retry manually:\n";
            echo "   sudo ln -sf '$scriptPath' /usr/local/bin/bahll\n";
        }
    } elseif ($choice === '2') {
        $binDir = getenv('HOME') . '/bin';
        $wrapper = $binDir . '/bahll';
        
        echo "\nPer-user installation:\n";
        echo " - Creating \$HOME/bin directory...\n";
        if (!is_dir($binDir)) {
            mkdir($binDir, 0755, true);
            echo " ✓ Created $binDir\n";
        } else {
            echo " ✓ Directory already exists\n";
        }
        
        echo " - Creating wrapper script...\n";
        $wrapperContent = "#!/bin/sh\nphp '$scriptPath' \"\$@\"\n";
        if (file_put_contents($wrapper, $wrapperContent) !== false) {
            chmod($wrapper, 0755);
            echo " ✓ Created $wrapper\n";
        } else {
            echo " ✗ Failed to create wrapper\n";
        }
        
        echo " - Adding \$HOME/bin to PATH...\n";
        $shellProfile = getenv('HOME') . '/.bashrc';
        if (!file_exists($shellProfile)) {
            $shellProfile = getenv('HOME') . '/.zshrc';
        }
        
        $pathExport = "export PATH=\"\$HOME/bin:\$PATH\"";
        $profileContent = file_get_contents($shellProfile) ?: '';
        
        if (strpos($profileContent, '$HOME/bin') === false) {
            file_put_contents($shellProfile, "\n" . $pathExport . "\n", FILE_APPEND);
            echo " ✓ Updated shell profile: $shellProfile\n";
        } else {
            echo " ✓ \$HOME/bin already in PATH\n";
        }
        
        echo "\n   Installation complete!\n";
        echo "   Please run: source $shellProfile\n";
        echo "   Then: bahll --help\n";
    } else {
        echo "Skipped system command installation.\n";
        echo "You can install later by running:\n";
        echo "  chmod +x $scriptPath\n";
        echo "  sudo ln -sf $scriptPath /usr/local/bin/bahll\n";
    }
} else {
    echo "Skipped system command installation.\n";
    echo "You can install later by running: php setup.php\n";
}
