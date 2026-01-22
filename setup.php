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
