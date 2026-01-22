<?php
declare(strict_types=1);

chdir(__DIR__);

if (getenv('BAHLL_FRESH') !== '1') {
    if (strncasecmp(PHP_OS, 'WIN', 3) !== 0) {
        @exec('reset 2>/dev/null');
        @exec('tput reset 2>/dev/null');
        @exec('stty sane 2>/dev/null');
        echo "\033c";
    } else {
        @system('cls');
    }
    putenv('BAHLL_FRESH=1');
}

$dirs = ['core', 'cli', 'utils', 'plugins', 'storage'];
foreach ($dirs as $d) {
    $p = __DIR__ . DIRECTORY_SEPARATOR . $d;
    if (!is_dir($p)) continue;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p));
    foreach ($it as $f) {
        if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
            require_once $f->getPathname();
        }
    }
}

if (!extension_loaded('openssl') && !extension_loaded('sodium')) {
    fwrite(STDERR, "✖ Rejected by Bahll: Required extensions 'openssl' or 'sodium' not available\n");
    exit(1);
}

$menuClass = '\\Bahll\\CLI\\Menu';
if (!class_exists($menuClass)) {
    fwrite(STDERR, "✖ Rejected by Bahll: CLI classes missing\n");
    exit(1);
}

(new $menuClass())->run();
