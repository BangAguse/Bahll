#!/usr/bin/env php
<?php
declare(strict_types=1);

chdir(__DIR__);


$isInteractiveMode = empty($argv) || (isset($argv[1]) && ($argv[1] === '' || $argv[1] === 'interactive'));
$isVersionMode = isset($argv[1]) && ($argv[1] === '--version' || $argv[1] === '-v' || $argv[1] === 'version');
$isHelpMode = isset($argv[1]) && ($argv[1] === '--help' || $argv[1] === '-h' || $argv[1] === 'help');


if (($isVersionMode || $isHelpMode) && !getenv('BAHLL_FRESH')) {
	putenv('BAHLL_FRESH=1');
}

if (($isInteractiveMode || $isHelpMode) && !getenv('BAHLL_FRESH_SKIP')) {
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


$requiredClasses = [
	'\\Bahll\\CLI\\Menu',
	'\\Bahll\\CLI\\CLIHandler',
];

foreach ($requiredClasses as $class) {
	if (!class_exists($class)) {
		fwrite(STDERR, "✖ Rejected by Bahll: Class $class not found\n");
		exit(1);
	}
}


$handler = new \Bahll\CLI\CLIHandler($argv);
$handler->handle();
