<?php
namespace Bahll\CLI;

class Output
{
    
    private const COLOR_CYAN = "\033[36m";
    private const COLOR_GREEN = "\033[32m";
    private const COLOR_YELLOW = "\033[33m";
    private const COLOR_RED = "\033[31m";
    private const COLOR_MAGENTA = "\033[35m";
    private const COLOR_BLUE = "\033[34m";
    private const COLOR_RESET = "\033[0m";
    private const COLOR_BOLD = "\033[1m";

    public static function banner(): void
    {
        $banner = <<<'BANNER'
        
 ███████████            █████      ████  ████ 
▒▒███▒▒▒▒▒███          ▒▒███      ▒▒███ ▒▒███ 
 ▒███    ▒███  ██████   ▒███████   ▒███  ▒███ 
 ▒██████████  ▒▒▒▒▒███  ▒███▒▒███  ▒███  ▒███ 
 ▒███▒▒▒▒▒███  ███████  ▒███ ▒███  ▒███  ▒███ 
 ▒███    ▒███ ███▒▒███  ▒███ ▒███  ▒███  ▒███ 
 ███████████ ▒▒████████ ████ █████ █████ █████
▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒ 

BANNER;
        echo self::COLOR_CYAN . $banner . self::COLOR_RESET;
        echo self::COLOR_BOLD . "Bahll Cryptography Suite" . self::COLOR_RESET . "\n";
        echo self::COLOR_BLUE . "Authority over your cryptography." . self::COLOR_RESET . "\n\n";
    }

    public static function writeln(string $s): void
    {
        echo $s . PHP_EOL;
    }

    public static function section(string $title): void
    {
        echo "\n" . self::COLOR_BOLD . self::COLOR_CYAN . "━━━ " . $title . " ━━━" . self::COLOR_RESET . "\n";
    }

    public static function success(string $msg): void
    {
        echo self::COLOR_GREEN . "✓ " . $msg . self::COLOR_RESET . "\n";
    }

    public static function error(string $msg): void
    {
        echo self::COLOR_RED . "✗ " . $msg . self::COLOR_RESET . "\n";
    }

    public static function warning(string $msg): void
    {
        echo self::COLOR_YELLOW . "⚠ " . $msg . self::COLOR_RESET . "\n";
    }

    public static function info(string $msg): void
    {
        echo self::COLOR_BLUE . "ℹ " . $msg . self::COLOR_RESET . "\n";
    }

    public static function highlight(string $msg): void
    {
        echo self::COLOR_MAGENTA . $msg . self::COLOR_RESET . "\n";
    }

    public static function menu(array $options): void
    {
        self::section("Menu");
        foreach ($options as $key => $label) {
            printf("  %s%-2s%s) %s\n", self::COLOR_YELLOW, $key, self::COLOR_RESET, $label);
        }
    }

    public static function result(string $title, string $content): void
    {
        echo "\n" . self::COLOR_BOLD . "◆ " . $title . self::COLOR_RESET . "\n";
        echo self::COLOR_GREEN . $content . self::COLOR_RESET . "\n";
    }
}
