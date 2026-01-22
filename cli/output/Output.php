<?php
namespace Bahll\CLI;

class Output
{
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
        echo "\033[36m";
        echo $banner . "\033[0m\n";
        echo "Bahll Cryptography Suite\n";
        echo "Authority over your cryptography.\n\n";
    }

    public static function writeln(string $s): void
    {
        echo $s . PHP_EOL;
    }
}
