<?php
namespace Bahll\CLI;

class Input
{
    public static function prompt(string $prompt): string
    {
        echo $prompt . ': ';
        $line = fgets(STDIN);
        return $line === false ? '' : trim($line, "\n\r");
    }
}
