<?php
namespace Fuel\Tasks;

class Uriauth
{
    public function __construct()
    {
    }

    public static function run()
    {
        static::help();
    }

    public static function help()
    {
        $output = <<<HELP

Description:
  Generate hash password from string.

Commands:
  php oil refine uriauth:password <string>

HELP;
        \Cli::write($output);
    }

    public static function password_encrypt($password)
    {
        $auth = \Auth::instance();
        $password = $auth->encrypt_password($password);
        $output = <<<EOD

Password : {$password}

EOD;
        \Cli::write($output);
    }

    public static function password_decrypt($password)
    {
        $auth = \Auth::instance();
        $password = $auth->decrypt_password($password);
        $output = <<<EOD

Password : {$password}

EOD;
        \Cli::write($output);
    }
}
