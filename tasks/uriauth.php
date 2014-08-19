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
  Convert hash password.

Commands:
  php oil refine uriauth:password_encrypt <string>
  php oil refine uriauth:password_decrypt <string>

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
