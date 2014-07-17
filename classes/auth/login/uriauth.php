<?php
namespace Auth;

class UriUserUpdateException extends \FuelException {}

class UriUserWrongPassword extends \FuelException {}

class Auth_Login_UriAuth extends \Auth_Login_Driver
{

    protected $config = array(
        'drivers' => array(
            'group' => array('UriGroup'),
            'acl'   => array('UriAcl'),
        ),
    );

    protected $user = null;

    protected static $prefix = null;

    protected static $publish = false;

    public static function _init()
    {
        \Config::load('uriauth', true, true, true);
        static::_init_prefix();
    }

    private static function _init_prefix()
    {
        static::$prefix = \Config::get('uriauth.default_prefix');
        static::$publish = \Config::get('uriauth.publish_unprefixed');
        if ( ! ($request = \Request::active())) return;
        $segments = $request->uri->get_segments();
        if (empty($segments) or ! is_array($segments)) return;
        if ( ! array_key_exists($segments[0], \Config::get('uriauth.prefixes', array()))) return;
        static::$prefix = $segments[0];
        static::$publish = false;
    }

    protected function perform_check()
    {
        $this->user = \Session::get('auth');
        if (isset($this->user[static::$prefix][\Config::get('uriauth.prefixes.'.static::$prefix.'.name_post_key', 'name')])) {
            return true;
        }

        $this->user[static::$prefix] = null;
        \Session::set('auth', $this->user);

        return false;
    }

    public function validate_user($user = null)
    {
        if (empty($user[\Config::get('uriauth.prefixes.'.static::$prefix.'.name_post_key', 'name')])) return;
        if (empty($user[\Config::get('uriauth.prefixes.'.static::$prefix.'.password_post_key', 'password')])) return;
        return $user;
    }

    public function login($user = null)
    {
        if ($user instanceof \Orm\Model) $user = $user->to_array();

        if ( ! ($this->user[static::$prefix] = $this->validate_user($user)))
        {
            $this->user[static::$prefix] = null;
            \Session::set('auth', $this->user);
            return false;
        }

        \Session::instance()->rotate();
        \Session::set('auth', $this->user);
        return true;
    }

    public function logout()
    {
        $this->user[static::$prefix] = null;
        \Session::set('auth', $this->user);
        return true;
    }

    public function get_user_id()
    {
        return false;
    }

    public function get_groups()
    {
        if ( ! is_array($this->user)) $this->user = array();
        $groups = array_keys(array_filter($this->user, create_function(
            '$user',
            'return ! empty($user);'
        )));

        if (empty($groups)) $groups = array('uriauth_guest');

        return array(array('UriGroup', $groups));
    }

    public function get_email()
    {
        return false;
    }

    public function get_screen_name()
    {
        return false;
    }

    public function has_access($condition, $driver = null, $user = null)
    {
        if (is_null($user))
        {
            $groups = $this->get_groups();
            $user = reset($groups);
        }
        return parent::has_access($condition, $driver, $user);
    }

    public function guest_login()
    {
        return true;
    }

    public function encrypt_password($password)
    {
        return \Crypt::encode($password);
    }

    public function decrypt_password($password)
    {
        return \Crypt::decode($password);
    }

    public function login_uri()
    {
        return \Config::get('uriauth.prefixes.'.static::$prefix.'.login_uri', '/');
    }

    public function get_prefix()
    {
        return static::$prefix;
    }

    public function is_publish()
    {
        return static::$publish;
    }

}
