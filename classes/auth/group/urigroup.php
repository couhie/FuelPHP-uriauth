<?php
namespace Auth;

class Auth_Group_UriGroup extends \Auth_Group_Driver
{

    public static $_valid_groups = array();

    public static function _init()
    {
        static::$_valid_groups = array_keys(\Config::get('uriauth.prefixes', array()));
    }

    protected $config = array(
        'drivers' => array('acl' => array('UriAcl'))
    );

    public function member($group, $user = null)
    {
        if ( ! is_array($group)) $group = array($group);
        $roles = array_intersect($group, static::$_valid_groups);
        if (empty($roles)) return false;

        if ($user === null)
        {
            $groups = \Auth::instance()->get_groups();
        }
        else
        {
            $groups = \Auth::instance($user[0])->get_groups();
        }

        if ( ! is_array($groups[0][1]) and ! isset($groups[0][1])) return false;

        $groups = $groups[0][1];
        $roles = array_intersect($groups, static::$_valid_groups);
        if (empty($roles)) return false;

        return true;
    }

    public function get_name($group)
    {
        if ($group === null) return null;
        return \Config::get('uriauth.prefixes.'.$group.'.name', null);
    }

    public function get_roles($groups = null)
    {
        if ($groups === null)
        {
            if ( ! $login = \Auth::instance()
                or ! is_array($groups = $login->get_groups())
                or ! isset($groups[0][1]))
            {
                return array();
            }
            $groups = $groups[0][1];
        }

        if ( ! is_array($groups)) $groups = array($groups);

        $roles = array_intersect($groups, static::$_valid_groups);

        return $roles;
    }

}
