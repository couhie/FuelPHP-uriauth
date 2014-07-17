<?php
namespace Auth;

class Auth_Acl_UriAcl extends \Auth_Acl_Driver
{

    protected static $_valid_roles = array();

    public static function _init()
    {
        static::$_valid_roles = array_keys(\Config::get('uriauth.prefixes', array()));
    }

    public function has_access($condition, Array $entity)
    {
        $prefix = \Auth::get_prefix();
        if (empty($prefix)) return true;
        if (\Auth::is_publish()) return true;

        $condition = static::_parse_conditions($condition);
        if ( ! is_array($condition)) return false;

        $ignore_actions = \Config::get('uriauth.ignore_actions', array());
        if (array_key_exists($condition[0], $ignore_actions) and in_array($condition[1], $ignore_actions[$condition[0]])) return true;

        $group = \Auth::group($entity[0]);
        if (empty($group) || ! is_callable(array($group, 'get_roles'))) return false;

        $roles  = $group->get_roles($entity[1]);

        if (in_array($prefix, $roles)) return true;

        return false;
    }

}
