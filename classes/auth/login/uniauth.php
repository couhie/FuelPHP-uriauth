<?php
namespace Auth;

class UniUserUpdateException extends \FuelException {}

class UniUserWrongPassword extends \FuelException {}

class Auth_Login_UniAuth extends \Auth_Login_Driver
{

	public static function _init()
	{
		\Config::load('uniauth', true, true, true);
		static::_redefine_guest_login();
	}

	private static function _redefine_guest_login()
	{
		$tmp = array();
		foreach (\Config::get('uniauth.definition_columns') as $key => $value)
		{
			$tmp[$value] = isset(static::$guest_login[$key]) ? static::$guest_login[$key] : null;
		}
		static::$guest_login = $tmp;
	}

	private static function _column($key)
	{
		if (isset(static::$_columns[$key])) return static::$_columns[$key];
		return static::$_columns[$key] = \Config::get("uniauth.definition_columns.{$key}");
	}

	private static $_columns = array();

	public $hash = null;

	/**
	 * @var  Database_Result  when login succeeded
	 */
	protected $user = null;

	/**
	 * @var  array  value for guest login
	 */
	protected static $guest_login = array(
		'id' => 'guest',
		'group' => '0',
	);

	/**
	 * @var  array  UniAuth class config
	 */
	protected $config = array(
		'drivers' => array(
			'group' => array('UniGroup'),
			'acl'   => array('UniAcl')),
		//'additional_fields' => array('profile'),
		'additional_fields' => array(),
	);

	/**
	 * Check for login
	 *
	 * @return  bool
	 */
	protected function perform_check()
	{
		$auth = \Session::get('auth');
		$id = isset($auth[static::_column('id')]) ? $auth[static::_column('id')] : '';
		$hash = isset($auth[static::_column('hash')]) ? $auth[static::_column('hash')] : '';

		if ( ! empty($id) and ! empty($hash))
		{
			if (\Config::get('uniauth.multi_login'))
			{
				$this->user = $auth;
				return true;
			}

			if (is_null($this->user) or ($this->user[static::_column('id')] != $id and $this->user != static::$guest_login))
			{
				$this->user = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
					->where(static::_column('id'), '=', $id)
					->where(static::_column('activated_at'), '!=', null)
					->where(static::_column('deleted_at'), '=', null)
					->from(\Config::get('uniauth.table_name'))
					->execute(\Config::get('uniauth.db_connection'))->current();
			}

			// return true when login was verified
			if ($this->user and $this->user[static::_column('hash')] === $hash)
			{
				return true;
			}
		}

		// no valid login when still here, ensure empty session and optionally set guest_login
		$this->user = \Config::get('uniauth.guest_login', true) ? static::$guest_login : false;
		\Session::delete('auth');

		return false;
	}

	/**
	 * Check the user exists before logging in
	 *
	 * @return  bool
	 */
	public function validate_user($id = '', $password = '')
	{
		$id = trim($id) ?: trim(\Input::post(\Config::get('uniauth.name_post_key', 'id')));
		$password = trim($password) ?: trim(\Input::post(\Config::get('uniauth.password_post_key', 'password')));

		if (empty($id) or empty($password))
		{
			return false;
		}

		$password = $this->hash_password($password);
		$this->user = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
			->where(static::_column('id'), '=', $id)
			->where(static::_column('password'), '=', $password)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->from(\Config::get('uniauth.table_name'))
			->execute(\Config::get('uniauth.db_connection'))->current();

		if ( ! $this->user) return false;

		$this->user = $this->shape_attribute($this->user);

		return $this->user;
	}

	/**
	 * Login user
	 *
	 * @param   string
	 * @param   string
	 * @param   array
	 * @return  bool
	 */
	public function login($id = '', $password = '', Array $options = array())
	{
		if ( ! ($this->user = $this->validate_user($id, $password)))
		{
			$this->user = \Config::get('uniauth.guest_login', true) ? static::$guest_login : false;
			\Session::delete('auth');
			return false;
		}

		$this->create_hash(null, $options);
		\Session::instance()->rotate();
		\Session::set('auth', $this->user);
		return true;
	}

	/**
	 * Force login user
	 *
	 * @param   string
	 * @return  bool
	 */
	public function force_login($id = '')
	{
		if (empty($id))
		{
			return false;
		}

		$this->user = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
			->where(static::_column('id'), '=', $id)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->from(\Config::get('uniauth.table_name'))
			->execute(\Config::get('uniauth.db_connection'))
			->current();

		if ($this->user == false)
		{
			$this->user = \Config::get('uniauth.guest_login', true) ? static::$guest_login : false;
			\Session::delete('auth');
			return false;
		}

		$this->user = $this->shape_attribute($this->user);
		$this->create_hash();
		\Session::set('auth', $this->user);
		return true;
	}

	/**
	 * Logout user
	 *
	 * @return  bool
	 */
	public function logout()
	{
		$this->user = \Config::get('uniauth.guest_login', true) ? static::$guest_login : false;
		\Session::delete('auth');
		return true;
	}

	/**
	 * Create new user
	 *
	 * @param   string
	 * @param   string
	 * @param   string  must contain valid email address
	 * @param   int     group id
	 * @param   Array
	 * @param   Array
	 * @param   bool
	 * @return  bool
	 */
	public function create_user($id, $password, $email, $group = 1, Array $profile = array(), Array $other_fields = array(), $force = false)
	{
		$password = trim($password);
		$email = trim($email);

		if (empty($id) or empty($password) or empty($email))
		{
			throw new \UniUserUpdateException('Id, password or email address is not given, or email address is invalid', 1);
		}

		$same_users = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
			->where(static::_column('id'), '=', $id)
			->from(\Config::get('uniauth.table_name'))
			->execute(\Config::get('uniauth.db_connection'));

		if ($same_users->count() > 0 and
			( ! is_null($same_users->get(static::_column('activated_at'))) or
			  ! is_null($same_users->get(static::_column('deleted_at')))))
		{
			throw new \UniUserUpdateException('Id already exists', 3);
		}

		$user = array();
		foreach (\Config::get('uniauth.definition_columns') as $key => $value)
		{
			switch ($key)
			{
				case 'id':
					$user[$value] = (string) $id;
					break;
				case 'password':
					$user[$value] = $this->hash_password((string) $password);
					break;
				case 'group':
					$user[$value] = (int) $group;
					break;
				case 'email':
					$user[$value] = $email;
					break;
				case 'profile':
					$user[$value] = serialize($profile);
					break;
				case 'hash':
					$user[$value] = $this->create_hash((string) $id);
					break;
				case 'created_at':
					$user[$value] = \Date::forge()->format('%Y-%m-%d %H:%M:%S');
					break;
				case 'updated_at':
					$user[$value] = \Date::forge()->format('%Y-%m-%d %H:%M:%S');
					break;
				default:
					isset($other_fields[$value]) and $user[$value] = $other_fields[$value];
			}
		}

		if ($force)
		{
			$user[static::_column('activated_at')] = \Date::forge()->format('%Y-%m-%d %H:%M:%S');
		}

		$ret = null;

		if ($same_users->count() > 0)
		{
			$affected_rows = \DB::update(\Config::get('uniauth.table_name'))
				->set($user)
				->where(static::_column('id'), '=', $same_users->get(static::_column('id')))
				->where(static::_column('deleted_at'), '=', null)
				->execute(\Config::get('uniauth.db_connection'));
			$ret = $affected_rows > 0 ? $same_users->get(static::_column('id')) : false;
		}
		else
		{
			$result = \DB::insert(\Config::get('uniauth.table_name'))
				->set($user)
				->execute(\Config::get('uniauth.db_connection'));
			$ret = ($result[1] > 0) ? $result[0] : false;
		}

		if ( ! $force) return $ret;

		return $this->login($id, $password, $user);
	}

	/**
	 * Update a user's properties
	 * Note: Id cannot be updated, to update password the old password must be passed as old_password
	 *
	 * @param   Array  properties to be updated including profile fields
	 * @param   string
	 * @return  bool
	 */
	public function update_user($values, $id = null)
	{
		$id = $id ?: $this->user['id'];
		$current_values = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
			->where(static::_column('id'), '=', $id)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->from(\Config::get('uniauth.table_name'))
			->execute(\Config::get('uniauth.db_connection'));

		if (empty($current_values))
		{
			throw new \UniUserUpdateException('Id not found', 4);
		}

		$update = array();
		$update[static::_column('updated_at')] = \Date::forge()->format('%Y-%m-%d %H:%M:%S');
		if (array_key_exists(static::_column('id'), $values))
		{
			throw new \UniUserUpdateException('Id cannot be changed.', 5);
		}
		if (array_key_exists(static::_column('password'), $values))
		{
			if (empty($values['old_password'])
				or $current_values->get(static::_column('password')) != $this->hash_password(trim($values['old_password'])))
			{
				throw new \UniUserWrongPassword('Old password is invalid');
			}

			$password = trim(strval($values[static::_column('password')]));
			if ($password === '')
			{
				throw new \UniUserUpdateException('Password can\'t be empty.', 6);
			}
			$update[static::_column('password')] = $this->hash_password($password);
			unset($values[static::_column('password')]);
		}
		if (array_key_exists('old_password', $values))
		{
			unset($values['old_password']);
		}
		if (array_key_exists(static::_column('email'), $values))
		{
			$email = trim($values[static::_column('email')]);
			if ( ! $email)
			{
				throw new \UniUserUpdateException('Email address is not valid', 7);
			}
			$update[static::_column('email')] = $email;
			unset($values[static::_column('email')]);
		}
		if (array_key_exists(static::_column('group'), $values))
		{
			if (is_numeric($values[static::_column('group')]))
			{
				$update[static::_column('group')] = (int) $values[static::_column('group')];
			}
			unset($values[static::_column('group')]);
		}
		if ( ! empty($values))
		{
			$profile = @unserialize($current_values->get(static::_column('profile'))) ?: array();
			foreach ($values as $key => $val)
			{
				if ($val === null)
				{
					unset($profile[$key]);
				}
				else
				{
					$profile[$key] = $val;
				}
			}
			$update[static::_column('profile')] = serialize($profile);
		}

		$affected_rows = \DB::update(\Config::get('uniauth.table_name'))
			->set($update)
			->where(static::_column('id'), '=', $id)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->execute(\Config::get('uniauth.db_connection'));

		// Refresh user
		if ($this->user[static::_column('id')] == $id)
		{
			$this->user = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
				->where(static::_column('id'), '=', $id)
				->where(static::_column('activated_at'), '!=', null)
				->where(static::_column('deleted_at'), '=', null)
				->from(\Config::get('uniauth.table_name'))
				->execute(\Config::get('uniauth.db_connection'))->current();
		}

		return $affected_rows > 0;
	}

	/**
	 * Change a user's password
	 *
	 * @param   string
	 * @param   string
	 * @param   string  id or null for current user
	 * @return  bool
	 */
	public function change_password($old_password, $new_password, $id = null)
	{
		try
		{
			return (bool) $this->update_user(array('old_password' => $old_password, static::_column('password') => $new_password), $id);
		}
		// Only catch the wrong password exception
		catch (UniUserWrongPassword $e)
		{
			return false;
		}
	}

	/**
	 * Generates new random password, sets it for the given id and returns the new password.
	 * To be used for resetting a user's forgotten password, should be emailed afterwards.
	 *
	 * @param   string  $id
	 * @return  string
	 */
	public function reset_password($id)
	{
		$new_password = \Str::random('alnum', 8);
		$password_hash = $this->hash_password($new_password);

		$affected_rows = \DB::update(\Config::get('uniauth.table_name'))
			->set(array(static::_column('password') => $password_hash))
			->where(static::_column('id'), '=', $id)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->execute(\Config::get('uniauth.db_connection'));

		if ( ! $affected_rows)
		{
			throw new \UniUserUpdateException('Failed to reset password, user was invalid.', 8);
		}

		return $new_password;
	}

	/**
	 * Deletes a given user
	 *
	 * @param   string
	 * @return  bool
	 */
	public function delete_user($id)
	{
		if (empty($id))
		{
			throw new \UniUserUpdateException('Cannot delete user with empty id', 9);
		}

		$affected_rows = \DB::delete(\Config::get('uniauth.table_name'))
			->where(static::_column('id'), '=', $id)
			->execute(\Config::get('uniauth.db_connection'));

		return $affected_rows > 0;
	}

	/**
	 * Creates a temporary hash that will validate the current login
	 *
	 * @return  string
	 */
	public function create_hash($id = null, Array $options = array())
	{
		if (empty($this->user) and is_null($id))
		{
			throw new \UniUserUpdateException('User not logged in, can\'t create login hash.', 10);
		}
		is_null($id) and $id = $this->user[static::_column('id')];

		$loggedin_at = \Date::forge()->format('%Y-%m-%d %H:%M:%S');
		$this->hash = sha1(\Config::get('uniauth.hash_salt').$id.$loggedin_at);

		if ( ! empty($this->user))
		{
			$remote_addr = isset($options[static::_column('remote_addr')]) ? $options[static::_column('remote_addr')] : @$_SERVER['REMOTE_ADDR'];
			$user_agent = substr(isset($options[static::_column('user_agent')]) ? $options[static::_column('user_agent')] : @$_SERVER['HTTP_USER_AGENT'], 0, 255);
			$data = array(
				static::_column('remote_addr') => $remote_addr,
				static::_column('user_agent')  => $user_agent,
				static::_column('loggedin_at') => $loggedin_at,
				static::_column('hash')        => $this->hash,
			);
			\DB::update(\Config::get('uniauth.table_name'))
				->set($data)
				->where(static::_column('id'), '=', $this->user[static::_column('id')])
				->where(static::_column('activated_at'), '!=', null)
				->where(static::_column('deleted_at'), '=', null)
				->execute(\Config::get('uniauth.db_connection'));

			$this->user[static::_column('remote_addr')] = $remote_addr;
			$this->user[static::_column('user_agent')] = $user_agent;
			$this->user[static::_column('loggedin_at')] = $loggedin_at;
			$this->user[static::_column('hash')] = $this->hash;
		}

		return $this->hash;
	}

	/**
	 * Get the user
	 *
	 * @return  Array
	 */
	public function get_user()
	{
		if (empty($this->user))
		{
			return false;
		}
		return $this->user;
	}

	/**
	 * Get the user's ID
	 *
	 * @return  Array  containing this driver's ID & the user's ID
	 */
	public function get_user_id()
	{
		return false;
	}

	/**
	 * Get the user's groups
	 *
	 * @return  Array  containing the group driver ID & the user's group ID
	 */
	public function get_groups()
	{
		if (empty($this->user))
		{
			return false;
		}

		return array(array('UniGroup', $this->user[static::_column('group')]));
	}

	/**
	 * Get the user's emailaddress
	 *
	 * @return  string
	 */
	public function get_email()
	{
		if (empty($this->user))
		{
			return false;
		}

		return $this->user[static::_column('email')];
	}

	/**
	 * Get the user's screen name
	 *
	 * @return  string
	 */
	public function get_screen_name()
	{
		if (empty($this->user))
		{
			return false;
		}

		return $this->user[static::_column('id')];
	}

	/**
	 * Get the user's profile fields
	 *
	 * @return  Array
	 */
	public function get_profile($field = null, $default = null)
	{
		if (empty($this->user))
		{
			return false;
		}

		if (isset($this->user[static::_column('profile')]))
		{
			is_array($this->user[static::_column('profile')]) or $this->user[static::_column('profile')] = @unserialize($this->user[static::_column('profile')]);
		}
		else
		{
			$this->user[static::_column('profile')] = array();
		}

		return is_null($field) ? $this->user[static::_column('profile')] : \Arr::get($this->user[static::_column('profile')], $field, $default);
	}

	/**
	 * Extension of base driver method to default to user group instead of user id
	 */
	public function has_access($condition, $driver = null, $user = null)
	{
		if (is_null($user))
		{
			$groups = $this->get_groups();
			$user = reset($groups);
		}
		return parent::has_access($condition, $driver, $user);
	}

	/**
	 * Extension of base driver because this supports a guest login when switched on
	 */
	public function guest_login()
	{
		return \Config::get('uniauth.guest_login', true);
	}

	public function hash_password($password)
	{
		return \Crypt::encode($password);
	}

	public function activate_user($hash)
	{
		if (empty($hash)) return false;

		$affected_rows = \DB::update(\Config::get('uniauth.table_name'))
			->set(array(static::_column('activated_at') => \Date::forge()->format('%Y-%m-%d %H:%M:%S')))
			->where(static::_column('hash'), '=', $hash)
			->where(static::_column('created_at'), '>=', date('Y-m-d H:i:s', strtotime('-2day', \Date::forge()->get_timestamp())))
			->where(static::_column('activated_at'), '=', null)
			->where(static::_column('deleted_at'), '=', null)
			->execute(\Config::get('uniauth.db_connection'));

		if ($affected_rows == 0) return false;

		$this->user = \DB::select_array(\Config::get('uniauth.table_columns', array('*')))
			->where(static::_column('hash'), '=', $hash)
			->where(static::_column('activated_at'), '!=', null)
			->where(static::_column('deleted_at'), '=', null)
			->from(\Config::get('uniauth.table_name'))
			->execute(\Config::get('uniauth.db_connection'))
			->current();

		if ($this->user == false)
		{
			$this->user = \Config::get('uniauth.guest_login', true) ? static::$guest_login : false;
			\Session::delete('auth');
			return false;
		}

		$this->user = $this->shape_attribute($this->user);
		$this->create_hash();
		\Session::set('auth', $this->user);
		return $this->user;
	}

	public function shape_attribute($user) {
		! $user and $user = \Session::get('auth');
		if ( ! is_array($user)) return false;
		foreach (\Config::get('uniauth.unkeep_columns') as $column)
		{
			$user = $this->del_attribute($column, $user);
		}
		return $user;
	}

	public function set_attribute($key, $value, $user = null)
	{
		! $user and $user = \Session::get('auth');
		if ( ! is_array($user)) return false;
		$user[$key] = $value;
		\Session::set('auth', $user);
		return $user;
	}

	public function del_attribute($key, $user = null)
	{
		! $user and $user = \Session::get('auth');
		if ( ! is_array($user)) return false;
		unset($user[$key]);
		\Session::delete("auth.{$key}");
		return $user;
	}

}
