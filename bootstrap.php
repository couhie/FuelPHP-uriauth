<?php
Autoloader::add_core_namespace('Auth');

Autoloader::add_classes(
	array(
		'Auth\\Auth_Acl_UniAcl'        => __DIR__.'/classes/auth/acl/uniacl.php',
		'Auth\\Auth_Group_UniGroup'    => __DIR__.'/classes/auth/group/unigroup.php',
		'Auth\\Auth_Login_UniAuth'     => __DIR__.'/classes/auth/login/uniauth.php',
		'Auth\\UniUserUpdateException' => __DIR__.'/classes/auth/login/uniauth.php',
		'Auth\\UniUserWrongPassword'   => __DIR__.'/classes/auth/login/uniauth.php',
	));
