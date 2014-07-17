<?php
Autoloader::add_core_namespace('Auth');

Autoloader::add_classes(array(
    'Auth\\Auth_Acl_UriAcl'        => __DIR__.'/classes/auth/acl/uriacl.php',
    'Auth\\Auth_Group_UriGroup'    => __DIR__.'/classes/auth/group/urigroup.php',
    'Auth\\Auth_Login_UriAuth'     => __DIR__.'/classes/auth/login/uriauth.php',
    'Auth\\UriUserUpdateException' => __DIR__.'/classes/auth/login/uriauth.php',
    'Auth\\UriUserWrongPassword'   => __DIR__.'/classes/auth/login/uriauth.php',
));
