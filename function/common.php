<?php
global $ldap_host;
// script path
$cmd="php -q /var/www/html/sc_change_pwd.php";
$ldap=ldap_connect($ldap_host);

require_once $_SERVER["DOCUMENT_ROOT"].'/config/config.php';
require_once $_SERVER["DOCUMENT_ROOT"].'/function/database.php';
require_once $_SERVER["DOCUMENT_ROOT"].'/function/setup.php';
require_once $_SERVER["DOCUMENT_ROOT"].'/function/ucs.php';

?>
