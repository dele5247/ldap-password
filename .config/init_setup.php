<?php
$argv = $_SERVER['argv'];
require_once '/var/www/html/config/config.php';
require_once '/var/www/html/function/database.php';
require_once '/var/www/html/function/setup.php';

$argv = $_SERVER['argv'];

init_setup();
function init_setup()
{
    global $db;
    db_open();
    $db->exec("insert into setting values (1, 'title', '')");
    $db->exec("insert into setting values (2, 'login_bgcolor', '')");
    $db->exec("insert into setting values (3, 'domain', '')");
    $db->exec("insert into setting values (4, 'ldap_host', '')");
    $db->exec("insert into setting values (5, 'ldap_port', '')");
    $db->exec("insert into setting values (6, 'ldap_base_dn', '')");
    $db->exec("insert into setting values (7, 'ldap_bind_dn', '')");
    $db->exec("insert into setting values (8, 'ldap_bind_pwd', '')");
    $db->exec("insert into setting values (9, 'ldap_mail_attribute', '')");
    $db->exec("insert into setting values (10, 'smtp_host', '')");
    $db->exec("insert into setting values (11, 'smtp_port', '')");
    $db->exec("insert into setting values (12, 'smtp_login_id', '')");
    $db->exec("insert into setting values (13, 'smtp_login_pw', '')");
    $db->exec("insert into setting values (14, 'smtp_send_addr', '')");
    $db->exec("insert into setting values (15, 'smtp_mail_title', '')");
    $db->exec("insert into setting values (16, 'smtp_mail_body', '')");
}
?>
