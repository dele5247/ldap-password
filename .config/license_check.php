<?php
$argv = $_SERVER['argv'];
require_once '/var/www/html/config/config.php';
require_once '/var/www/html/function/database.php';
require_once '/var/www/html/function/setup.php';

$argv = $_SERVER['argv'];

$aa=get_license_info();
echo "$aa";
function get_license_info(){
    global $db;
    db_open();
    
    $res = $db->query("SELECT key FROM license WHERE id = 1;");
    
    $license_info = $res->fetchArray();
    
    if ($license_info) {
        return $license_info['key'];
    }
    
    return null;
}
?>
