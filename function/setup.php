<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

include_once('PHPMailer/src/PHPMailer.php');
include_once('PHPMailer/src/SMTP.php');
include_once('PHPMailer/src/Exception.php');

$post_otp="";

function logo()
{
    global $logo_file_path;
    echo "<img class='center-block' src='$logo_file_path' width=130% >";
}

function logo_ico()
{
    global $logo_file_path2;
    echo "<link rel='shortcut icon' type='image/x-icon' href='$logo_file_path2' />";
}

function title()
{
    global $web_title;

    $check_set=set_list(1);
    if(isset($check_set)){
	return $check_set;
    }else{
    	return $web_title;
    }
}

function login_bgcolor()
{
   global $login_bgcolor;
   
    $check_set=set_list(2);
    if(isset($check_set)){
        return  $check_set;
    }else{
        return  $login_bgcolor;
    }
}

function domain(){
    global $domain;
    $check_set=set_list(3);
    if(!empty($check_set)){
        return $check_set;
    }else{
        return $domain;
    }
}
function ldap_set(){
    global $ldap_host;
    global $ldaps_host;
    global $ldap_port;
    global $ldap_base;
    global $admin_dn;
    global $admin_pw;
    global $ldap_mail_attribute;
    $ldap_host_set=set_list(4);
    $ldap_port_set=set_list(5);
    $ldap_base_set=set_list(6);
    $admin_dn_set=set_list(7);
    $admin_pw_set=set_list(8);
    $ldap_mail_attribute_set=set_list(9);
    if(!empty($ldap_host_set)){
        $ldap_host=$ldap_host_set;
        $ldaps_host="ldaps://$ldap_host:$ldap_port";
    }
    if(!empty($ldap_port_set)){
        $ldap_port=$ldap_port_set;
    }
    if(!empty($ldap_base_set)){
        $ldap_base=$ldap_base_set;
    }
    if(!empty($admin_dn_set)){
        $admin_dn=$admin_dn_set;
    }
    if(!empty($admin_pw_set)){
        $admin_pw=$admin_pw_set;
    }
    if(!empty($ldap_mail_attribute_set)){
        $ldap_mail_attribute=$ldap_mail_attribute_set;
    }
    return false;
}

function smtp_set(){
    global $smtp_server;
    global $smtp_port;
    global $smtp_admin_id;
    global $smtp_admin_pwd;
    global $smtp_send_address;
    global $smtp_mail_title;
    global $smtp_mail_body;
    $smtp_server_set=set_list(10);
    $smtp_port_set=set_list(11);
    $smtp_admin_id_set=set_list(12);
    $smtp_admin_pwd_set=set_list(13);
    $smtp_send_address_set=set_list(14);
    $smtp_mail_title_set=set_list(15);
    $smtp_mail_body_set=set_list(16);
    if(!empty($smtp_server_set)){
        $smtp_server=$smtp_server_set;
    }
    if(!empty($smtp_port_set)){
        $smtp_port=$smtp_port_set;
    }
    if(!empty($smtp_admin_id_set)){
        $smtp_admin_id=$smtp_admin_id_set;
    }
    if(!empty($smtp_admin_pwd_set)){
        $smtp_admin_pwd=$smtp_admin_pwd_set;
    }
    if(!empty($smtp_send_address_set)){
        $smtp_send_address=$smtp_send_address_set;
    }
    if(!empty($smtp_mail_title_set)){
        $smtp_mail_title=$smtp_mail_title_set;
    }
    if(!empty($smtp_mail_body_set)){
        $smtp_mail_body=$smtp_mail_body_set;
    }
}

function set_list($id){
        global $db;
        db_open();
        $res = $db->query("SELECT set_val FROM setting where id=$id;");
        while ($row = $res->fetchArray()){
                return $row[0];
        }
}


?>
