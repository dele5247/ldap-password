<?php
$argv = $_SERVER['argv'];
require_once '/var/www/html/config/config.php';
require_once '/var/www/html/function/database.php';
require_once '/var/www/html/function/setup.php';

$argv = $_SERVER['argv'];

$user=$argv[1];
$password=$argv[2];
ldap_set();

//changePassword($user,$password);

$ldap=ldap_connect($ldaps_host);
changePassword($user,$password);
function changePassword($user, $password)
{
    global $message;
    global $ldap_base;
    global $ldaps_host;
    global $admin_dn;
    global $admin_pw;
    //error_reporting(0);
    //ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    ldap_set();
    putenv ('LDAPTLS_REQCERT=never');
    $ldap = ldap_connect($ldaps_host);
    echo "$ldaps_host";
    if ( $ldap === false ) {
  	echo "ERROR: connect failed to $host\n";
    }
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

    // bind rdn and find user by uid
    if (ldap_bind($ldap, $admin_dn, $admin_pw) === false) {

        $message[] = "Error E201 - Unable to connect to server, you may not change your password at this time, sorry.";
        return false;
    }

    $userSearch = ldap_search($ldap, $ldap_base, "(|(sAMAccountName=$user))");
    $userGet = ldap_get_entries($ldap, $userSearch);
    if (!$userGet) {
        $message[] = "Error E202 - Unable to connect to server, you may not change your password at this time, sorry.";
        return false;
    }
    // find the first match and search again
    $userEntry = ldap_first_entry($ldap, $userSearch);
    $userDn = ldap_get_dn($ldap, $userEntry);
    $userId = $userGet[0]["cn"][0];
    $userMail = $userGet[0]["proxyaddresses"][0];
    $userSearchArray = array("pwdaccountlockedtime");
    $userSearchFilter = "(|(samaccountname=$userId))";
    $userSearchOpt = ldap_search($ldap, $userDn, $userSearchFilter, $userSearchArray);
    $userGetOpt = ldap_get_entries($ldap, $userSearchOpt);
    $entry = array();

    $result=check_ldap_user($user);
    if (is_null($userDn)){
        $message[] = "[Error]Your password was not changed . with:".print_r($result, true);
        $error = ldap_error($ldap);
        $errno = ldap_errno($ldap);
        $message[] = "$errno - $error";
    }else {
        $ok = "yes";
	$new_password=getPassword($password);
        //$message[] = " Your password has been changed.\n Email :".var_dump($userGet[0]["sAMAccountName"][0]);
        //$message[] = " Your password has been changed.\n Email :".var_dump($userGet[0]["cn"][0]);
            
	if(is_null($userMail)){
	    //$userdata["unicodePwd"] = iconv("UTF-8", "UTF-16LE", '"' . $new_password . '"');
	    $userdata["unicodePwd"] = $new_password;
            $chg_result = ldap_mod_replace($ldap, $userDn , $userdata);
            if (!$result) {
            	$message[]=ldap_error($ldap);
            }else{
	        $message[] = "[Error] Not Mail Address!! /".print_r($password)."/".print_r($chg_result);
	    }

        }else{
	    //$userdata["unicodePwd"] = iconv("UTF-8", "UTF-16LE", '"' . $new_password . '"');
	    $userdata["unicodePwd"] = $new_password;
            $chg_result = ldap_mod_replace($ldap, $userDn , $userdata);
            $message[] = "[OK] Your password has been changed. <p>Email : $userMail / ".print_r($chg_result);
	}
    }
    echo "############################\n";
    echo "##  $user / ".var_dump($userdata)."\n";
    echo "############################\n";
    var_dump($message);
ldap_close($ldap);
}


function getPassword($sPassword) { 
    $sPassword = '"' . $sPassword . '"'; 
    $nCount = strlen($sPassword); 
    $sNewPassword = ""; 
    for ($i = 0; $i < $nCount; $i++) { 
	$sNewPassword .= $sPassword[$i] . "\000"; 
    } 
    return $sNewPassword; 
}


function mail_send($mail_address, $password){
    global $smtp_server;
    global $smtp_port;
    global $smtp_admin_id;
    global $smtp_admin_pwd;
    global $smtp_send_address;
    smtp_set();
    require "PHPMailer/src/PHPMailer.php";
    require "PHPMailer/src/SMTP.php";
    require "PHPMailer/src/Exception.php";
    //use PHPMailer\PHPMailer\PHPMailer;
    //use PHPMailer\PHPMailer\Exception;
    $mail = new PHPMailer(true);
    try {
	$mail -> SMTPDebug = 2;
	$mail -> isSMTP();
	$mail -> Host = $smtp_server;           
	$mail -> SMTPAuth = true;                      
	$mail -> Username = $smtp_admin_id;
	$mail -> Password = $smtp_admin_pwd;
	$mail -> SMTPSecure = "ssl";                       
	$mail -> Port = $smtp_port;                                 
	$mail -> CharSet = "utf-8"; 
	$mail -> setFrom($smtp_send_address);
	$mail -> addAddress($main_address, "receive01");
	$mail -> isHTML(true); //
	$mail -> Subject = "test";
	$mail -> Body = "New Password : ".$password;    
	$mail -> SMTPOptions = array(
  	"ssl" => array(
  	    "verify_peer" => false
            , "verify_peer_name" => false
            , "allow_self_signed" => true
  	));
        $mail -> send();
        echo "Message has been sent";
    } catch (Exception $e) {
	echo "Message could not be sent. Mailer Error : ", $mail -> ErrorInfo;
    }
}
function randomPassword($length,$count, $characters) {
// define variables used within the function    
    $symbols = array();
    $passwords = array();
    $used_symbols = '';
    $pass = '';
// an array of different character types    
    $symbols["lower_case"] = 'abcdefghijklmnopqrstuvwxyz';
    $symbols["upper_case"] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $symbols["numbers"] = '1234567890';
    $symbols["special_symbols"] = '!?@#[]{}';
    $characters = explode(",",$characters); 
    foreach ($characters as $key=>$value) {
        $used_symbols .= $symbols[$value]; // build a string with all characters
    }
    $symbols_length = strlen($used_symbols) - 1; //strlen starts from 0 so to get number of characters deduct 1
    for ($p = 0; $p < $count; $p++) {
        $pass = '';
        for ($i = 0; $i < $length; $i++) {
            $n = rand(0, $symbols_length); // get a random character from the string with all characters
            $pass .= $used_symbols[$n]; // add the character to the password string
        }
        $passwords[] = $pass;
    }
    return $passwords; // return the generated password
}

function ntpasswd($Input) {
  // Convert the password from UTF8 to UTF16 (little endian)
  $Input=iconv('UTF-8','UTF-16LE',$Input);

  $MD4Hash=hash('md4',$Input);

  // Make it uppercase, not necessary, but it's common to do so with NTLM hashes
  $NTLMHash=strtoupper($MD4Hash);

  // Return the result
  return($NTLMHash);
}

function checknt($passwd, $hash){
        return (ntpasswd($passwd) === strtoupper($hash));
}

function sshapasswd($input){
        mt_srand((double)(microtime(true) ^ posix_getpid()));
        $salt = pack("CCCC", mt_rand(0,255), mt_rand(0,255), mt_rand(0,255), mt_rand(0,255));

        $passwd_sha1 = sha1($input . $salt, TRUE);

        $result = '{SSHA}' . base64_encode($passwd_sha1 . $salt);

        if (!checkssha($result, $input))
                return null;
        else
                return $result;

}

function checkssha ($input, $passwd){
        $orig = base64_decode(substr($input, 6));
        $hash = substr($orig, 0, 20);
        $salt = substr($orig, 20, 4);

        if (sha1($passwd . $salt, TRUE) == $hash){
                return TRUE;
        } else {
                return FALSE;
        }
}

function check_ldap_passwd($username, $passwd){
        global $ldap, $ldaps_host, $ldap_base;
	ldap_set();
        # Assume uid=username,searchbase
        $ldap = ldap_connect($ldaps_host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        return @ldap_bind($ldap, 'uid=' . $username . ',' . $ldap_base, $passwd);
}

function change_ldap_passwd($username, $passwd, $new){
        global $ldap, $ldap_base;

        if ($ldap == null){
                // Odd, this should've been done already.
                if(!check_ldap_passwd($username, $passwd))
                        return NULL;
        }

        // Get the account's info
        $res = ldap_search($ldap, 'uid=' . $username . ',' . $ldap_base, '(objectClass=posixAccount)');
        if (ldap_count_entries($ldap, $res) > 1){
                die('Something is wrong- more than one search result.');
        } else if (ldap_count_entries($ldap, $res) == 0){
                die('Something is wrong- You logged in but I can\'t find you anymore.');
        }

        $entry = ldap_first_entry($ldap, $res);
        $userdn = ldap_get_dn($ldap, $entry);
        $obj = null;

        // Does this account already have objectClass: sambaSamAccount?
        if(!ldap_compare($ldap, $userdn, 'objectClass', 'sambaSamAccount')){
                // Have to get other objectClass values, too.
                $object = ldap_get_attributes($ldap, $entry);
                unset($object['objectClass']['count']);
                $obj['objectClass'] = $object['objectClass'];
                $obj['objectClass'][] = 'sambaSamAccount';
        }

        $now = time();
        $obj['userPassword'] = sshapasswd($new);
        $obj['sambaNTPassword'] = ntpasswd($new);
        $obj['sambaPwdLastSet'] = "$now";


        return @ldap_modify($ldap, $userdn, $obj);
}

function change_ldap_passwd_admin($username, $passwd){
        global $ldap, $ldap_base, $ldaps_host, $admin_dn, $admin_pw;
	ldap_set();
        if ($ldap == null){
                // Odd, this should've been done already.
                $ldap = ldap_connect($ldaps_host);
                ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

                if (!@ldap_bind($ldap, $admin_dn, $admin_pw)){
                        my_die("<!-- check_ldap_user -->An error occurred.");
                }
        }


        // Get the account's info
        $res = ldap_search($ldap, 'uid=' . $username . ',' . $ldap_base, '(objectClass=posixAccount)');
        if (ldap_count_entries($ldap, $res) > 1){
                die('Something is wrong- more than one search result.');
        } else if (ldap_count_entries($ldap, $res) == 0){
                die('Something is wrong- You logged in but I can\'t find you anymore.');
        }

        $entry = ldap_first_entry($ldap, $res);
        $userdn = ldap_get_dn($ldap, $entry);
        $obj = null;

        // Does this account already have objectClass: sambaSamAccount?
        if(!ldap_compare($ldap, $userdn, 'objectClass', 'sambaSamAccount')){
                // Have to get other objectClass values, too.
                $object = ldap_get_attributes($ldap, $entry);
                unset($object['objectClass']['count']);
                $obj['objectClass'] = $object['objectClass'];
                $obj['objectClass'][] = 'sambaSamAccount';
        }

        $obj['userPassword'] = sshapasswd($passwd);
        $obj['sambaNTPassword'] = ntpasswd($passwd);

        echo "ssh: " . $obj['userPassword'] . " nt: " . $obj['sambaNTPassword'];

        return @ldap_modify($ldap, $userdn, $obj);
}

function check_nt_passwd($username, $password){
        global $ldap, $ldap_base, $ldaps_host, $admin_dn, $admin_pw;
	ldap_set();
        $ldap = ldap_connect($ldaps_host);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        if (!@ldap_bind($ldap, $admin_dn, $admin_pw)){
                my_die("<!-- check_nt_password -->An error occurred.");
        }

        $res = ldap_search($ldap, 'uid=' . $username . ',' . $ldap_base, '(objectClass=posixAccount)');
        if (ldap_count_entries($ldap, $res) > 1){
                die('Something is wrong- more than one search result.');
        } else if (ldap_count_entries($ldap, $res) == 0){
                die('Something is wrong- You logged in but I can\'t find you anymore.');
        }

        $entry = ldap_first_entry($ldap, $res);
        $userdn = ldap_get_dn($ldap, $entry);
        $object = ldap_get_attributes($ldap, $entry);
        if (isset($object['sambaNTPassword'])){
                return checknt($password, $object['sambaNTPassword'][0]);
        } else {
                return null;
        }
}

function check_ldap_user($username){
        global $ldap, $ldap_base, $ldaps_host, $admin_dn, $admin_pw;
	ldap_set();
        if ($ldap == null){
                // Odd, this should've been done already.
                $ldap = ldap_connect($ldaps_host);
                ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

                if (!@ldap_bind($ldap, $admin_dn, $admin_pw)){
                        my_die("<!-- check_ldap_user -->An error occurred.");
                }
        }

        $res = @ldap_search($ldap, 'uid=' . $username . ',' . $ldap_base, '(objectClass=posixAccount)');
        #return @ldap_count_entries($ldap, $res) == 1;
        return $res;

}
?>
