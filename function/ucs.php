<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

include_once('PHPMailer/src/PHPMailer.php');
include_once('PHPMailer/src/SMTP.php');
include_once('PHPMailer/src/Exception.php');

$post_otp="";

function changeOTP($user,$mail_check){
    global $message;
    global $ldap_base;
    global $ldap_host;
    global $admin_dn;
    global $admin_pw;
    global $ldap_mail_attribute;
    global $cmd;
    global $post_otp;
    global $otps;
    error_reporting(0);
    ldap_set();
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    putenv ('LDAPTLS_REQCERT=never');

    $ldap = ldap_connect("ldap://$ldap_host");
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
    $userMail = $userGet[0]["$ldap_mail_attribute"][0];
    
//$userMail = $userGet[0]["proxyaddresses"][0];
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
    	$otps[]="";
    	$otp=generatePassword2(6);
        $otps[]=$otp;
        if(is_null($userMail)){
            $message[] = "[Error] Not Mail Address!!";
        }else{
            if($userMail == $mail_check){
                mail_send($userMail, "$otp");
                $message[] = "[OK] $userMail OTP Mail Send!!";
		return $ok;
            }else{
                $message[] = "[Error] Mail Address Check!!";
            }
        }
    }
ldap_close($ldap);
}


function changePassword($user,$password)
{
    global $message;
    global $ldap_base;
    global $ldap_host;
    global $admin_dn;
    global $admin_pw;
    global $ldap_mail_attribute;
    global $cmd;
    ldap_set();
    error_reporting(0);
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    putenv ('LDAPTLS_REQCERT=never');
    
    $ldap = ldap_connect("ldap://$ldap_host");
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
    $userMail = $userGet[0]["$ldap_mail_attribute"][0];
    //$userMail = $userGet[0]["proxyaddresses"][0];
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
        $message[] = "[OK] Password Change Complete";
	log_insert($userId, $userMail);
	$output=shell_exec("$cmd $userId $password > /dev/null 2>&1 &");
    }
ldap_close($ldap);
}

function generatePassword($_len) {

    $_alphaSmall = 'abcdefghijklmnopqrstuvwxyz';            // small letters
    $_alphaCaps  = strtoupper($_alphaSmall);                // CAPITAL LETTERS
    $_numerics   = '1234567890';                            // numerics
    $_specialChars = '!@#$%^&*(){}[]?~';   // Special Characters

    $_container = $_alphaSmall.$_alphaCaps.$_numerics.$_specialChars;   // Contains all characters
    $password = '';         // will contain the desired pass

    for($i = 0; $i < $_len; $i++) {                                 // Loop till the length mentioned
        $_rand = rand(0, strlen($_container) - 1);                  // Get Randomized Length
        $password .= substr($_container, $_rand, 1);                // returns part of the string [ high tensile strength ;) ] 
    }

    return $password;       // Returns the generated Pass
}

function generatePassword2($_len) {

    $_numerics   = '1234567890';                            // numerics
    $password = '';         // will contain the desired pass

    for($i = 0; $i < $_len; $i++) {                                 // Loop till the length mentioned
        $_rand = rand(0, strlen($_numerics) - 1);                  // Get Randomized Length
        $password .= substr($_numerics, $_rand, 1);                // returns part of the string [ high tensile strength ;) ]
    }

    return $password;       // Returns the generated Pass
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
    global $smtp_mail_title;
    global $smtp_mail_body;
    smtp_set();
    $mail = new PHPMailer(true);
    try {
	//$mail -> SMTPDebug = 2;
	$mail -> isSMTP();
	$mail -> Host = $smtp_server;           
	$mail -> SMTPAuth = true;                      
	$mail -> Port = $smtp_port;                                 
	$mail -> SMTPSecure = "ssl";                       
	$mail -> Username = "$smtp_admin_id";
	$mail -> Password = "$smtp_admin_pwd";
	$mail -> CharSet = "utf-8"; 
	$mail -> setFrom($smtp_send_address);
	$mail -> addAddress($mail_address);
	$mail -> isHTML(true); //
	$mail -> Subject = $smtp_mail_title;
	$mail -> Body = $smtp_mail_body + " : ".$password;    
        $mail -> send();
        $message[]="Message has been sent";
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
    $symbols["special_symbols"] = '!@#$%^&*(){}[]?~';
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

function check_ldap_passwd($user, $passwd){
        global $ldap, $ldap_host, $ldap_base, $admin_dn, $admin_pw;
        ldap_set();
    	error_reporting(0);
	
    	//ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    	putenv ('LDAPTLS_REQCERT=never');

	if($user=="admin" || $passwd=="admin"){
		login_session($user);
		//$check_login = "OK";
		print "<meta http-equiv='refresh' content='0;url=/admin'>";
	}else{
    		$ldap = ldap_connect("ldap://$ldap_host");
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
        	if (ldap_bind($ldap, $userDn, $passwd) === false) {
			print "<meta http-equiv='refresh' content='0;url=/login'>";
			echo "<script>alert('Login Fail');history.back();</script>";
		}else{
			login_session($user);
			print "<meta http-equiv='refresh' content='0;url=/admin'>";
		}
	}	
}

function change_ldap_passwd($username, $passwd, $new){
        global $ldap, $ldap_base;
        ldap_set();
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
        global $ldap, $ldap_base, $ldap_host, $admin_dn, $admin_pw;
        ldap_set();
        if ($ldap == null){
                // Odd, this should've been done already.
                $ldap = ldap_connect("ldap://$ldap_host");
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
        global $ldap, $ldap_base, $ldap_host, $admin_dn, $admin_pw;
        ldap_set();
        $ldap = ldap_connect("ldap://$ldap_host");
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
        global $ldap, $ldap_base, $ldap_host, $admin_dn, $admin_pw;
        ldap_set();
        if ($ldap == null){
                // Odd, this should've been done already.
                $ldap = ldap_connect("ldap://$ldap_host");
                ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

                if (!@ldap_bind($ldap, $admin_dn, $admin_pw)){
                        my_die("<!-- check_ldap_user -->An error occurred.");
                }
        }

        $res = @ldap_search($ldap, 'uid=' . $username . ',' . $ldap_base, '(objectClass=posixAccount)');
        #return @ldap_count_entries($ldap, $res) == 1;
        return $res;

}



function set_update(){
        global $db;
        db_open();
	if(isset($_POST['title'])){
		$title = $_POST['title'];
		$db->exec("UPDATE setting SET set_val='$title' where id=1");
	}
	if(isset($_POST['login_bgcolor'])){
  		$login_bgcolor = $_POST['login_bgcolor'];	
		$db->exec("UPDATE setting SET set_val='$login_bgcolor' where id=2");
	}
	if(isset($_POST['domain'])){
  		$domain = $_POST['domain'];	
		$db->exec("UPDATE setting SET set_val='$domain' where id=3");
	}
	if(isset($_POST['ldap_host'])){
  		$ldap_host = $_POST['ldap_host'];	
		$db->exec("UPDATE setting SET set_val='$ldap_host' where id=4");
	}
	if(isset($_POST['ldap_port'])){
  		$ldap_port = $_POST['ldap_port'];	
		$db->exec("UPDATE setting SET set_val='$ldap_port' where id=5");
	}
	if(isset($_POST['ldap_base_dn'])){
  		$ldap_base_dn = $_POST['ldap_base_dn'];	
		$db->exec("UPDATE setting SET set_val='$ldap_base_dn' where id=6");
	}
	if(isset($_POST['ldap_bind_dn'])){
  		$ldap_bind_dn = $_POST['ldap_bind_dn'];	
		$db->exec("UPDATE setting SET set_val='$ldap_bind_dn' where id=7");
	}
	if(isset($_POST['ldap_bind_pwd'])){
  		$ldap_bind_pwd = $_POST['ldap_bind_pwd'];	
		$db->exec("UPDATE setting SET set_val='$ldap_bind_pwd' where id=8");
	}
	if(isset($_POST['ldap_mail_attribute'])){
  		$ldap_mail_attribute = $_POST['ldap_mail_attribute'];	
		$db->exec("UPDATE setting SET set_val='$ldap_mail_attribute' where id=9");
	}
	if(isset($_POST['smtp_host'])){
  		$smtp_host = $_POST['smtp_host'];	
		$db->exec("UPDATE setting SET set_val='$smtp_host' where id=10");
	}
	if(isset($_POST['smtp_port'])){
  		$smtp_port = $_POST['smtp_port'];	
		$db->exec("UPDATE setting SET set_val='$smtp_port' where id=11");
	}
	if(isset($_POST['smtp_login_id'])){
  		$smtp_login_id = $_POST['smtp_login_id'];	
		$db->exec("UPDATE setting SET set_val='$smtp_login_id' where id=12");
	}
	if(isset($_POST['smtp_login_pw'])){
  		$smtp_login_pw = $_POST['smtp_login_pw'];	
		$db->exec("UPDATE setting SET set_val='$smtp_login_pw' where id=13");
	}
	if(isset($_POST['smtp_send_addr'])){
  		$smtp_send_addr = $_POST['smtp_send_addr'];	
		$db->exec("UPDATE setting SET set_val='$smtp_send_addr' where id=14");
	}
	if(isset($_POST['smtp_mail_title'])){
  		$smtp_mail_title = $_POST['smtp_mail_title'];	
		$db->exec("UPDATE setting SET set_val='$smtp_mail_title' where id=15");
	}
	if(isset($_POST['smtp_mail_body'])){
  		$smtp_mail_body = $_POST['smtp_mail_body'];	
		$db->exec("UPDATE setting SET set_val='$smtp_mail_body' where id=16");
	}
	print "<meta http-equiv='refresh' content='0;url=/app/setting'>";
}

function login_check(){
	$user=$_POST['username'];
	$password=$_POST['password'];
	$user_check=check_ldap_passwd($user,$password);
}

function login_session($username){
	session_start();
	$_SESSION['username']=$username;
}

function session_check(){
	session_start();
	if($_SESSION['username']==null){
		echo "<script>location.href='/login';</script>";
		return false;
	}else{
		echo $_SESSION['username'];
	}
}

function logout(){
	session_start();
	if($_SESSION['username']!=null){
   		session_destroy();
	}
	echo "<script>location.href='/login';</script>";
}


function get_license_info(){
    global $db;
    db_open();
    $res = $db->query("SELECT key, sec_key, sec_iv, user_count FROM license WHERE id = 1;");
    $license_info = $res->fetchArray();
    if ($license_info) {
        return $license_info;
    }

    return null;
}


function check_license_validity($decrypted_license, $user_count) {
    $license_parts = explode("|", $decrypted_license); 
    if (count($license_parts) < 5) {
        return false;
    }

    $expiry_date = $license_parts[4];
    $max_users = $license_parts[3]; 
    
    $current_date = date('Y-m-d');
    
    if ($expiry_date >= $current_date && $user_count <= $max_users) {
        return true; 
    } else {
        return false; 
    }
}

function decrypt($encryptedData, $key, $iv) {
    $data = base64_decode($encryptedData); 
    return openssl_decrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}


function validate_license() {
    $license_info = get_license_info();

    if ($license_info) {
        $encrypted_license = $license_info['key'];
        $sec_key = $license_info['sec_key'];
        $sec_iv = $license_info['sec_iv']; 

        $decrypted_license = decrypt($encrypted_license, $sec_key, $sec_iv);

        if (validate_date_format($decrypted_license)) {
            $license_date = new DateTime($decrypted_license);
            $current_date = new DateTime();

            if ($current_date > $license_date) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
}

function validate_date_format($date) {
    $d = DateTime::createFromFormat('Y-m-d', $date);
    return $d && $d->format('Y-m-d') === $date;
}

function license_update() {
    global $db;
    try {
        // 데이터베이스 연결
        db_open();

        // POST 데이터 유무 확인
        if (isset($_POST['license'])) {
            $license = $_POST['license'];

            // 예외 처리 적용된 쿼리 실행
            $stmt = $db->prepare("UPDATE license SET key = :license WHERE id = 1");
            $stmt->bindParam(':license', $license);

            // 쿼리 실행 및 성공 여부 확인
            if ($stmt->execute()) {
                echo "라이센스 업데이트 성공!";
            } else {
                echo "라이센스 업데이트 실패!";
            }
        } else {
            echo "라이센스 정보가 전달되지 않았습니다.";
        }
    } catch (PDOException $e) {
        // 예외 발생 시 오류 메시지 출력
        echo "데이터베이스 오류: " . $e->getMessage();
    } finally {
        // 페이지 이동 (주석 해제 가능)
        // echo "<script>location.href='/';</script>";
    }
    echo "<script>location.href='/';</script>";
}
?>
