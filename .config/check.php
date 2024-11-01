<?php
$argv = $_SERVER['argv'];
require_once '/var/www/html/config/config.php';
require_once '/var/www/html/function/database.php';
require_once '/var/www/html/function/setup.php';

// 명령줄 인수 확인
if ($argc < 2) {
    echo "사용법: php -q check.php <키를 생성할 날짜나 문자열>\n";
    exit(1); // 오류 코드로 종료
}

// 명령줄 인수를 받아 변수로 사용
$inputVariable = $argv[1]; // 첫 번째 인수 (예: 2024-12-03)

// 암호화 함수
function encrypt($data, $key, $iv) {
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($encrypted); // Base64 인코딩하여 출력
}

// 복호화 함수
function decrypt($encryptedData, $key, $iv) {
    $data = base64_decode($encryptedData); // Base64 디코딩
    return openssl_decrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

// 데이터베이스에서 라이선스 정보를 가져오는 함수
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

// 라이선스 정보 가져오기
$license_info = get_license_info();
if (!$license_info) {
    echo "라이선스 정보를 가져올 수 없습니다.\n";
    exit(1);
}

// Base64로 인코딩된 키와 IV를 디코딩 (필요시 적용)
$iv = $license_info['sec_iv'];
$key = $license_info['sec_key'];

// 키와 IV가 올바른 길이인지 확인
if (strlen($iv) !== 16 || strlen($key) !== 32) {
    echo "IV 또는 키의 길이가 올바르지 않습니다.\n";
    exit(1);
}

// 암호화할 데이터
$originalData =$inputVariable;

// 암호화
$encryptedData = encrypt($originalData, $key, $iv);
echo "암호화된 데이터: " . $encryptedData . "\n";

// 복호화
//$decryptedData = decrypt($encryptedData, $key, $iv);
//echo "복호화된 데이터: " . $decryptedData . "\n";



function validate_license() {
    // 라이선스 정보를 가져옴
    $license_info = get_license_info();

    if ($license_info) {
        $encrypted_license = $license_info['key'];
        $sec_key = $license_info['sec_key']; // Base64 디코딩
        $sec_iv = $license_info['sec_iv'];   // Base64 디코딩

        // 라이선스 복호화
        $decrypted_license = decrypt($encrypted_license, $sec_key, $sec_iv);

        // 날짜 형식으로 복호화된 값이 나오는지 확인
        if (validate_date_format($decrypted_license)) {
            $license_date = new DateTime($decrypted_license);
            $current_date = new DateTime();

            // 만료 확인: 현재 날짜가 라이선스 날짜를 지났는지 확인
            if ($current_date > $license_date) {
                echo "잘못된 라이센스: 라이센스가 만료되었습니다.\n";
            } else {
                echo "정상적인 라이센스: 유효한 라이센스입니다.\n";
            }
        } else {
            echo "잘못된 라이센스: 복호화된 값이 유효한 날짜 형식이 아닙니다.\n";
        }
    } else {
        echo "라이선스 정보를 가져올 수 없습니다.\n";
    }
}

// 날짜 형식을 확인하는 함수 (예: '2024-12-03' 형태 확인)
function validate_date_format($date) {
    $d = DateTime::createFromFormat('Y-m-d', $date);
    return $d && $d->format('Y-m-d') === $date;
}


$aa=validate_license();
echo "결과: $aa";

?>
