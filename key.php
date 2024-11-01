<?php
// 16바이트의 IV를 무작위로 생성 (AES-256-CBC는 16바이트 IV 필요)
$sec_iv = openssl_random_pseudo_bytes(16); // 16바이트 IV 생성
$sec_iv_base64 = base64_encode($sec_iv); // Base64로 인코딩

// 32바이트의 키를 무작위로 생성 (AES-256은 32바이트 키 필요)
$sec_key = openssl_random_pseudo_bytes(32); // 32바이트 키 생성
$sec_key_base64 = base64_encode($sec_key); // Base64로 인코딩

// 결과 출력
echo "sec_iv (Base64): " . $sec_iv_base64 . "\n";
echo "sec_key (Base64): " . $sec_key_base64 . "\n";
?>
