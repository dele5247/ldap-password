<?php
include $_SERVER["DOCUMENT_ROOT"]."/function/common.php";

if (validate_license()) {
  include $_SERVER["DOCUMENT_ROOT"]."/html/password.html";
}else{
  include $_SERVER["DOCUMENT_ROOT"]."/html/lockpage.html";
}
echo validate_license();
?>


