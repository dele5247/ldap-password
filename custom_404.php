<?php
if (!file_exists($requested_page)) {
    header("HTTP/1.0 404 Not Found");
    header("Location: /error.php");
    exit();
}
