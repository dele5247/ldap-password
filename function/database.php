<?php

function db_open(){
    global $db;
    $db = new SQLite3('/var/www/html/db/testdb');
}

?>
