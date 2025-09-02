<?php
// index4.php - AST advanced rule tests

// 1. preg_replace with /e modifier → should trigger PHP-PREG-REPLACE-E-AST
$input = "Hello";
echo preg_replace("/.*/e", "system('ls')", $input);

// 2. unserialize on user input ($_GET) → should trigger PHP-UNSERIALIZE-AST
$data = $_GET['payload'];
$obj = unserialize($data);

// 3. include with tainted source → should trigger PHP-INCLUDE-AST
$file = $_GET['page'];
include($file);
?>
