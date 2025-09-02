<?php
// ==========================
// Broken Access Control
// ==========================
// PHP-AUTH-CHECK-001
if ($_GET['role'] === 'admin') {
    echo "Admin panel visible!"; // BAD: user-controlled auth
}

// ==========================
// Insecure Design
// ==========================
// PHP-HARDCODED-SECRET-002
$secret = "mySuperSecretApiKey123";

// ==========================
// Outdated Component
// ==========================
// PHP-OUTDATED-MYSQL-001
$conn = mysql_connect("localhost", "root", "password");

// ==========================
// SSRF
// ==========================
// PHP-SSRF-001
$url = $_GET['url'];
$response = file_get_contents("http://" . $url);

// ==========================
// Path Traversal
// ==========================
// PHP-FILE-READ-001
$filename = $_GET['file'];
$data = file_get_contents($filename);

echo "Done.";
?>
