<?php
// vulnerable.php

// 1. Hardcoded database credentials (sensitive info disclosure)
$servername = "localhost";
$username = "root";
$password = "root123"; 
$dbname = "users_db";

// 2. No error handling in DB connection
$conn = new mysqli($servername, $username, $password, $dbname);

// 3. Unsanitized user input (SQL Injection possible)
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
$result = $conn->query($sql);

// 4. Cross-Site Scripting (XSS) – directly echoing input
echo "Welcome, " . $_GET['name'] . "!<br>";

// 5. Command Injection (passing user input to shell)
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}

// 6. File Inclusion vulnerability
if (isset($_GET['page'])) {
    include($_GET['page']); 
}

// 7. Session not started securely (missing session_start + flags)
session_start();
$_SESSION['user'] = $_GET['user'];  // no validation
?>