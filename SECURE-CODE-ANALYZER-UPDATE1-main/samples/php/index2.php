<?php
// 1. Remote Code Execution (RCE) with eval
$code = $_GET['code'];
eval($code); // ❌ Dangerous

// 2. Command Injection
$file = $_GET['file'];
system("cat " . $file); // ❌ Dangerous

// 3. SQL Injection
$conn = mysqli_connect("localhost", "root", "root123", "testdb");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id"; // ❌ SQL Injection
$result = mysqli_query($conn, $query);

// 4. Weak Cryptography
$password = "mypassword";
$hash1 = md5($password);   // ❌ Weak hash
$hash2 = sha1($password);  // ❌ Weak hash

// 5. File Inclusion (LFI/RFI)
$page = $_GET['page'];
include($page . ".php"); // ❌ Insecure include

// 6. XSS
$name = $_GET['name'];
echo "Hello " . $name; // ❌ XSS if user injects <script>

// 7. Poor Error Handling
ini_set('display_errors', 1); // ❌ Exposes sensitive info

// 8. Hardcoded Secrets
$db_user = "admin";
$db_pass = "supersecret123"; // ❌ Hardcoded secret

// 9. Insecure File Upload
if (isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']); // ❌ No checks
}

// 10. Session Hijacking
session_start(); // ❌ No secure cookie flags
$_SESSION['user'] = "testuser";

echo "User logged in: " . $_SESSION['user'];
?>