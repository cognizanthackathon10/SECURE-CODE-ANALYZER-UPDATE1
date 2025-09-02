<?php
// ==============================================
//  Simple Vulnerable PHP App (FOR TESTING ONLY)
// ==============================================

// Database connection (weak - no error handling, root/no password)
$conn = mysqli_connect("localhost", "root", "", "testdb");
if (!$conn) {
    die("DB Connection Failed: " . mysqli_connect_error());
}

// ----------------------------------------------
// 1. LOGIN FORM (SQL INJECTION)
// ----------------------------------------------
if (isset($_POST['login'])) {
    $username = $_POST['username']; // no sanitization
    $password = $_POST['password']; // no sanitization

    $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = mysqli_query($conn, $sql);

    if (mysqli_num_rows($result) > 0) {
        echo "<h3>Welcome, $username!</h3>"; // XSS also possible here
    } else {
        echo "<h3>Login failed!</h3>";
    }
}

// ----------------------------------------------
// 2. COMMAND EXECUTION (Command Injection)
// ----------------------------------------------
if (isset($_GET['ping'])) {
    $host = $_GET['ping'];
    echo "<pre>";
    system("ping -c 2 " . $host); // vulnerable
    echo "</pre>";
}

// ----------------------------------------------
// 3. FILE INCLUSION (LFI/RFI)
// ----------------------------------------------
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page . ".php"); // vulnerable
}

// ----------------------------------------------
// 4. FILE UPLOAD (Insecure Upload)
// ----------------------------------------------
if (isset($_POST['upload'])) {
    $filename = $_FILES['file']['name'];
    $tmp = $_FILES['file']['tmp_name'];

    // No validation: attacker can upload .php shell
    move_uploaded_file($tmp, $filename);
    echo "<p>File uploaded as $filename</p>";
}

// ----------------------------------------------
// 5. SEARCH FEATURE (Reflected XSS)
// ----------------------------------------------
if (isset($_GET['search'])) {
    $term = $_GET['search'];
    echo "<p>Results for: $term</p>"; // vulnerable: XSS
    // Fake DB search
    echo "<p>No results found.</p>";
}

// ----------------------------------------------
// 6. SESSION HANDLING (Weak)
// ----------------------------------------------
session_start();
if (isset($_GET['setname'])) {
    $_SESSION['user'] = $_GET['setname']; // session poisoning risk
}
if (isset($_SESSION['user'])) {
    echo "<p>Session User: " . $_SESSION['user'] . "</p>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable PHP App</title>
</head>
<body>
    <h2>Login Form (SQL Injection)</h2>
    <form method="POST">
        Username: <input type="text" name="username"><br><br>
        Password: <input type="password" name="password"><br><br>
        <input type="submit" name="login" value="Login">
    </form>

    <h2>Command Execution (Command Injection)</h2>
    <form method="GET">
        Host to Ping: <input type="text" name="ping">
        <input type="submit" value="Ping">
    </form>

    <h2>File Upload (Insecure)</h2>
    <form method="POST" enctype="multipart/form-data">
        Select file: <input type="file" name="file">
        <input type="submit" name="upload" value="Upload">
    </form>

    <h2>Search (Reflected XSS)</h2>
    <form method="GET">
        Search: <input type="text" name="search">
        <input type="submit" value="Search">
    </form>

    <h2>Page Include (LFI/RFI)</h2>
    <a href="?page=about">Load About Page</a><br>
    <a href="?page=../../etc/passwd">Try LFI</a>
</body>
</html>
