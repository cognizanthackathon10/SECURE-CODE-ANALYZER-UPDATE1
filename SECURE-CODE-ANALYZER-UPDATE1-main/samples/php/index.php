<?php
$mysqli = new mysqli("localhost","root","","db");

$name = $_GET['name'];
$sql = "SELECT * FROM users WHERE name = '" . $name . "'"; // SQLi
$result = $mysqli->query($sql);

echo $_GET['html']; // XSS

$hash = md5($_GET['p']); // weak crypto

if(isset($_GET['cmd'])){
    system("ls " . $_GET['cmd']); // command injection
}

try {
    throw new Exception("Boom");
} catch (Exception $e) {
    var_dump($e); // error leak
}
?>