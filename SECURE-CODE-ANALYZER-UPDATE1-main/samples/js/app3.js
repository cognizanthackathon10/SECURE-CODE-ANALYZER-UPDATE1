/*// app3.js - AST advanced rule tests

// 1. setTimeout with string → should trigger JS-SETTIMEOUT-STRING-AST
setTimeout("alert('XSS')", 1000);

// 2. localStorage storing a password → should trigger JS-LOCALSTORAGE-AST
localStorage.setItem("password", "12345");

// 3. DOM-based XSS: assigning window.location to innerHTML → should trigger JS-DOMXSS-AST
document.getElementById("demo").innerHTML = window.location;*/
