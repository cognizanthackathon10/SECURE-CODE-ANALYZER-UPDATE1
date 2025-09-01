/*// ==========================
// Broken Access Control
// ==========================
// JS-CLIENT-AUTH-001
if (user.role === "admin") {
    console.log("Admin section visible!"); // BAD: client-side auth check
}

// ==========================
// Insecure Design
// ==========================
// JS-DISABLE-CSP-001
const cspHeader = "Content-Security-Policy: default-src 'self' 'unsafe-inline'";

// ==========================
// Outdated Component
// ==========================
// JS-JQUERY-OLD-001
const jqueryVer = "jquery-1.12.4.min.js";

// ==========================
// SSRF
// ==========================
// JS-SSRF-001
const userUrl = "http://" + window.location.search.replace("?url=", "");
fetch(userUrl);

// ==========================
// Info Disclosure
// ==========================
// JS-CONSOLE-001
console.log("Debug: reached end of app2.js");*/
