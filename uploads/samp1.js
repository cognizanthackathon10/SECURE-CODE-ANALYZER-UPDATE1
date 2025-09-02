// --- XSS ---
const params = new URLSearchParams(window.location.search);
const name = params.get("name");
document.body.innerHTML = "Hello " + name; 
// ⚠️ vulnerable: attacker can inject <script>alert(1)</script>

// --- Insecure Eval ---
const userCode = params.get("code");
eval(userCode);  
// ⚠️ vulnerable: remote code execution

// --- CSRF Simulation (No Token Check) ---
function transferMoney(amount, to) {
  fetch("/bank/transfer", {
    method: "POST",
    body: JSON.stringify({ amount, to }),
    headers: { "Content-Type": "application/json" }
  });
}
// ⚠️ vulnerable: no CSRF protection
