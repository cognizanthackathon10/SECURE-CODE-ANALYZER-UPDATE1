/*
 * vuln-sample.js — INTENTIONALLY INSECURE EXAMPLES
 * -------------------------------------------------
 * This single-file “grab bag” showcases common JavaScript anti-patterns and
 * insecure sinks for you to build scanners (regex/AST/taint) against.
 *
 * ⚠️ DO NOT use this code in production. It is purposely vulnerable.
 *
 * Each snippet is prefixed with:  // VULN: [id] — short title — what/why
 * IDs are stable so your analyzer can point to them.
 */

/*************************
 * Helpers / mock inputs  *
 *************************/
function getParam(name) {
  // naive query param parser (itself intentionally sloppy)
  const m = new RegExp('[?&]' + name + '=([^&#]*)').exec(location.search);
  return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : '';
}

// Simulate untrusted data sources
const SRC = {
  hash: () => location.hash.slice(1),
  q: () => getParam('q'),
  json: () => getParam('json'),
  url: () => getParam('url'),
  html: () => getParam('html'),
  code: () => getParam('code'),
  target: () => getParam('target'),
  token: () => getParam('token'),
  re: () => getParam('re'),
  msg: () => getParam('msg')
};

/****************************************
 * 1) DOM XSS sinks (innerHTML family)  *
 ****************************************/
(function domXss() {
  const container = document.getElementById('out1') || document.body;

  // VULN: V001 — DOM XSS — innerHTML sink fed by location.hash (source)
  const untrusted1 = SRC.hash(); // SOURCE
  container.innerHTML = '<h3>Search:</h3>' + untrusted1; // SINK

  // VULN: V002 — DOM XSS — insertAdjacentHTML with user q param
  const untrusted2 = SRC.q(); // SOURCE
  container.insertAdjacentHTML('beforeend', '<div class="result">' + untrusted2 + '</div>'); // SINK

  // VULN: V003 — DOM XSS — document.write with untrusted html
  const untrusted3 = SRC.html(); // SOURCE
  if (untrusted3) {
    document.write('<section>' + untrusted3 + '</section>'); // SINK
  }
})();

/*******************************************
 * 2) Code injection (eval / Function etc) *
 *******************************************/
(function codeInjection() {
  // VULN: V004 — Code Injection — eval on user-controlled string
  const code = SRC.code(); // SOURCE
  if (code) {
    eval(code); // SINK
  }

  // VULN: V005 — Code Injection — new Function from untrusted input
  const fnBody = SRC.code(); // SOURCE
  if (fnBody) {
    const f = new Function('return (' + fnBody + ')'); // SINK
    try { f(); } catch (e) {}
  }

  // VULN: V006 — Code Injection — setTimeout with string
  const later = SRC.code(); // SOURCE
  if (later) setTimeout(later, 50); // SINK (string form)
})();

/**************************************
 * 3) Open redirect / URL assignment  *
 **************************************/
(function openRedirect() {
  // VULN: V007 — Open Redirect — location.href assigned from user input
  const t = SRC.target(); // SOURCE
  if (t) {
    // Dangerous: no allowlist/URL validation
    // Uncomment to observe redirect behavior in a test harness.
    // location.href = t; // SINK
  }
})();

/*****************************************
 * 4) Insecure fetch / CORS credentials  *
 *****************************************/
(async function insecureFetch() {
  // VULN: V008 — Data exfil / CORS — user-controlled URL with credentials: include
  const u = SRC.url(); // SOURCE
  if (u) {
    try {
      const res = await fetch(u, { credentials: 'include' }); // SINK
      console.log('Fetched length (insecure):', (await res.text()).length);
    } catch (e) {}
  }
})();

/*************************
 * 5) Insecure storage   *
 *************************/
(function storage() {
  // VULN: V009 — Insecure Storage — JWT placed in localStorage (readable by XSS)
  const t = SRC.token(); // SOURCE
  if (t) {
    localStorage.setItem('authToken', t); // SINK
  }

  // VULN: V010 — Weak cookie flags — cookie set without Secure/SameSite
  document.cookie = 'session=' + encodeURIComponent(SRC.token() || 'demo') + '; path=/'; // SINK
})();

/*******************************
 * 6) Insecure randomness      *
 *******************************/
(function weakRandomness() {
  // VULN: V011 — Insecure Randomness — security token via Math.random
  const token = Math.random().toString(36).slice(2); // SINK
  console.log('Weak token:', token);
})();

/********************************
 * 7) Prototype pollution demo  *
 ********************************/
(function protoPollution() {
  // VULN: V012 — Prototype Pollution — merge JSON with __proto__ into target options
  const raw = SRC.json(); // e.g. {"__proto__":{"pwned":true}}
  if (!raw) return;
  try {
    const user = JSON.parse(raw); // SOURCE
    const defaults = { safe: true };
    // naive deep merge
    function deepMerge(t, s) {
      for (const k in s) {
        if (s[k] && typeof s[k] === 'object') t[k] = deepMerge(t[k] || {}, s[k]);
        else t[k] = s[k];
      }
      return t;
    }
    const opts = deepMerge({}, defaults);
    deepMerge(opts, user); // SINK — will traverse __proto__
    // If polluted, any {} now inherits attacker props
    const check = {};
    console.log('Polluted?', (check).pwned === true);
  } catch (e) {}
})();

/****************************************
 * 8) Event handler attribute injection *
 ****************************************/
(function handlerInjection() {
  // VULN: V013 — Event Handler Injection — setting on* attribute from user string
  const btn = document.getElementById('dangerBtn') || document.createElement('button');
  btn.id = 'dangerBtn';
  btn.textContent = 'Danger';
  const handler = SRC.code(); // SOURCE
  if (handler) {
    btn.setAttribute('onclick', handler); // SINK
  }
  document.body.appendChild(btn);
})();

/**************************
 * 9) ReDoS via regex     *
 **************************/
(function redos() {
  // VULN: V014 — ReDoS — catastrophic backtracking from user-supplied pattern
  const pattern = SRC.re(); // SOURCE
  if (!pattern) return;
  try {
    const re = new RegExp(pattern); // SINK
    const s = 'a'.repeat(50000) + '!';
    console.log('Testing user regex length=', pattern.length);
    re.test(s); // can hang
  } catch (e) {}
})();

/*******************************************
 * 10) postMessage origin/data trust issues *
 *******************************************/
(function postMessageTrust() {
  // VULN: V015 — postMessage — trusting any origin and executing data
  window.addEventListener('message', (ev) => {
    // Missing origin allowlist check and data validation
    if (typeof ev.data === 'string' && ev.data.startsWith('RUN:')) {
      const payload = ev.data.slice(4); // SOURCE
      eval(payload); // SINK
    }
  });
})();

/************************************************
 * 11) Dangerous URL construction + innerHTML    *
 ************************************************/
(function dangerousURL() {
  // VULN: V016 — HREF/HTML — building HTML with unsanitized href
  const u = SRC.url(); // SOURCE
  if (!u) return;
  const a = document.createElement('div');
  a.innerHTML = '<a href="' + u + '">go</a>'; // SINK
  document.body.appendChild(a);
})();

/*****************************************
 * 12) Dangerous setAttribute on style    *
 *****************************************/
(function cssInjection() {
  // VULN: V017 — CSS Injection — unsanitized style attribute
  const v = SRC.html(); // SOURCE (could contain url("javascript:..."))
  if (!v) return;
  const el = document.createElement('div');
  el.setAttribute('style', v); // SINK
  document.body.appendChild(el);
})();

/*****************************************
 * 13) Dangerous URL in fetch headers     *
 *****************************************/
(async function headerInjection() {
  // VULN: V018 — Header Injection — user-controlled header value
  const msg = SRC.msg(); // SOURCE
  if (!msg) return;
  try {
    await fetch('/api/echo', { headers: { 'X-Note': msg } }); // SINK (potential splitting on some servers)
  } catch (e) {}
})();

/*****************************************
 * 14) Dangerous innerHTML += (implicit)  *
 *****************************************/
(function implicitPlusEqual() {
  // VULN: V019 — DOM XSS — innerHTML += pattern (reads/rewrites HTML)
  const extra = SRC.html(); // SOURCE
  if (!extra) return;
  const c = document.getElementById('out2') || document.body;
  c.innerHTML += '<p>' + extra + '</p>'; // SINK
})();

/*****************************************
 * 15) Dangerous URL: javascript: scheme   *
 *****************************************/
(function javascriptScheme() {
  // VULN: V020 — JS URL — setting href/location to javascript: without blocking
  const u = SRC.url(); // SOURCE (e.g., javascript:alert(1))
  if (!u) return;
  const link = document.createElement('a');
  link.href = u; // SINK
  document.body.appendChild(link);
})();

/****************************
 * End of insecure samples  *
 ****************************/
