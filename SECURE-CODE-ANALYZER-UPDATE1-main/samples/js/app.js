const express = require('express');
const app = express();
const crypto = require('crypto');
const child_process = require('child_process');

app.get('/hash', (req, res) => {
  const h = crypto.createHash('md5').update(req.query.q || 'x').digest('hex');
  res.send(h);
});

app.get('/run', (req, res) => {
  child_process.exec('ls ' + req.query.dir); // command injection
  res.send("ok");
});




app.get('/eval', (req, res) => {
  eval(req.query.code); // code injection
  res.send("done");
});

app.get('/search', (req, res) => {
  const sql = "SELECT * FROM users WHERE name = '" + req.query.name + "'"; // SQLi
  db.query(sql);
  res.send("searching");
});

app.get('/xss', (req, res) => {
  document.body.innerHTML = req.query.html; // XSS in client-side route (demo)
  res.send("done");
});
