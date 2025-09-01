// js_ast_runner.js
// Parses JavaScript code with AST and applies AST rules with context-aware checks.

const esprima = require("esprima");
const fs = require("fs");

let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input);
    const code = payload.code;
    const rules = payload.rules || [];
    const ast = esprima.parseScript(code, { loc: true });

    let findings = {};

    function walk(node, parent) {
      if (!node || typeof node !== "object") return;

      // Check against all AST rules
      for (const rule of rules) {
        if (node.type === rule.nodeType) {
          let matched = false;

          // --- Match by callee name ---
          if (node.type === "CallExpression" || node.type === "NewExpression") {
            if (node.callee) {
              const calleeName = node.callee.name || (node.callee.property && node.callee.property.name);
              const objName = node.callee.object && node.callee.object.name;

              if (rule.calleeName && calleeName === rule.calleeName) matched = true;
              if (rule.objectName && objName === rule.objectName) matched = true;

              // Check if first argument is a string literal
              if (rule.argIsString && node.arguments.length > 0 && node.arguments[0].type === "Literal" && typeof node.arguments[0].value === "string") {
                matched = true;
              }

              // Taint check: if argument contains user-controlled sources
              if (rule.sources && node.arguments.length > 0) {
                const argCode = code.substring(node.arguments[0].range ? node.arguments[0].range[0] : 0,
                                               node.arguments[0].range ? node.arguments[0].range[1] : 0);
                if (rule.sources.some(src => argCode.includes(src))) matched = true;
              }
            }
          }

          // --- Match assignments (e.g., innerHTML, window.location) ---
          if (node.type === "AssignmentExpression") {
            const left = node.left;
            if (left && left.property && rule.calleeName && left.property.name === rule.calleeName) {
              matched = true;
              if (rule.sources && node.right) {
                const rightCode = code.substring(node.right.range ? node.right.range[0] : 0,
                                                 node.right.range ? node.right.range[1] : 0);
                if (!rule.sources.some(src => rightCode.includes(src))) {
                  matched = false;
                }
              }
            }
          }

          // Record finding
          if (matched) {
            findings[rule.id] = findings[rule.id] || [];
            findings[rule.id].push(node.loc.start.line);
          }
        }
      }

      // Recurse
      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(child => walk(child, node));
        else if (val && typeof val === "object") walk(val, node);
      }
    }

    walk(ast, null);

    process.stdout.write(JSON.stringify(findings));
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: err.message }));
  }
});
