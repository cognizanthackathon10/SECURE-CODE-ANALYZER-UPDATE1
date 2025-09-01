// php_ast_runner.js
// Parses PHP code and applies AST rules with taint/context-aware detection.

const parser = require("php-parser");
const fs = require("fs");

const engine = new parser.Engine({
  parser: { extractDoc: true },
  ast: { withPositions: true }
});

let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input);
    const code = payload.code;
    const rules = payload.rules || [];
    const ast = engine.parseCode(code);

    let findings = {};

    function walk(node) {
      if (!node || typeof node !== "object") return;

      for (const rule of rules) {
        if (node.kind === rule.nodeType) {
          let matched = false;

          // Function calls
          if (node.kind === "call" && node.what && node.what.name) {
            const fn = node.what.name.toLowerCase();
            if (rule.calleeName && fn === rule.calleeName.toLowerCase()) {
              matched = true;

              // Taint analysis
              if (rule.sources && node.arguments.length > 0) {
                const argDump = JSON.stringify(node.arguments);
                if (rule.sources.some(src => argDump.includes(src))) {
                  matched = true;
                }
              }

              // Pattern check (preg_replace /e)
              if (rule.patternCheck && node.arguments.length > 0) {
                const argDump = JSON.stringify(node.arguments[0]);
                if (argDump.includes(rule.patternCheck)) matched = true;
              }
            }
          }

          // Include/require
          if (["include", "includeonce", "require", "requireonce"].includes(node.kind) && rule.nodeType === "include") {
            matched = true;
            if (rule.sources && node.target) {
              const argDump = JSON.stringify(node.target);
              if (!rule.sources.some(src => argDump.includes(src))) {
                matched = false;
              }
            }
          }

          if (matched) {
            findings[rule.id] = findings[rule.id] || [];
            findings[rule.id].push(node.loc.start.line);
          }
        }
      }

      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(walk);
        else if (val && typeof val === "object") walk(val);
      }
    }

    walk(ast);

    process.stdout.write(JSON.stringify(findings));
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: err.message }));
  }
});
