import re
import json
import os
import subprocess

# ========================
# Load rules from rules.json
# ========================
RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # go up from /core
    "rules",
    "rules.json"
)

with open(RULES_PATH, "r", encoding="utf-8") as f:
    RULES = json.load(f)

# ========================
# AST Runner Paths
# ========================
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)

JS_AST_RUNNER = os.path.join(PROJECT_ROOT, "js_ast_runner.js")
PHP_AST_RUNNER = os.path.join(PROJECT_ROOT, "php_ast_runner.js")

print("JS_AST_RUNNER:", JS_AST_RUNNER)
print("PHP_AST_RUNNER:", PHP_AST_RUNNER)


# ========================
# AST Runner Helper
# ========================
def run_node_ast_runner(runner, code, ast_rules):
    """
    Run Node.js AST helper once and return parsed matches.
    We now also pass the AST rules so the runner knows about
    taint-aware / context-aware detection.
    """
    try:
        proc = subprocess.run(
            ["node", runner],
            input=json.dumps({"code": code, "rules": ast_rules}).encode("utf-8"),
            capture_output=True,
            check=True
        )
        return json.loads(proc.stdout.decode("utf-8"))
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}


# ========================
# Rule-based detector
# ========================
def run_detectors(code, file_path):
    issues = []

    # Detect language by file extension
    lang = "javascript" if file_path.endswith(".js") else "php" if file_path.endswith(".php") else None
    if not lang:
        return issues

    # Separate regex, AST, and Context-AST rules
    regex_rules      = [r for r in RULES if r["language"] == lang and r["type"] == "regex"]
    ast_rules        = [r for r in RULES if r["language"] == lang and r["type"] == "ast"]
    context_ast_rules = [r for r in RULES if r["language"] == lang and r["type"] == "context-ast"]


    # --- Regex rules ---
    for rule in regex_rules:
        for match in re.finditer(rule["pattern"], code, flags=re.IGNORECASE):
            line_no = code[:match.start()].count("\n") + 1
            issues.append({
                "id": rule["id"],
                "file": file_path,
                "line": line_no,
                "severity": rule["severity"].upper(),
                "category": rule["category"],
                "message": rule["message"],
                "suggestion": rule["suggestion"],
                "owasp": rule.get("owasp", ""),
                "cwe": rule.get("cwe", ""),
                "snippet": code.splitlines()[line_no - 1].strip(),
                "detected_by": "Regex"
            })

    # --- AST rules ---
    if ast_rules:
        runner = JS_AST_RUNNER if lang == "javascript" else PHP_AST_RUNNER
        result = run_node_ast_runner(runner, code, ast_rules)

        if "error" in result:
            error_msg = result["error"]

            # Try to extract line number from error message
            line_no = 0
            m = re.search(r"[Ll]ine\s+(\d+)", error_msg)
            if m:
                try:
                    line_no = int(m.group(1))
                except ValueError:
                    line_no = 0

            snippet = ""
            if line_no > 0 and line_no <= len(code.splitlines()):
                snippet = code.splitlines()[line_no - 1].strip()

            issues.append({
                "id": f"{lang.upper()}-AST-PARSE-ERROR",
                "file": file_path,
                "line": line_no,
                "severity": "LOW",
                "category": "Parser",
                "message": f"{lang.upper()} AST parse error: {error_msg}",
                "suggestion": "Check syntax or Node.js runner configuration.",
                "owasp": "",
                "cwe": "",
                "snippet": snippet,
                "detected_by": "AST"
            })
        else:
            for rule in ast_rules:
                matched_lines = result.get(rule["id"], [])
                for line_no in matched_lines:
                    issues.append({
                        "id": rule["id"],
                        "file": file_path,
                        "line": line_no,
                        "severity": rule["severity"].upper(),
                        "category": rule["category"],
                        "message": rule["message"],
                        "suggestion": rule["suggestion"],
                        "owasp": rule.get("owasp", ""),
                        "cwe": rule.get("cwe", ""),
                        "snippet": code.splitlines()[line_no - 1].strip() if line_no > 0 else "",
                        "detected_by": "AST"
                    })

    # --- Context-AST rules ---
    if context_ast_rules:
        runner = JS_AST_RUNNER if lang == "javascript" else PHP_AST_RUNNER
        result = run_node_ast_runner(runner, code, context_ast_rules)
        
        if "error" not in result:
            for rule in context_ast_rules:
                matched_lines = result.get(rule["id"], [])
                for line_no in matched_lines:
                    issues.append({
                        "id": rule["id"],
                        "file": file_path,
                        "line": line_no,
                        "severity": rule["severity"].upper(),
                        "category": rule["category"],
                        "message": rule["message"],
                        "suggestion": rule["suggestion"],
                        "owasp": rule.get("owasp", ""),
                        "cwe": rule.get("cwe", ""),
                        "snippet": code.splitlines()[line_no - 1].strip() if line_no > 0 else "",
                        "detected_by": "Context-AST"
                    })
                

    # --- Deduplication + Merge ---
    deduped = {}
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for issue in issues:
        key = (issue["file"], issue["line"], issue["snippet"])
        existing = deduped.get(key)

        if not existing:
            deduped[key] = issue
        else:
            # pick higher severity
            if sev_order[issue["severity"]] > sev_order[existing["severity"]]:
                merged = issue
            else:
                merged = existing

            # merge messages/suggestions
            merged["message"] = f"{existing['message']} | {issue['message']}"
            merged["suggestion"] = f"{existing['suggestion']} | {issue['suggestion']}"

            # merge detectors with Context-AST priority
            detected_set = set(existing["detected_by"].split("+")) | set(issue["detected_by"].split("+"))
            if "Context-AST" in detected_set:
                merged["detected_by"] = "Context-AST"
            else:
                merged["detected_by"] = "+".join(sorted(detected_set))

            # merge OWASP tags
            owasp_set = set(filter(None, existing.get("owasp", "").split(","))) | \
                        set(filter(None, issue.get("owasp", "").split(",")))
            merged["owasp"] = ",".join(sorted(owasp_set))

            # merge CWE tags
            cwe_set = set(filter(None, existing.get("cwe", "").split(","))) | \
                      set(filter(None, issue.get("cwe", "").split(",")))
            merged["cwe"] = ",".join(sorted(cwe_set))

            deduped[key] = merged

    return list(deduped.values())


# ========================
# Main detector entry
# ========================
def detect_issues(file_path):
    """Read file and run rule-based detectors."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        return [{
            "id": "FILE-ERROR",
            "file": file_path,
            "line": 0,
            "severity": "LOW",
            "category": "I/O",
            "message": f"Error reading file: {e}",
            "suggestion": "Check file path and permissions.",
            "detected_by": "System",
            "owasp": "",
            "cwe": "",
            "snippet": ""
        }]

    return run_detectors(code, file_path)
