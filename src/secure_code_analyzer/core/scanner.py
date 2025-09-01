from .severity import normalize_severity, severity_worse_or_equal, sort_by_severity
from .detectors import detect_issues


def scan_file(file_path):
    """
    Scan a file for security issues using regex + AST detectors.
    Always returns a list of issues (possibly empty).
    """
    try:
        issues = detect_issues(file_path)
    except Exception as e:
        return [{
            "file": file_path,
            "line": 0,
            "severity": "LOW",
            "message": f"Error scanning file: {e}",
            "id": "SCAN_ERROR"
        }]
    return issues


def filter_issues(issues, min_severity="low"):
    normalized_min = normalize_severity(min_severity)
    return [i for i in issues if severity_worse_or_equal(i["severity"], normalized_min)]


def sort_issues(issues):
    return sort_by_severity(issues)


def print_summary(issues):
    """
    Always print a summary, even if no issues are found.
    """
    if not issues:
        print("✅ No issues found.")
    else:
        print(f"⚠️ Found {len(issues)} issue(s):")
        for issue in issues:
            print(f" - {issue['file']}:{issue['line']} [{issue['severity']}] {issue['message']}")
