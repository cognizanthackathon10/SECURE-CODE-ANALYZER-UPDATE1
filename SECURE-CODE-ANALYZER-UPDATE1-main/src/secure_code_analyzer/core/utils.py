import re

def strip_comments_and_strings(text, language):
    """
    Remove comments and string literals to reduce false positives for pattern rules.
    Very naive but effective for demo purposes.
    """
    if language in ("javascript", "php"):
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
        text = re.sub(r'//.*', ' ', text)
        if language == "php":
            text = re.sub(r'#.*', ' ', text)
    text = re.sub(r"(\'(?:\\.|[^\\'])*\'|\"(?:\\.|[^\\\"])*\"|`(?:\\.|[^\\`])*`)", '""', text)
    return text


def filter_issues(issues, severity=None):
    """
    Filter issues by severity if provided.
    """
    if severity:
        return [i for i in issues if i.get("severity") == severity]
    return issues


def sort_issues(issues, key="severity"):
    """
    Sort issues by a given key (default: severity).
    """
    return sorted(issues, key=lambda x: x.get(key, ""))
