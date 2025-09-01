SEVERITY_LEVELS = {
    "critical": {
        "rank": 4,
        "description": "Critical risk. Exploitable remotely. Can fully compromise confidentiality, integrity, or availability.",
        "action": "Fix immediately before deployment."
    },
    "high": {
        "rank": 3,
        "description": "High risk. Leads to serious security issues such as injection or RCE.",
        "action": "Fix urgently and add test coverage."
    },
    "medium": {
        "rank": 2,
        "description": "Moderate risk. Exploitable with some conditions, may lead to data leakage or weaker attacks.",
        "action": "Fix in the next sprint / release."
    },
    "low": {
        "rank": 1,
        "description": "Low risk. Minor information leaks or bad practices.",
        "action": "Fix when convenient / monitor."
    },
    "info": {
        "rank": 0,
        "description": "Informational only. No immediate security impact.",
        "action": "Review and ignore if acceptable."
    }
}


def normalize_severity(sev: str):
    return sev.lower() if sev.lower() in SEVERITY_LEVELS else "info"


def severity_worse_or_equal(a, b):
    """Return True if severity a is worse or equal to b."""
    return SEVERITY_LEVELS[normalize_severity(a)]["rank"] >= SEVERITY_LEVELS[normalize_severity(b)]["rank"]


def sort_by_severity(issues):
    """Sort issues by severity rank (critical > high > medium > low > info)."""
    return sorted(issues, key=lambda i: SEVERITY_LEVELS[normalize_severity(i["severity"])]["rank"], reverse=True)
