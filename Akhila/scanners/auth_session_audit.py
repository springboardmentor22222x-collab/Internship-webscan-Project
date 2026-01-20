# scanners/auth_session_audit.py

import requests

def auth_session_check(url: str):
    results = []

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
    except Exception as e:
        return [{
            "type": "Authentication / Session",
            "severity": "Low",
            "issue": "Request failed",
            "details": str(e)
        }]

    cookies = response.cookies

    if not cookies:
        results.append({
            "type": "Authentication / Session",
            "severity": "Medium",
            "issue": "No session cookies detected",
            "details": "Application may not be using sessions properly"
        })
    else:
        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append("Secure flag missing")

            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag missing")

            severity = "High" if issues else "Low"

            results.append({
                "type": "Authentication / Session",
                "severity": severity,
                "issue": "Session cookie analysis",
                "details": {
                    "cookie": cookie.name,
                    "issues": issues if issues else "No obvious issues"
                }
            })

    return results
