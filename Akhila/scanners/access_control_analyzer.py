# scanners/access_control_analyzer.py

import requests

def access_control_check(url: str):
    results = []

    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
    except Exception as e:
        return [{
            "type": "Access Control",
            "severity": "Low",
            "issue": "Request failed",
            "details": str(e)
        }]

    if r.status_code in [401, 403]:
        results.append({
            "type": "Access Control",
            "severity": "Medium",
            "issue": "Protected resource detected",
            "details": f"HTTP {r.status_code} response"
        })
    else:
        results.append({
            "type": "Access Control",
            "severity": "Low",
            "issue": "No obvious access control issue",
            "details": "Endpoint accessible"
        })

    return results
