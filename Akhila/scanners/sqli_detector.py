# backend/sqli_detector.py
import re, requests
from urllib.parse import urlparse, parse_qs

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"unclosed quotation mark after the character string",
    r"SQLSTATE\[\d+\]",
    r"ORA-\d{5}",
    r"PG::SyntaxError",
    r"you have an error in your sql syntax",
]

def passive_sqli_check(url):
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent":"WebScanPro/1.0"})
    except Exception as e:
        return {"error": "fetch_failed", "reason": str(e)}
    html = r.text or ""
    found = []
    for p in SQL_ERROR_PATTERNS:
        if re.search(p, html, flags=re.I):
            found.append(p)
    # naive reflected param check
    reflected = []
    params = parse_qs(urlparse(url).query)
    for k, vals in params.items():
        for v in vals:
            if v and v in html:
                reflected.append({"param": k, "value": v})
    return {
        "url": url,
        "status_code": r.status_code,
        "error_signatures": found,
        "reflected_params": reflected
    }
