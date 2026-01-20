# scanners/xss_detector.py

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

USER_AGENT = "WebScanPro-XSS-Detector/1.0"
TIMEOUT = 10


def passive_xss_check(url: str):
    """
    Perform passive XSS detection on a given URL.
    No payload injection, only response analysis.
    """

    findings = []

    try:
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
    except Exception as e:
        return [{
            "type": "XSS",
            "severity": "Low",
            "issue": "Target not reachable",
            "details": str(e)
        }]

    content_type = response.headers.get("Content-Type", "")
    html = response.text

    soup = BeautifulSoup(html, "html.parser")

    # -------------------------------
    # 1. Inline JavaScript detection
    # -------------------------------
    inline_scripts = soup.find_all("script", src=False)
    if inline_scripts:
        findings.append({
            "type": "XSS",
            "severity": "Medium",
            "issue": "Inline JavaScript detected",
            "details": f"{len(inline_scripts)} inline <script> blocks found"
        })

    # -------------------------------
    # 2. Dangerous HTML attributes
    # -------------------------------
    event_attrs = [
        "onerror", "onload", "onclick", "onmouseover",
        "onfocus", "onmouseenter", "onmouseleave"
    ]

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.lower() in event_attrs:
                findings.append({
                    "type": "XSS",
                    "severity": "High",
                    "issue": "Dangerous event handler found",
                    "details": f"<{tag.name} {attr}=...>"
                })

    # -------------------------------
    # 3. Reflected parameters check
    # -------------------------------
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in params:
        pattern = re.compile(re.escape(param), re.IGNORECASE)
        if pattern.search(html):
            findings.append({
                "type": "XSS",
                "severity": "Medium",
                "issue": "Reflected parameter detected",
                "details": f"URL parameter '{param}' reflected in response"
            })

    # -------------------------------
    # 4. DOM-based sinks detection
    # -------------------------------
    dom_sinks = [
        "document.write",
        "innerHTML",
        "outerHTML",
        "eval(",
        "setTimeout(",
        "setInterval("
    ]

    for sink in dom_sinks:
        if sink in html:
            findings.append({
                "type": "XSS",
                "severity": "High",
                "issue": "Potential DOM XSS sink found",
                "details": sink
            })

    # -------------------------------
    # Final result
    # -------------------------------
    if not findings:
        findings.append({
            "type": "XSS",
            "severity": "None",
            "issue": "No passive XSS indicators found",
            "details": "Page appears safe from passive XSS checks"
        })

    return findings
