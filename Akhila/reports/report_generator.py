# reports/report_generator.py

import os
from collections import Counter
from datetime import datetime


def generate_report_html(target_url, vulnerabilities):
    os.makedirs("reports/output", exist_ok=True)

    severity_count = Counter(v["severity"] for v in vulnerabilities)

    rows = ""
    for v in vulnerabilities:
        rows += f"""
        <tr>
            <td>{v["vulnerability"]}</td>
            <td>{v["endpoint"]}</td>
            <td class="{v["severity"]}">{v["severity"]}</td>
            <td>{v["mitigation"]}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro Security Report</title>
    <style>
        body {{ font-family: Arial; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background: #f4f4f4; }}
        .High {{ color: red; font-weight: bold; }}
        .Medium {{ color: orange; font-weight: bold; }}
        .Low {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>

<h1>WebScanPro – Vulnerability Scan Report</h1>

<p><b>Target:</b> {target_url}</p>
<p><b>Scan Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

<h2>Summary</h2>
<ul>
    <li>Total vulnerabilities: {len(vulnerabilities)}</li>
    <li>High: {severity_count.get("High", 0)}</li>
    <li>Medium: {severity_count.get("Medium", 0)}</li>
    <li>Low: {severity_count.get("Low", 0)}</li>
</ul>

<h2>Detailed Findings</h2>

<table>
<tr>
    <th>Vulnerability</th>
    <th>Affected Endpoint</th>
    <th>Severity</th>
    <th>Suggested Mitigation</th>
</tr>

{rows}

</table>

</body>
</html>
"""

    output_path = "reports/output/webscanpro_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
