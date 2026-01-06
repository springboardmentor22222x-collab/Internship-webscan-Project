import datetime
import webbrowser
import os

# === DATA FROM OUR SCANS ===
# These are the actual findings from your previous weeks
scan_results = [
    {
        "type": "SQL Injection (SQLi)",
        "severity": "High",
        "url": "http://localhost/vulnerabilities/sqli/",
        "payload": "' OR '1'='1",
        "detail": "Database error and data dump detected. The 'id' parameter is not sanitized.",
        "mitigation": "Use prepared statements (parameterized queries) instead of string concatenation."
    },
    {
        "type": "Reflected Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "url": "http://localhost/vulnerabilities/xss_r/",
        "payload": "<script>alert('XSS')</script>",
        "detail": "The application reflects user input from the 'name' parameter without encoding.",
        "mitigation": "Sanitize input and Encode output (convert special characters to HTML entities)."
    },
    {
        "type": "Weak Authentication (Brute Force)",
        "severity": "High",
        "url": "http://localhost/vulnerabilities/brute/",
        "payload": "password (found for user 'admin')",
        "detail": "Admin password was cracked using a dictionary attack.",
        "mitigation": "Enforce strong password policies and implement account lockout after failed attempts."
    },
    {
        "type": "Insecure Direct Object Reference (IDOR)",
        "severity": "High",
        "url": "http://localhost/vulnerabilities/sqli/",
        "payload": "id=1, id=2, id=3...",
        "detail": "Horizontal privilege escalation. User can view other users' data by changing the ID in the URL.",
        "mitigation": "Implement proper access control checks to verify user permissions before returning objects."
    }
]

def generate_html_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = "WebScanPro_Report.html"
    
    # HTML Structure
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WebScanPro Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; }}
            .container {{ background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .timestamp {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
            .summary {{ background-color: #e8f6f3; padding: 15px; border-left: 5px solid #2ecc71; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .High {{ color: #c0392b; font-weight: bold; }}
            .Medium {{ color: #e67e22; font-weight: bold; }}
            .Low {{ color: #27ae60; font-weight: bold; }}
            .footer {{ margin-top: 40px; font-size: 0.8em; text-align: center; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>WebScanPro Vulnerability Report</h1>
            <div class="timestamp">Generated on: {timestamp}</div>
            
            <div class="summary">
                <h3>Executive Summary</h3>
                <p>WebScanPro scanned the target <strong>http://localhost/dvwa</strong> and identified <strong>{len(scan_results)}</strong> critical vulnerabilities. 
                Immediate remediation is recommended.</p>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Target URL</th>
                        <th>Details</th>
                        <th>Mitigation</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    # Add rows dynamically
    for vul in scan_results:
        html_content += f"""
        <tr>
            <td>{vul['type']}</td>
            <td class="{vul['severity']}">{vul['severity']}</td>
            <td>{vul['url']}</td>
            <td>
                <strong>Payload:</strong> <code>{vul['payload']}</code><br>
                <em>{vul['detail']}</em>
            </td>
            <td>{vul['mitigation']}</td>
        </tr>
        """

    # Close HTML
    html_content += """
                </tbody>
            </table>
            
            <div class="footer">
                WebScanPro Tool - Automated Security Assessment
            </div>
        </div>
    </body>
    </html>
    """
    
    # Save the file
    with open(filename, "w") as f:
        f.write(html_content)
    
    print(f"[+] Report generated successfully: {filename}")
    
    # Automatically open the report in the browser
    webbrowser.open("file://" + os.path.realpath(filename))

if __name__ == "__main__":
    generate_html_report()