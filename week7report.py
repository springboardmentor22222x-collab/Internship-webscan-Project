import pandas as pd
import os
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import messagebox

print("\n=== WEEK 7: FULL AI DRIVEN SECURITY REPORT SYSTEM STARTED ===\n")

# ================================================================
# AUTO-LOAD SQLi FILE
# ================================================================
possible_files = [
    "sqli_unsupervised_scores.csv",
    "sqli_runs_raw.csv",
    "sqli_runs_features.csv",
    "sqli_runs_features_auto_labeled.csv"
]

sqli_file = None
for f in possible_files:
    if os.path.exists(f):
        sqli_file = f
        break

if not sqli_file:
    print("❌ ERROR: Put one SQLi CSV in the folder:")
    for f in possible_files: print(" -", f)
    exit()

sqli = pd.read_csv(sqli_file)
sqli["vulnerability"] = "SQL Injection"
print(f"✔ SQL Injection file loaded: {sqli_file}")

# ================================================================
# LOAD XSS TARGETS
# ================================================================
if os.path.exists("targets.csv"):
    xss = pd.read_csv("targets.csv", header=None, names=["endpoint"])
    xss["payload"] = "XSS test payload"
    xss["vulnerability"] = "XSS"
    print("✔ XSS targets loaded")
else:
    xss = pd.DataFrame(columns=["endpoint","payload","vulnerability"])
    print("⚠ WARNING: No XSS CSV found, skipping")

# ================================================================
# MANUAL FINDINGS FOR AUTHENTICATION & IDOR
# ================================================================
auth = pd.DataFrame([
    {"endpoint": "/login", "payload": "Weak session token", "vulnerability": "Authentication Issue"},
    {"endpoint": "/admin", "payload": "No MFA or session timeout", "vulnerability": "Authentication Issue"},
])

idor = pd.DataFrame([
    {"endpoint": "/user/1/edit", "payload": "Unauthorized object access", "vulnerability": "IDOR"},
    {"endpoint": "/profile/5", "payload": "Direct access without permission", "vulnerability": "IDOR"},
])

# ================================================================
# COMBINE ALL RESULTS
# ================================================================
data = pd.concat([sqli, xss, auth, idor], ignore_index=True)
print("✔ Combined all vulnerability data")

# ================================================================
# SEVERITY & RISK SCORING
# ================================================================
def severity(v):
    return {
        "SQL Injection": "Critical",
        "IDOR": "Critical",
        "XSS": "High",
        "Authentication Issue": "Medium"
    }.get(v, "Low")

data["severity"] = data["vulnerability"].apply(severity)

risk_score = {"Low":2, "Medium":5, "High":8, "Critical":10}
data["risk_score"] = data["severity"].map(risk_score)

# ================================================================
# MITIGATION SUGGESTIONS
# ================================================================
def fix(v):
    return {
        "SQL Injection": "Use prepared statements & validation.",
        "XSS": "Sanitize input, escape output, enable CSP.",
        "Authentication Issue": "Enable MFA, session timeout, secure cookies.",
        "IDOR": "Add access control authorization checks."
    }.get(v, "Follow OWASP Top 10 standards.")

data["mitigation"] = data["vulnerability"].apply(fix)

# ================================================================
# EXECUTIVE SUMMARY
# ================================================================
critical_count = len(data[data["severity"]=="Critical"])
high_count = len(data[data["severity"]=="High"])
medium_count = len(data[data["severity"]=="Medium"])

executive_summary = f"""
<h2>Executive Summary</h2>
<p>The security assessment identified a total of {len(data)} vulnerabilities.
The system currently contains <b>{critical_count} Critical</b> and <b>{high_count} High</b> severity risks.
Immediate remediation is required to prevent exploitation and data compromise.</p>
<hr>
"""

# ================================================================
# GENERATE SEVERITY CHART
# ================================================================
plt.figure(figsize=(6,4))
data["severity"].value_counts().plot(kind="bar")
plt.title("Vulnerability Severity Distribution")
plt.xlabel("Severity Level")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("severity_chart.png")
print("📊 Severity chart generated: severity_chart.png")

# ================================================================
# GENERATE HTML REPORT WITH CSS STYLING
# ================================================================
html = f"""
<html>
<head>
<title>Week 7 - AI Security Report</title>
<style>
body {{ font-family: Arial; margin: 20px; }}
h1 {{ color: #003366; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background-color: #003366; color: white; }}
</style>
</head>
<body>

<h1>Week 7 - AI Driven Security Report</h1>
{executive_summary}
<h3>Vulnerability Table</h3>
{data.to_html(index=False)}
<br>
<h3>Severity Chart</h3>
<img src="severity_chart.png" width="500">
</body>
</html>
"""

with open("week7_security_report.html", "w", encoding="utf-8") as report:
    report.write(html)

print("\n🎉 REPORT GENERATED SUCCESSFULLY!")
print("📄 File: week7_security_report.html\n")

# ================================================================
# SIMPLE GUI BUTTON LAUNCHER
# ================================================================
def open_report():
    os.system("start week7_security_report.html")
    messagebox.showinfo("Report Opened", "Week 7 Security Report Opened Successfully!")

root = tk.Tk()
root.title("Week 7 Report Generator")
root.geometry("300x120")
tk.Label(root, text="Week 7 - AI Security Report", font=("Arial", 12)).pack(pady=10)
tk.Button(root, text="Open Report", command=open_report, bg="navy", fg="white").pack(pady=10)
root.mainloop()
