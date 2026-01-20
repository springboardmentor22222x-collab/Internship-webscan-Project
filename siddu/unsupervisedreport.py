# unsupervisedreport.py

import os
import pandas as pd
from jinja2 import Template

# ---------- CONFIG ----------
OUT_HTML = "sqli_unsupervised_report.html"
SRC = "sqli_unsupervised_scores.csv"  # make sure this file is in the same folder


# ---------- HTML TEMPLATE ----------
tpl = """
<html>
<head>
    <meta charset="utf-8">
    <title>WebScanPro — Unsupervised Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        h1 {
            font-family: Arial, sans-serif;
        }
        table {
            border-collapse: collapse;
            font-family: Arial;
            font-size: 14px;
        }
        td, th {
            border: 1px solid #555;
            padding: 6px 10px;
        }
        th {
            background: #eee;
        }
        code {
            font-family: Consolas, "Courier New", monospace;
        }
    </style>
</head>
<body>
    <h1>WebScanPro — Unsupervised Anomaly Report</h1>
    <p>Sorted by anomaly_score (higher = more anomalous)</p>

    <table>
        <tr>
            <th>#</th>
            <th>Anomaly Score</th>
            <th>SQL Error</th>
            <th>Len Diff</th>
            <th>Resp Time</th>
            <th>URL</th>
            <th>Param</th>
            <th>Payload</th>
            <th>Evidence</th>
        </tr>

        {% for r in rows %}
        <tr>
            <td>{{ loop.index }}</td>
            <td>{{ "%.3f" % r.anomaly_score }}</td>
            <td>{{ r.sql_error_flag }}</td>
            <td>{{ r.len_diff }}</td>
            <td>{{ "%.3f" % r.resp_time }}</td>
            <td>{{ r.url }}</td>
            <td>{{ r.param }}</td>
            <td><code>{{ r.payload }}</code></td>
            <td>{{ r.evidence }}</td>
        </tr>
        {% endfor %}

    </table>
</body>
</html>
"""


# ---------- EVIDENCE BUILDING ----------
def build_evidence(row):
    """
    Build a human-readable evidence string for why this row looks suspicious.
    """
    ev = []

    try:
        sql_error_flag = int(row.get("sql_error_flag", 0))
    except Exception:
        sql_error_flag = 0

    try:
        len_diff = float(row.get("len_diff", 0))
    except Exception:
        len_diff = 0.0

    try:
        resp_time = float(row.get("resp_time", 0))
    except Exception:
        resp_time = 0.0

    if sql_error_flag == 1:
        ev.append("sql_error")

    if len_diff > 100:
        ev.append(f"len_diff={int(len_diff)}")

    if resp_time > 1.5:
        ev.append(f"slow={resp_time:.3f}s")

    return "; ".join(ev) if ev else "none"


# ---------- MAIN SCRIPT ----------

def main():
    print("Unsupervised SQLi report generator")
    print("Looking for CSV:", os.path.abspath(SRC))

    if not os.path.exists(SRC):
        print(f"ERROR: '{SRC}' not found in folder:")
        print("       ", os.path.abspath("."))
        print("Make sure the file name is exactly:", SRC)
        return

    df = pd.read_csv(SRC)
    print("Loaded rows:", len(df))

    # Ensure required columns exist
    required_cols = [
        "anomaly_score",
        "sql_error_flag",
        "len_diff",
        "resp_time",
        "url",
        "param",
        "payload",
    ]

    for c in required_cols:
        if c not in df.columns:
            print(f"Column '{c}' missing, filling with default 0/empty.")
            if c in ("url", "param", "payload"):
                df[c] = ""
            else:
                df[c] = 0

    # Add evidence
    df["evidence"] = df.apply(build_evidence, axis=1)

    # Sort highest → lowest anomaly score
    try:
        df["anomaly_score"] = df["anomaly_score"].astype(float)
        df_sorted = df.sort_values("anomaly_score", ascending=False)
    except Exception:
        print("WARNING: anomaly_score column is not numeric, leaving unsorted.")
        df_sorted = df

    rows = df_sorted.to_dict("records")

    # Render HTML
    html = Template(tpl).render(rows=rows)

    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    print("Wrote HTML report to:", os.path.abspath(OUT_HTML))


if __name__ == "__main__":
    main()
