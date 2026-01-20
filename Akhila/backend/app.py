import os
import sys


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)

import streamlit as st
from reports.report_generator import generate_report_html
 
from scanners.xss_detector import passive_xss_check
from scanners.sqli_detector import passive_sqli_check
from scanners.access_control_analyzer import access_control_check
from scanners.auth_session_audit import auth_session_check

def get_severity(item):
    if isinstance(item, dict):
        return item.get("severity", "Low")
    return "Low"


def normalize_results(url, xss, sqli, auth, access):
    findings = []

    for item in xss:
        findings.append({
            "vulnerability": "Cross-Site Scripting (XSS)",
            "endpoint": url,
            "severity": get_severity(item),
            "mitigation": "Apply output encoding, input validation, and Content Security Policy (CSP)"
        })

    for item in sqli:
        findings.append({
            "vulnerability": "SQL Injection",
            "endpoint": url,
            "severity": get_severity(item),
            "mitigation": "Use parameterized queries and avoid dynamic SQL"
        })

    for item in auth:
        findings.append({
            "vulnerability": "Authentication / Session Management",
            "endpoint": url,
            "severity": get_severity(item),
            "mitigation": "Use Secure and HttpOnly cookies, proper session expiry, and strong authentication"
        })

    for item in access:
        findings.append({
            "vulnerability": "Access Control",
            "endpoint": url,
            "severity": get_severity(item),
            "mitigation": "Implement role-based access control and server-side authorization checks"
        })

    return findings

st.set_page_config(page_title="WebScanPro", layout="wide")

st.title("🔐 WebScanPro – Web Vulnerability Scanner")

url = st.text_input("Enter Target URL", placeholder="https://example.com")

if st.button("Start Scan"):
    if not url:
        st.warning("Please enter a valid URL")
    else:
        with st.spinner("Scanning target..."):
            xss = passive_xss_check(url)
            sqli = passive_sqli_check(url)
            auth = auth_session_check(url)
            access = access_control_check(url)

        st.success("Scan completed")

        
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🧪 XSS")
            st.json(xss)

            st.subheader("💉 SQL Injection")
            st.json(sqli)

        with col2:
            st.subheader("🔐 Authentication")
            st.json(auth)

            st.subheader("🚪 Access Control")
            st.json(access)

        
        findings = normalize_results(url, xss, sqli, auth, access)
        report_path = generate_report_html(url, findings)

        st.divider()
        st.subheader("📄 Security Report")

        st.success("Structured vulnerability report generated")

        with open(report_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="⬇️ Download HTML Report",
                data=f.read(),
                file_name="WebScanPro_Report.html",
                mime="text/html"
            )