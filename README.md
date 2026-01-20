# WebScanPro: Automated Web Application Security Testing Tool

**WebScanPro** is a Python-based automated security scanner designed to detect common vulnerabilities in web applications. It simulates real-world attacks based on the **OWASP Top 10**, including SQL Injection, Cross-Site Scripting (XSS), and Broken Authentication.

This tool was built to automate the detection phase of penetration testing, providing developers with actionable reports to secure their applications.

---

## 🚀 Features

* **🕷️ Automated Crawler:** Authenticates and spiders the target application to map URLs and input forms.
* **💉 SQL Injection Scanner:** Detects Error-based and Boolean-based SQL injection vulnerabilities.
* **⚠️ XSS Detector:** Identifies Reflected Cross-Site Scripting (XSS) by injecting and analyzing payloads.
* **🔓 Authentication Tester:** Performs dictionary attacks (Brute Force) and analyzes session cookie security flags (`Secure`, `HttpOnly`).
* **🕵️ IDOR Scanner:** Detects Insecure Direct Object References by iterating through user identifiers to check for data leaks.
* **📊 HTML Reporting:** Generates a professional, color-coded HTML report summarizing all findings and mitigation strategies.

---

## 🛠️ Technology Stack

* **Language:** Python 3.x
* **Libraries:**
    * `requests` (HTTP Session Management)
    * `beautifulsoup4` (HTML Parsing & Scraping)
    * `colorama` (Terminal Output Formatting - optional)
* **Target Environment:** DVWA (Damn Vulnerable Web Application)

---

## ⚙️ Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/WebScanPro.git](https://github.com/yourusername/WebScanPro.git)
    cd WebScanPro
    ```

2.  **Install Dependencies**
    ```bash
    pip install requests beautifulsoup4
    ```

3.  **Set Up the Target (DVWA)**
    * This tool is configured to run against a local instance of **DVWA**.
    * Ensure DVWA is running on `http://localhost/` (via Docker or XAMPP).
    * **Important:** Set DVWA Security Level to **"Low"** before scanning.

---

## 📖 Usage

### 1. Run the Crawler
Maps the website structure and finds input forms.
```bash
python scanner.py


2. Test for SQL Injection
  python sqli_tester.py

3. Test for XSS
 python xss_scanner.py

4.Test Authentication & Session
python auth_tester.py

5.enerate Final Report
python report_generator.py
