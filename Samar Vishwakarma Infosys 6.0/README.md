# 🛡️ WebScanPro – Automated Web Application Security Scanner

WebScanPro is an automated penetration testing framework designed to detect **OWASP Top 10 vulnerabilities** in **Single Page Applications (SPAs)**.

Built during an **8-week cybersecurity internship**, the tool uses **browser automation instead of static analysis**, enabling it to test modern JavaScript-heavy applications.

---

## 📖 Overview

Unlike traditional scanners, WebScanPro leverages **Selenium WebDriver** to:

- Interact with dynamic UI elements
- Bypass pop-ups and banners
- Perform real-world attack simulations
- Generate professional, client-ready security reports

The tool was tested against **OWASP Juice Shop (v14.x)** inside a Docker environment.

---

## 🎯 Key Features

- 🔄 **Dynamic Scanning**
  - Supports Angular / React SPAs using browser automation

- 💉 **SQL Injection Engine**
  - Automated authentication bypass testing

- 🧪 **XSS Detection**
  - Identifies reflected XSS via URL injection

- 🔐 **Authentication Analysis**
  - Brute-force testing
  - Session cookie flag inspection

- 🧾 **IDOR Testing**
  - Detects horizontal privilege escalation

- 📊 **Auto Reporting**
  - Generates HTML & JSON security reports
  - Severity ratings & mitigation guidance included

---

## 🛠️ Technology Stack

| Component | Technology |
|---------|-----------|
| Language | Python 3 |
| Automation | Selenium WebDriver |
| Browser | Google Chrome |
| Target App | OWASP Juice Shop |
| Environment | Docker |
| Reporting | HTML / CSS / JSON |

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.x
- Docker Desktop
- Google Chrome

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/WebScanPro.git
cd WebScanPro

