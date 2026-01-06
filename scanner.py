import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configuration
TARGET_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
# If using Docker, the URL might be just "http://localhost/" and "http://localhost/login.php"
# Adjust the URLs below if your Docker setup uses port 80 directly.
TARGET_URL = "http://localhost/" 
LOGIN_URL = "http://localhost/login.php"

USERNAME = "admin"
PASSWORD = "password"

# Session setup (Keeps us logged in)
session = requests.Session()

def login():
    """Logs into DVWA to allow scanning authenticated pages."""
    print(f"[*] Attempting to login to {LOGIN_URL}...")
    
    # 1. Get the login page to fetch the CSRF token
    response = session.get(LOGIN_URL)
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Extract the user_token (CSRF token) - DVWA requires this!
    user_token = soup.find("input", {"name": "user_token"})['value']
    
    # 2. Prepare login data
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        "user_token": user_token
    }
    
    # 3. Send POST request to log in
    response = session.post(LOGIN_URL, data=login_data)
    
    if "Welcome to Damn Vulnerable Web Application" in response.text:
        print("[+] Login Successful!")
        return True
    else:
        print("[-] Login Failed. Check credentials or URL.")
        return False

def crawl(url):
    """Scans the page for links and forms."""
    print(f"\n[*] Scanning: {url}")
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    # --- Find Links ---
    links = soup.find_all("a")
    print(f"    -> Found {len(links)} links.")
    
    unique_links = set()
    for link in links:
        href = link.get("href")
        if href and not href.startswith("#"):
            full_url = urljoin(url, href)
            if "logout" not in full_url: # Avoid logging ourselves out!
                unique_links.add(full_url)
                print(f"       [LINK] {full_url}")

    # --- Find Forms (Input Fields) ---
    forms = soup.find_all("form")
    print(f"    -> Found {len(forms)} forms.")
    
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").upper()
        inputs = form.find_all("input")
        print(f"       [FORM] Action: {action} | Method: {method}")
        for inp in inputs:
            input_name = inp.get("name")
            print(f"              [INPUT] Name: {input_name}")

    return unique_links

# === MAIN EXECUTION ===
if __name__ == "__main__":
    if login():
        # Scan the dashboard first
        found_links = crawl(TARGET_URL)
        
        # Optional: Deep scan (visit the links we found)
        # We limit to 3 links here just to test
        print("\n[*] Performing deep scan on found links...")
        count = 0
        for link in found_links:
            if TARGET_URL in link and count < 3: # Only scan internal links
                crawl(link)
                count += 1