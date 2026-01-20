
import requests
from bs4 import BeautifulSoup            # <-- this is where BeautifulSoup is used to parse HTML
from urllib.parse import urljoin, urlparse
import json
import os
import time

# -------- CONFIG --------
START_URL = "http://localhost/dvwa"     # change to your target (dvwa, juice shop etc.)
MAX_PAGES = 200                         # stop after crawling this many pages (safety)
OUTPUT_JSON = "./output/pages_metadata.json"
OUTPUT_LINKS = "./output/links.txt"
REQUEST_TIMEOUT = 8                     
SLEEP_BETWEEN_REQUESTS = 0.3
# ------------------------

visited = set()
found_links = []
pages_metadata = []  # list of dicts: {url, title, status_code, forms: [...]}

def sanitize_url(base, href):
    """Turn href into absolute URL and remove fragments (anchors)."""
    if not href:
        return None
    full = urljoin(base, href)
    # strip fragment
    parsed = urlparse(full)
    cleaned = parsed._replace(fragment="").geturl()
    return cleaned

def same_domain(url1, url2):
    """Return True if url2 is in same domain as url1 (scheme + hostname)."""
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return (p1.scheme, p1.hostname) == (p2.scheme, p2.hostname)

def ensure_output_dir(path):
    """Ensure directory for a file path exists."""
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

def save_json(obj, path):
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def save_links(links, path):
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        for l in links:
            f.write(l + "\n")

def extract_inputs_and_forms(soup):
    """Return a list of forms with input details found on the page."""
    forms_info = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            typ = inp.get("type") if inp.name == "input" else inp.name
            value = inp.get("value")
            inputs.append({"name": name, "type": typ, "value": value})
        forms_info.append({"action": action, "method": method, "inputs": inputs})
    return forms_info

def crawl(start_url, max_pages=MAX_PAGES):
    to_visit = [start_url]

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        print(f"[+] Fetching: {url}")
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"    ! Request failed: {e}")
            visited.add(url)
            pages_metadata.append({
                "url": url,
                "status": "error",
                "error": str(e),
                "forms": []
            })
            continue

        visited.add(url)
        status = resp.status_code
        text = resp.text if resp.text else ""
        # parse HTML with BeautifulSoup
        soup = BeautifulSoup(text, "html.parser")

        # page title (if any)
        title_tag = soup.find("title")
        title = title_tag.get_text().strip() if title_tag else ""

        # extract forms and inputs
        forms = extract_inputs_and_forms(soup)

        pages_metadata.append({
            "url": url,
            "status": status,
            "title": title,
            "forms": forms
        })

        # collect and enqueue links
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            full = sanitize_url(url, href)
            if not full:
                continue
            # ignore mailto:, javascript: etc.
            if full.startswith("mailto:") or full.startswith("javascript:"):
                continue
            # stay in same domain
            if same_domain(start_url, full):
                if full not in visited and full not in to_visit:
                    to_visit.append(full)
                    found_links.append(full)

        # polite delay
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    print(f"\nCrawled {len(visited)} pages.")
    return pages_metadata, found_links

if __name__ == "__main__":
    print("Starting crawler...")
    pages, links = crawl(START_URL)
    # Save outputs (will create ./output/ directory automatically)
    save_json(pages, OUTPUT_JSON)
    save_links(sorted(set(links)), OUTPUT_LINKS)
    print(f"Saved pages metadata to {OUTPUT_JSON}")
    print(f"Saved links to {OUTPUT_LINKS}")
