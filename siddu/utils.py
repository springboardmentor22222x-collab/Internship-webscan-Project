# src/utils.py
import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, urlparse

from config import USER_AGENT, CRAWL_DELAY

HEADERS = {"User-Agent": USER_AGENT}

def fetch(url):
    """Fetch URL and return (status_code, text) or (None, None) on serious error."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        time.sleep(CRAWL_DELAY)
        return r.status_code, r.text
    except Exception as e:
        print(f"[fetch] Error fetching {url}: {e}")
        return None, None

def extract_links(html, base_url):
    """Return a set of absolute URLs found in anchor tags."""
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        # build absolute URL
        abs_url = urljoin(base_url, href)
        # ignore mailto: and javascript:
        if abs_url.startswith("http"):
            links.add(strip_fragment(abs_url))
    return links

def extract_inputs(html, base_url):
    """Return list of input fields and forms with basic attributes."""
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        form_info = {}
        form_info["action"] = urljoin(base_url, form.get("action") or "")
        form_info["method"] = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name"),
                "type": inp.get("type"),
                "placeholder": inp.get("placeholder"),
                "value": inp.get("value")
            })
        form_info["inputs"] = inputs
        forms.append(form_info)
    # also list standalone input tags outside forms if needed
    return forms

def strip_fragment(url):
    # remove #fragment part
    p = urlparse(url)
    return p._replace(fragment="").geturl()
