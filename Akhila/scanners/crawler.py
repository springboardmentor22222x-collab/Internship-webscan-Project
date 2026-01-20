# crawler.py
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json
import time
import threading
import queue
import re
import os
from urllib import robotparser as rp  

START_URL = os.getenv("START_URL", "https://owasp.org/www-project-juice-shop/")
MAX_PAGES = int(os.getenv("MAX_PAGES", "500"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "collected_endpoints.jsonl")
USER_AGENT = "WebScanProCrawler/1.0 (+https://yourdomain.example)"

visited = set()
q = queue.Queue()
q.put(START_URL)
lock = threading.Lock()

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})

def allowed_by_robots(url):
    
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_txt = session.get(urljoin(base, "/robots.txt"), timeout=5).text
        # simple parse
        for line in robots_txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("disallow:"):
                path = line.split(":",1)[1].strip()
                if path == "/":
                    return False
                if parsed.path.startswith(path):
                    return False
    except Exception:
        pass
    return True

def extract_forms(soup, base_url):
    forms = []
    for form in soup.find_all("form"):
        f = {}
        f["action"] = urljoin(base_url, form.get("action") or "")
        f["method"] = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            typ = inp.get("type") or inp.name
            inputs.append({"name": name, "type": typ})
        f["inputs"] = inputs
        forms.append(f)
    return forms

def normalize_url(u, base):
    if not u:
        return None
    u = urljoin(base, u)
    parsed = urlparse(u)
    # remove fragment
    return parsed._replace(fragment="").geturl()

def crawl_worker():
    while True:
        try:
            url = q.get(timeout=3)
        except queue.Empty:
            return
        with lock:
            if url in visited or len(visited) >= MAX_PAGES:
                q.task_done()
                continue
            visited.add(url)
        if not allowed_by_robots(url):
            q.task_done()
            continue
        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
        except Exception as e:
            q.task_done()
            continue
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        content_type = resp.headers.get("content-type","")
        text = resp.text if "html" in content_type else ""
        soup = BeautifulSoup(text, "html.parser") if text else None

        record = {
            "url": url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "content_length": len(resp.content),
            "has_html": bool(soup),
            "forms": extract_forms(soup, base) if soup else [],
            "links": [],
            "fetched_at": time.time()
        }

        if soup:
            # collect links
            for a in soup.find_all("a", href=True):
                link = normalize_url(a["href"], base)
                if link and urlparse(link).netloc == parsed.netloc:
                    record["links"].append(link)
                    with lock:
                        if link not in visited:
                            q.put(link)

            # also capture script tags, input counts etc.
            record["num_inputs"] = sum(1 for _ in soup.find_all("input"))
            record["num_textareas"] = sum(1 for _ in soup.find_all("textarea"))
            record["contains_js"] = bool(soup.find("script"))

        # write record to output
        with open(OUTPUT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

        q.task_done()

def main():
    num_threads = int(os.getenv("CRAWL_THREADS", "6"))
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=crawl_worker, daemon=True)
        t.start()
        threads.append(t)
    q.join()
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
# docker build -t webscanpro-crawler