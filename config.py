# src/config.py
TARGET = "http://localhost:8080"   # change to your target (DVWA/JuiceShop) or site to scan
MAX_PAGES = 200                    # limit pages to crawl
CRAWL_DELAY = 1.0                  # seconds between requests (be polite)
USER_AGENT = "WebScanProBot/1.0 (+https://example.org)"  # change if needed
OUTPUT_JSON = "../output/pages_metadata.json"
OUTPUT_CSV = "../output/pages_metadata.csv"
