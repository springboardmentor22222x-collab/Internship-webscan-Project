# xss_scanner_ml.py
import requests, time, re, os, csv, sys, joblib
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# ----------------- Config -----------------
TARGETS_FILE = "targets.txt"
DATASET_CSV = "xss_dataset.csv"    # holds features + label (label can be blank initially)
MODEL_FILE = "xss_model.joblib"
REPORT_CSV = "xss_report.csv"
TIMEOUT = 6
HEADERS = {"User-Agent": "WebScanPro-XSS/1.0"}
# safe-ish payloads for testing local DVWA
PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '\'><img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>'
]
# ------------------------------------------

# ---- Networking helpers ----
def fetch(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
    except Exception as e:
        print("Fetch error:", e)
        return None

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        method = (f.get("method") or "get").lower()
        action = f.get("action") or base_url
        inputs = [i.get("name") for i in f.find_all(["input","textarea","select"]) if i.get("name")]
        forms.append({"method": method, "action": action, "inputs": inputs})
    return forms

def inject_get(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    new_qs = urlencode(qs, doseq=True)
    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_qs, p.fragment))
    try:
        r = requests.get(new_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        return r, new_url
    except Exception as e:
        print("GET inject error:", e); return None, new_url

def inject_post(action, inputs, payload):
    data = {name: payload for name in inputs}
    try:
        r = requests.post(action, data=data, headers=HEADERS, timeout=TIMEOUT, verify=False)
        return r, action
    except Exception as e:
        print("POST inject error:", e); return None, action

# ---- Feature extraction ----
def features_from_response(orig_text, resp_text, payload, response):
    f = {}
    f["len_diff"] = len(resp_text) - len(orig_text)
    f["payload_reflected"] = int(payload in resp_text)
    f["num_script_tags"] = resp_text.lower().count("<script")
    f["num_on_event"] = len(re.findall(r'on\w+\s*=', resp_text))
    f["status_code"] = response.status_code if response is not None else 0
    # headers keys lowered
    hdrs = {k.lower(): v for k,v in (response.headers.items() if response is not None else {})}
    f["has_csp"] = int("content-security-policy" in hdrs)
    return f

# ---- Dataset writing helper ----
def append_dataset_row(endpoint, param, payload, features, label=""):
    header = ["endpoint","param","payload","len_diff","payload_reflected","num_script_tags","num_on_event","status_code","has_csp","label"]
    exists = os.path.exists(DATASET_CSV)
    with open(DATASET_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if not exists:
            writer.writeheader()
        row = {"endpoint": endpoint, "param": param, "payload": payload}
        for k in ["len_diff","payload_reflected","num_script_tags","num_on_event","status_code","has_csp"]:
            row[k] = features[k]
        row["label"] = label
        writer.writerow(row)

# ---- Model helpers ----
def train_model():
    if not os.path.exists(DATASET_CSV):
        print("No dataset found:", DATASET_CSV)
        return
    df = pd.read_csv(DATASET_CSV)
    # must have label values
    df_labeled = df[df["label"].notna() & (df["label"]!="")]
    if df_labeled.empty:
        print("No labeled rows found in", DATASET_CSV, "— label some rows before training.")
        return
    X = df_labeled[["len_diff","payload_reflected","num_script_tags","num_on_event","status_code","has_csp"]]
    y = df_labeled["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2, random_state=42)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    print("Train score:", model.score(X_train, y_train))
    print("Test score:", model.score(X_test, y_test))
    joblib.dump(model, MODEL_FILE)
    print("Model saved to", MODEL_FILE)

def load_model():
    if os.path.exists(MODEL_FILE):
        return joblib.load(MODEL_FILE)
    return None

# ---- Scanning/collection ----
def scan_target_collect(url):
    r = fetch(url)
    if not r:
        print("Could not fetch", url); return []
    orig = r.text
    results = []

    # query params
    p = urlparse(url); qs = parse_qs(p.query)
    for param in qs.keys():
        for payload in PAYLOADS:
            resp, injected_url = inject_get(url, param, payload)
            if not resp: continue
            f = features_from_response(orig, resp.text, payload, resp)
            append_dataset_row(injected_url, param, payload, f, label="")  # unlabeled
            results.append({"endpoint": injected_url, "param": param, "payload": payload, **f})
            time.sleep(0.15)

    # forms
    forms = extract_forms(orig, url)
    for form in forms:
        for payload in PAYLOADS:
            if not form["inputs"]:
                # skip empty forms (or use a default param name)
                continue
            resp, action = inject_post(form["action"], form["inputs"], payload)
            if not resp: continue
            f = features_from_response(orig, resp.text, payload, resp)
            append_dataset_row(action, ",".join(form["inputs"]), payload, f, label="")
            results.append({"endpoint": action, "param": ",".join(form["inputs"]), "payload": payload, **f})
            time.sleep(0.15)

    return results

def scan_target_score(url, model=None):
    r = fetch(url)
    if not r:
        print("Could not fetch", url); return []
    orig = r.text
    findings = []

    p = urlparse(url); qs = parse_qs(p.query)
    for param in qs.keys():
        for payload in PAYLOADS:
            resp, injected_url = inject_get(url, param, payload)
            if not resp: continue
            f = features_from_response(orig, resp.text, payload, resp)
            prob = None
            if model:
                prob = model.predict_proba([[f["len_diff"],f["payload_reflected"],f["num_script_tags"],f["num_on_event"],f["status_code"],f["has_csp"]]])[:,1][0]
            severity = "High" if (f["payload_reflected"]==1 or (prob is not None and prob>0.7)) else ("Medium" if prob is not None and prob>0.4 else "Low")
            evidence = payload if f["payload_reflected"] else resp.text[:300].replace("\n"," ")
            findings.append({"endpoint": injected_url, "param": param, "payload": payload, "evidence": evidence, "prob": prob, "severity": severity, **f})
            time.sleep(0.15)

    forms = extract_forms(orig, url)
    for form in forms:
        for payload in PAYLOADS:
            if not form["inputs"]:
                continue
            resp, action = inject_post(form["action"], form["inputs"], payload)
            if not resp: continue
            f = features_from_response(orig, resp.text, payload, resp)
            prob = None
            if model:
                prob = model.predict_proba([[f["len_diff"],f["payload_reflected"],f["num_script_tags"],f["num_on_event"],f["status_code"],f["has_csp"]]])[:,1][0]
            severity = "High" if (f["payload_reflected"]==1 or (prob is not None and prob>0.7)) else ("Medium" if prob is not None and prob>0.4 else "Low")
            evidence = payload if f["payload_reflected"] else resp.text[:300].replace("\n"," ")
            findings.append({"endpoint": action, "param": ",".join(form["inputs"]), "payload": payload, "evidence": evidence, "prob": prob, "severity": severity, **f})
            time.sleep(0.15)

    return findings

# ---- Main orchestration ----
def collect_mode():
    if not os.path.exists(TARGETS_FILE):
        print("Create", TARGETS_FILE, "with one URL per line."); return
    urls = [l.strip() for l in open(TARGETS_FILE).read().splitlines() if l.strip()]
    total = 0
    for u in urls:
        print("Collecting features from", u)
        res = scan_target_collect(u)
        total += len(res)
    print("Collection done. Appended", total, "rows to", DATASET_CSV)

def scan_mode():
    model = load_model()
    if model:
        print("Loaded model:", MODEL_FILE)
    else:
        print("No model found, running rule-only scanner (probabilities will be empty).")
    if not os.path.exists(TARGETS_FILE):
        print("Create", TARGETS_FILE, "with target URLs."); return
    urls = [l.strip() for l in open(TARGETS_FILE).read().splitlines() if l.strip()]
    all_findings = []
    for u in urls:
        print("Scanning", u)
        findings = scan_target_score(u, model)
        all_findings += findings
    if all_findings:
        pd.DataFrame(all_findings).to_csv(REPORT_CSV, index=False)
        print("Report saved to", REPORT_CSV)
    else:
        print("No findings.")

# ---- CLI ----
def print_help():
    print("Usage:")
    print("  python xss_scanner_ml.py --collect   # collect feature rows (unlabeled) into xss_dataset.csv")
    print("  python xss_scanner_ml.py --train     # train model from labeled rows in xss_dataset.csv")
    print("  python xss_scanner_ml.py --scan      # run scanner and output xss_report.csv (uses model if present)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help(); sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == "--collect":
        collect_mode()
    elif cmd == "--train":
        train_model()
    elif cmd == "--scan":
        scan_mode()
    else:
        print_help()
