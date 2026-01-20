# sqli_runner.py
"""
Run SQL payloads against targets.csv and write sqli_runs_raw.csv
Outputs columns:
  run_id, url, method, param, payload, status_code, resp_len, resp_time, sql_error_flag, resp_snippet
"""
import csv, time, json, hashlib, uuid
import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
from tqdm import tqdm

TARGETS_CSV = 'targets.csv'
PAYLOADS_TXT = 'payloads.txt'
OUT_CSV = 'sqli_runs_raw.csv'
SQL_ERROR_KEYWORDS = ['syntax error', 'mysql', 'sql', 'unclosed quotation mark', 'odbc', 'pg_', 'sqlstate', 'error in your sql syntax']

def load_targets(path):
    rows = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            # parse headers JSON-like
            hdrs = {}
            if r.get('headers'):
                try:
                    hdrs = json.loads(r['headers'].replace("'", '"'))
                except:
                    try:
                        hdrs = eval(r['headers'])
                    except:
                        hdrs = {}
            rows.append({'url': r['url'], 'method': r['method'].upper(), 'param': r['param'], 'benign_value': r['benign_value'], 'headers': hdrs})
    return rows

def load_payloads(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def run_one(target, payload):
    url = target['url']
    method = target['method']
    param = target['param']
    headers = target.get('headers') or {}
    # Build params / data
    if method == 'GET':
        # parse existing query and replace param
        from urllib.parse import urlsplit, urlunsplit, parse_qs
        parsed = urlsplit(url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
        start = time.time()
        resp = requests.get(test_url, headers=headers, timeout=10)
    else:
        # POST
        # simple approach: send param in form body
        data = {param: payload}
        start = time.time()
        resp = requests.post(url, data=data, headers=headers, timeout=10)
    elapsed = time.time() - start
    text = resp.text.lower() if resp.text else ''
    sql_err = any(kw in text for kw in SQL_ERROR_KEYWORDS)
    snippet = text[:500].replace('\n',' ')
    return resp.status_code, len(text), elapsed, sql_err, snippet

def main():
    targets = load_targets(TARGETS_CSV)
    payloads = load_payloads(PAYLOADS_TXT)
    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['run_id','url','method','param','payload','status','resp_len','resp_time','sql_error_flag','resp_snippet'])
        for t in tqdm(targets, desc='targets'):
            for p in payloads:
                run_id = str(uuid.uuid4())
                try:
                    status, rlen, rtime, sql_err, snippet = run_one(t, p)
                except Exception as e:
                    status, rlen, rtime, sql_err, snippet = -1, 0, 0.0, False, f'ERROR:{e}'
                writer.writerow([run_id, t['url'], t['method'], t['param'], p, status, rlen, rtime, int(sql_err), snippet])

if __name__ == '__main__':
    main()
