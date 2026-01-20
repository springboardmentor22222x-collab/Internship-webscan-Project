# features.py
import json
import math
import numpy as np
import pandas as pd
from collections import Counter
from urllib.parse import urlparse, parse_qs

INPUT = "data/collected_endpoints.jsonl"
OUT_CSV = "data/features.csv"

def entropy(s):
    if not s:
        return 0.0
    probs = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in probs)

rows = []
with open(INPUT, 'r', encoding='utf-8') as fh:
    for line in fh:
        r = json.loads(line)
        parsed = urlparse(r["url"])
        params = parse_qs(parsed.query)
        row = {}
        row["url"] = r["url"]
        row["status_code"] = r.get("status_code",0)
        row["content_length"] = r.get("content_length",0)
        row["num_links"] = len(r.get("links",[]))
        row["num_forms"] = len(r.get("forms",[]))
        row["num_inputs"] = r.get("num_inputs",0)
        row["contains_js"] = int(r.get("contains_js", False))
        # features about query params
        row["num_query_params"] = len(params)
        row["avg_param_name_len"] = (sum(len(k) for k in params.keys())/max(1,len(params)))
        # entropy of response body not collected here, but could be:
        # row["body_entropy"] = entropy(r.get("body",""))
        # heuristic: presence of suspicious server header
        server = r.get("headers",{}).get("server","").lower()
        row["server_header_len"] = len(server)
        rows.append(row)

df = pd.DataFrame(rows).fillna(0)
df.to_csv(OUT_CSV, index=False)
print("Wrote features to", OUT_CSV)
