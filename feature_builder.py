# feature_builder.py
"""
Takes sqli_runs_raw.csv and builds features using baseline responses.
Outputs: sqli_runs_features.csv
Columns:
 url, method, param, payload, status, resp_len, resp_time, sql_error_flag,
 len_diff, seq_ratio, baseline_len, baseline_snippet, payload_type
"""
import pandas as pd
import difflib, csv, json
from collections import defaultdict

RAW = 'sqli_runs_raw.csv'
OUT = 'sqli_runs_features.csv'

def detect_payload_type(payload):
    p = payload.lower()
    if 'sleep' in p or 'sleep(' in p: return 'time'
    if 'union' in p: return 'union'
    if '--' in p or '/*' in p: return 'comment'
    if "'" in p or '"' in p: return 'quote'
    return 'normal'

def build_baselines(df):
    # baseline per (url, method, param) using runs with payload == benign_value
    # but if benign not present, take min resp_len run as baseline
    bases = {}
    groups = df.groupby(['url','method','param'])
    for key,g in groups:
        # try to find run with payload that equals '1' or '0' common benign; else pick smallest resp_len
        ben = g[g['payload'].isin(['1','0',''])]
        if len(ben)>0:
            row = ben.iloc[0]
        else:
            row = g.loc[g['resp_len'].idxmin()]
        bases[key] = {'baseline_len': int(row['resp_len']), 'baseline_snippet': row['resp_snippet'][:300]}
    return bases

def main():
    df = pd.read_csv(RAW)
    # If you included a 'benign_value' per target and ran it, good. If not, baselines inferred.
    bases = build_baselines(df)
    out_rows = []
    for _,r in df.iterrows():
        key = (r['url'], r['method'], r['param'])
        base = bases.get(key, {'baseline_len':0,'baseline_snippet':''})
        len_diff = int(r['resp_len']) - base['baseline_len']
        # sequence ratio on first 200 chars
        seq_ratio = difflib.SequenceMatcher(None, str(base['baseline_snippet'])[:200], str(r['resp_snippet'])[:200]).ratio()
        ptype = detect_payload_type(r['payload'])
        out_rows.append({
            'url': r['url'], 'method': r['method'], 'param': r['param'], 'payload': r['payload'],
            'status': int(r['status']), 'resp_len': int(r['resp_len']), 'resp_time': float(r['resp_time']),
            'sql_error_flag': int(r['sql_error_flag']),
            'baseline_len': base['baseline_len'], 'len_diff': len_diff, 'seq_ratio': seq_ratio,
            'payload_type': ptype, 'baseline_snippet': base['baseline_snippet'][:300], 'resp_snippet': r['resp_snippet'][:300]
        })
    out_df = pd.DataFrame(out_rows)
    out_df.to_csv(OUT, index=False)
    print("Wrote", OUT, " with shape ", out_df.shape)

if __name__ == '__main__':
    main()
