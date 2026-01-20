# simple_report_from_model.py
import pandas as pd, joblib
from jinja2 import Template

MODEL_PKG = 'sqli_model_package.joblib'   # produced by train_model.py
FEATURES_CSV = 'sqli_runs_features.csv'   # ensured above
OUT_HTML = 'sqli_report_auto.html'

tpl = """
<html><head><meta charset="utf-8"><title>SQLi Auto Report</title></head><body>
<h1>WebScanPro — Auto Labeled Report</h1>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>confidence</th><th>label</th><th>url</th><th>param</th><th>payload</th><th>evidence</th></tr>
{% for r in rows %}
<tr>
<td>{{'%.2f' % r.confidence}}</td>
<td>{{r.label}}</td>
<td>{{r.url}}</td>
<td>{{r.param}}</td>
<td><code>{{r.payload}}</code></td>
<td>{{r.evidence}}</td>
</tr>
{% endfor %}
</table></body></html>
"""

pkg = joblib.load(MODEL_PKG)
clf = pkg['model']; feature_columns = pkg['feature_columns']
df = pd.read_csv(FEATURES_CSV)

# Prepare X -> one-hot payload_type if present (simple)
X = df.copy()
if 'payload_type' in X.columns:
    X = pd.get_dummies(X, columns=['payload_type'], drop_first=True)
for c in feature_columns:
    if c not in X.columns:
        X[c] = 0
X = X[feature_columns]
probs = clf.predict_proba(X)[:,1]
df['confidence'] = probs
rows = []
for _,r in df.iterrows():
    evidence = []
    if r.get('sql_error_flag',0): evidence.append('sql_error')
    if r.get('len_diff',0) > 100: evidence.append(f'len_diff={r["len_diff"]}')
    if r.get('resp_time',0) > 1.5: evidence.append(f'slow={r["resp_time"]}s')
    rows.append({'confidence': float(r['confidence']), 'label': int(r.get('label', -1)),
                 'url': r.get('url'), 'param': r.get('param'), 'payload': r.get('payload'),
                 'evidence': '; '.join(evidence) if evidence else 'none'})
rows = sorted(rows, key=lambda x: x['confidence'], reverse=True)
html = Template(tpl).render(rows=rows)
with open(OUT_HTML,'w',encoding='utf8') as f:
    f.write(html)
print("Wrote", OUT_HTML)
