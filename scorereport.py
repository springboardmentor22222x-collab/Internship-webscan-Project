# score_report.py
import pandas as pd, joblib, os
from jinja2 import Template

MODEL_PACKAGE = 'sqli_model_package.joblib'
FEATURES_CSV = 'sqli_runs_features.csv'
OUT_CSV = 'sqli_report.csv'
OUT_HTML = 'sqli_report.html'

tpl = """
<html><head><meta charset="utf-8"><title>SQLi Report</title></head><body>
<h1>WebScanPro SQLi Report</h1>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>url</th><th>param</th><th>payload</th><th>confidence</th><th>evidence</th><th>suggested_fix</th></tr>
{% for r in rows %}
<tr>
<td>{{r.url}}</td>
<td>{{r.param}}</td>
<td><code>{{r.payload}}</code></td>
<td>{{'%.2f' % r.confidence}}</td>
<td>{{r.evidence}}</td>
<td>{{r.suggested_fix}}</td>
</tr>
{% endfor %}
</table>
</body></html>
"""

def main():
    pkg = joblib.load(MODEL_PACKAGE)
    clf = pkg['model']; feature_columns = pkg['feature_columns']
    df = pd.read_csv(FEATURES_CSV)
    # Build X same as during training: keep same columns
    X = df.copy()
    # if payload_type present and one-hot encoding was used, create dummies and align columns
    if 'payload_type' in X.columns:
        X = pd.get_dummies(X, columns=['payload_type'], drop_first=True)
    # Ensure we have all feature columns
    for c in feature_columns:
        if c not in X.columns:
            X[c] = 0
    X = X[feature_columns]
    probs = clf.predict_proba(X)[:,1]
    df['confidence'] = probs
    # pick best evidence and suggestion
    rows = []
    for _,r in df.iterrows():
        evidence = []
        if r['sql_error_flag']: evidence.append('SQL error in response')
        if r['len_diff'] > 200: evidence.append(f'len_diff={r["len_diff"]}')
        if r['resp_time'] > 2.0: evidence.append(f'slow response {r["resp_time"]}s')
        suggested_fix = 'Use parameterized queries / ORM + input validation'
        rows.append({'url': r['url'], 'param': r['param'], 'payload': r['payload'], 'confidence': float(r['confidence']),
                     'evidence': '; '.join(evidence) if evidence else 'no clear heuristic', 'suggested_fix': suggested_fix})
    # save CSV
    out_df = pd.DataFrame(rows).sort_values('confidence', ascending=False)
    out_df.to_csv(OUT_CSV, index=False)
    # save HTML
    html = Template(tpl).render(rows=out_df.to_dict('records'))
    with open(OUT_HTML, 'w', encoding='utf8') as f:
        f.write(html)
    print("Wrote", OUT_CSV, "and", OUT_HTML)

if __name__ == '__main__':
    main()
