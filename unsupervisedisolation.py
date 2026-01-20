# unsupervised_isolation.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

df = pd.read_csv('sqli_runs_features.csv')
# pick numeric columns
num = df.select_dtypes(include=['number']).copy()
# drop the label if present
if 'label' in num.columns: num = num.drop(columns=['label'])
# fill NaNs
num = num.fillna(num.median())
clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
clf.fit(num)
scores = -clf.decision_function(num)  # higher => more anomalous
df['anomaly_score'] = scores
df = df.sort_values('anomaly_score', ascending=False)
df[['url','param','payload','resp_len','len_diff','sql_error_flag','resp_time','anomaly_score']].head(50).to_csv('sqli_unsupervised_scores.csv', index=False)
print("Wrote sqli_unsupervised_scores.csv — inspect top rows as likely issues.")
joblib.dump({'isof':clf, 'feature_cols': num.columns.tolist()}, 'isof_package.joblib')
