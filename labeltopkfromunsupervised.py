# label_topk_from_unsupervised.py
import pandas as pd

SRC = 'sqli_unsupervised_scores.csv'
OUT = 'sqli_runs_features_auto_labeled.csv'
K = 30   # change to how many top anomalies you want to mark positive

df = pd.read_csv(SRC)
df = df.sort_values('anomaly_score', ascending=False).reset_index(drop=True)
df['label'] = 0
df.loc[:K-1, 'label'] = 1
print(f"Marked top {K} rows as label=1. Label counts:\n", df['label'].value_counts())
# Keep only expected feature columns (if your train pipeline expects certain columns)
# But we'll save everything: train_model.py will pick features it needs.
df.to_csv(OUT, index=False)
print("Wrote", OUT)
