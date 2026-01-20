# train_rf.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

df = pd.read_csv("data/features.csv")
# REQUIRED: add or create a 'label' column. This script assumes label exists.
if "label" not in df.columns:
    raise SystemExit("Add a 'label' column to data/features.csv before training")

X = df.drop(columns=["url","label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2, random_state=42, stratify=y)
clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))

joblib.dump(clf, "models/rf_webscanpro.pkl")
print("Saved model to models/rf_webscanpro.pkl")
