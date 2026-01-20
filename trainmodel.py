# train_model.py
import pandas as pd, numpy as np, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

IN = 'sqli_runs_features.csv'
OUT = 'sqli_model_package.joblib'
LABEL_COL = 'label'  # we'll add labels heuristically below

def add_heuristic_label(df):
    # Create a heuristic label to bootstrap training
    # 1 if sql_error_flag or large len_diff or long resp_time (time-based)
    df['label'] = 0
    df.loc[df['sql_error_flag']==1, 'label'] = 1
    df.loc[df['len_diff'] > 200, 'label'] = 1
    df.loc[df['resp_time'] > 2.0, 'label'] = 1
    return df

def preprocess(df, feature_cols):
    # drop constant cols, fill NaNs, encode categorical
    X = df[feature_cols].copy()
    # Fill NaNs
    for c in X.columns:
        if X[c].isnull().any():
            if np.issubdtype(X[c].dtype, np.number):
                X[c] = X[c].fillna(X[c].median())
            else:
                X[c] = X[c].fillna('<<MISSING>>')
    # One-hot encode payload_type if present
    obj_cols = X.select_dtypes(include=['object','category']).columns.tolist()
    if obj_cols:
        X = pd.get_dummies(X, columns=obj_cols, drop_first=True)
    return X

def main():
    df = pd.read_csv(IN)
    df = add_heuristic_label(df)
    # define feature columns we want to use
    feature_cols = ['status','resp_len','resp_time','sql_error_flag','len_diff','seq_ratio','payload_type']
    # if payload_type is present only as object, it will be one-hoted
    # ensure columns exist
    feature_cols = [c for c in feature_cols if c in df.columns]
    X = preprocess(df, feature_cols)
    y = df['label'].astype(int)

    # remove constant columns
    X = X.loc[:, X.nunique() > 1]

    # require at least two classes
    if y.nunique() < 2:
        raise SystemExit("Need at least two classes to train. Adjust heuristics or add labeled data.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    print("Test accuracy:", clf.score(X_test, y_test))
    print(classification_report(y_test, clf.predict(X_test)))
    # Save model + feature list
    package = {'model': clf, 'feature_columns': X.columns.tolist()}
    joblib.dump(package, OUT)
    print("Saved model package to", OUT)

if __name__ == '__main__':
    main()
