# train_xss.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

os.makedirs('models', exist_ok=True)

df = pd.read_csv('data/xss_dataset.csv')
X = df['text'].astype(str)
y = df['label']

# character n-grams are useful for small short payload detection
vectorizer = TfidfVectorizer(ngram_range=(1,3), analyzer='char_wb', max_features=3000)
X_vec = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:,1]

print("Classification report:")
print(classification_report(y_test, y_pred))
try:
    print("ROC AUC:", roc_auc_score(y_test, y_prob))
except Exception:
    pass

joblib.dump({'model': model, 'vectorizer': vectorizer}, 'models/xss_detector.joblib')
print("Saved model to models/xss_detector.joblib")
