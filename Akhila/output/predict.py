import pandas as pd
import joblib
import os


model_path = "models/rf_webscanpro.pkl"
features_path = "data/features.csv"
output_path = "data/predictions.csv"


if not os.path.exists(model_path):
    raise FileNotFoundError(f"Model not found at {model_path}. Train the model first.")

if not os.path.exists(features_path):
    raise FileNotFoundError(f"Features file not found at {features_path}. Run features.py first.")

print("Loading model...")
model = joblib.load(model_path)

print("Loading features...")
df = pd.read_csv(features_path)

print("Preparing feature matrix...")
X = df.drop(columns=["url", "label"], errors="ignore")

print("Running predictions...")
preds = model.predict(X)
df["prediction"] = preds

print(f"Saving predictions to {output_path}...")
df.to_csv(output_path, index=False)

print("✔ Prediction completed! Check data/predictions.csv")
