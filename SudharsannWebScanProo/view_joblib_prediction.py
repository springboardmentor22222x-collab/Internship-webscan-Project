import joblib
import os

print("SCRIPT STARTED")

# Build correct path
model_path = os.path.join("ml_models", "access_access_classifier.joblib")

print("Model path:", model_path)

# Load model
model = joblib.load(model_path)

print("MODEL LOADED SUCCESSFULLY")
