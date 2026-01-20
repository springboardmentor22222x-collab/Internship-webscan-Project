import pandas as pd

df = pd.read_csv("data/features.csv")
df["label"] = 0   # Testing only
df.to_csv("data/features.csv", index=False)

print("Label column added ✔")
