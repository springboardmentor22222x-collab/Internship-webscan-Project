import os

print("\n📂 CSV FILES IN THIS FOLDER:\n")
for f in os.listdir():
    if f.lower().endswith(".csv"):
        print(f)
