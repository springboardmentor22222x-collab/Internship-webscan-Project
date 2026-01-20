# test_output.py
import json
import os

print("Checking output files...")
for filename in os.listdir("output"):
    if filename.endswith(".json"):
        print(f"\n=== {filename} ===")
        try:
            with open(f"output/{filename}", "r") as f:
                data = json.load(f)
                print(f"Type: {type(data)}")
                if isinstance(data, dict):
                    print(f"Keys: {list(data.keys())}")
                    if 'vulnerabilities' in data:
                        print(f"Vulnerabilities count: {len(data['vulnerabilities'])}")
                        if data['vulnerabilities']:
                            print(f"Sample: {data['vulnerabilities'][0]}")
                elif isinstance(data, list):
                    print(f"Items count: {len(data)}")
                    if data:
                        print(f"Sample: {data[0]}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")