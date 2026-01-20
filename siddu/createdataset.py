# data/create_dataset.py
import csv
import os

os.makedirs('data', exist_ok=True)

benign = [
    "Hello, this is a test message",
    "I like your website, thanks!",
    "Please contact me at example@example.com",
    "My name is John Doe",
    "Looking forward to the meeting",
    "Nice to meet you",
    "This is a normal comment"
]

xss = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "';alert(1);//",
    "\" onmouseover=alert(1) x=\"",
    "\"><svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<svg/onload=alert(1)>"
]

rows = []
for b in benign:
    rows.append([b, 0])
for x in xss:
    rows.append([x, 1])

os.makedirs('data', exist_ok=True)
with open('data/xss_dataset.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['text','label'])
    writer.writerows(rows)

print("Dataset created at data/xss_dataset.csv")
