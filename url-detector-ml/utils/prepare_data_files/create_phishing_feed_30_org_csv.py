#!/usr/bin/env python
import json
import csv
import os

# Ensure output directories exist
os.makedirs('data/raw', exist_ok=True)
os.makedirs('data/org', exist_ok=True)

# Input and output file paths
json_file = 'data/raw/phishing_feed_30_days'
raw_csv_file = 'data/raw/phishing_feed_30_raw.csv'
org_csv_file = 'data/org/phishing_feed_30_org.csv'

# Read the JSON data
print(f"Reading JSON data from {json_file}...")
with open(json_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Write the raw CSV file with all JSON data
print(f"Writing raw data to {raw_csv_file}...")
if isinstance(data, list) and len(data) > 0:
    # Get all unique keys from the JSON data
    keys = set()
    for item in data:
        if isinstance(item, dict):
            keys.update(item.keys())

    keys = sorted(list(keys))

    with open(raw_csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in data:
            if isinstance(item, dict):
                writer.writerow(item)
elif isinstance(data, dict):
    # If the JSON is a dictionary, write it directly
    with open(raw_csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)
else:
    print("Unexpected JSON format. Please check the file structure.")

# Write the organized CSV file with url, label, and result columns
print(f"Writing organized data to {org_csv_file}...")
with open(org_csv_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['url', 'label', 'result'])

    # Extract URLs from the JSON data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                # Look for common URL field names
                url = None
                for field in ['url', 'URL', 'uri', 'URI', 'phish_url', 'phishing_url']:
                    if field in item:
                        url = item[field]
                        break

                if url:
                    writer.writerow([url, 'phishing', 1])
    elif isinstance(data, dict):
        # If the data is a single dictionary, try to extract URL
        for field in ['url', 'URL', 'uri', 'URI', 'phish_url', 'phishing_url']:
            if field in data:
                writer.writerow([data[field], 'phishing', 1])
                break

print("Processing complete!")
