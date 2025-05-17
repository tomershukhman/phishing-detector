#!/usr/bin/env python
# filepath: /Users/tomer.shukhman/dev/phishing-v2/prepare_data/create_phistank_org_csv.py

import csv
import os

# Ensure output directories exist
os.makedirs('data/raw', exist_ok=True)
os.makedirs('data/org', exist_ok=True)

# Input and output file paths
input_file = 'data/raw/phishtank_raw.csv'
output_file = 'data/org/phishtank_org.csv'

# Read the input CSV file and create the output CSV file
print(f"Processing data from {input_file} to {output_file}...")

# Create the output CSV with three columns: url, Label, Result
with open(input_file, 'r', encoding='utf-8') as infile, \
     open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    
    # Create CSV reader and writer
    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    
    # Write the header row for the output file
    writer.writerow(['url', 'Label', 'Result'])
    
    # Process each row from input file
    count = 0
    for row in reader:
        # Extract URL from the input data
        url = row.get('url', '')
        
        if url:
            # Write the row with the specified values
            writer.writerow([url, 'benign', 1])
            count += 1
    
    print(f"Successfully processed {count} URLs to {output_file}")

print("Processing complete!")