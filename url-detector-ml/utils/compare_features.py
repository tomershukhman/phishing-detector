#!/usr/bin/env .venv/bin/python
import json
import os
import glob
import shutil
from prettytable import PrettyTable

def get_latest_phishing_file():
    """Find the latest phishing-analysis*.json file in Downloads and copy it to extension-predictions"""
    # Search for phishing-analysis*.json files in Downloads
    home_dir = os.path.expanduser("~")
    downloads_dir = os.path.join(home_dir, "Downloads")
    pattern = os.path.join(downloads_dir, "phishing-analysis*.json")
    
    # Get all matching files
    matching_files = glob.glob(pattern)
    
    if not matching_files:
        print("Error: No phishing-analysis*.json files found in ~/Downloads")
        return None
    
    # Get the latest file based on modification time
    latest_file = max(matching_files, key=os.path.getmtime)
    
    # Create extension-predictions directory if it doesn't exist
    ext_dir = "extension-predictions"
    os.makedirs(ext_dir, exist_ok=True)
    
    # Get the filename and destination path
    filename = os.path.basename(latest_file)
    destination = os.path.join(ext_dir, filename)
    
    # Copy the file
    shutil.copy2(latest_file, destination)
    print(f"Copied latest phishing analysis file: {latest_file} to {destination}")
    
    return destination

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def round_float(value):
    """Round float values to 6 decimal places for comparison."""
    if isinstance(value, float):
        return round(value, 6)
    return value

def is_close_enough(val1, val2, tolerance=1e-6):
    """Check if two values are close enough considering floating point precision."""
    if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
        # Convert integers to float for comparison
        val1_float = float(val1)
        val2_float = float(val2)
        return abs(val1_float - val2_float) < tolerance
    # For non-numeric values, use direct comparison
    return val1 == val2

def main():
    # Get the latest phishing analysis file from Downloads
    extension_file_path = get_latest_phishing_file()
    if not extension_file_path:
        print("Could not find any phishing analysis files in Downloads. Exiting.")
        return
    
    # Load the JSON files
    extension_file = load_json_file(extension_file_path)
    python_file = load_json_file("prediction_results/python_prediction.json")
    
    # Create a table for comparison
    table = PrettyTable()
    table.field_names = ["Feature Name", "Extension Value", "Python Value", "Match"]
    
    # Extract features from extension file
    extension_features = extension_file["urlFeatures"]["features"]
    
    # Extract features from python file
    python_features = python_file["features"]
    
    # Get all unique feature names
    all_features = sorted(set(list(extension_features.keys()) + list(python_features.keys())))
    
    # Compare features and add to table
    for feature_name in all_features:
        ext_value = extension_features.get(feature_name, "N/A")
        py_value = python_features.get(feature_name, "N/A")
        
        # Format the values for display
        if isinstance(ext_value, float):
            ext_value = round(ext_value, 6)
        if isinstance(py_value, float):
            py_value = round(py_value, 6)
        
        # Check if values match
        match = "✓" if (ext_value == "N/A" or py_value == "N/A" or 
                        is_close_enough(ext_value, py_value)) else "✗"
        
        # Add row to table
        table.add_row([feature_name, ext_value, py_value, match])
    
    # Print the table
    print("\nFeature Comparison between Extension and Python Files:")
    print(table)
    
    # Summary statistics
    matches = sum(1 for row in table._rows if row[-1] == "✓")
    total = len(table._rows)
    print(f"\nSummary: {matches}/{total} features match ({(matches/total)*100:.2f}%)")
    
    # Display mismatched features
    if matches < total:
        print("\nMismatched Features:")
        for row in table._rows:
            if row[-1] == "✗":
                print(f"  - {row[0]}: Extension={row[1]}, Python={row[2]}")

if __name__ == "__main__":
    main()