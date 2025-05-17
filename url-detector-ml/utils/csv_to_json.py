import csv
import json
import sys
from pathlib import Path

def extract_second_column_to_json(csv_path: str) -> None:
    """
    Extracts the second column from a CSV file and writes it to a JSON file
    with the same base name as the input CSV, but with a .json extension.

    Args:
        csv_path (str): Path to the input CSV file.
    """
    csv_file = Path(csv_path)
    if not csv_file.is_file():
        print(f"Error: File '{csv_path}' does not exist.")
        sys.exit(1)

    output_json_path = csv_file.with_suffix('.json')
    second_column_values = []

    with csv_file.open(mode='r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row_number, row in enumerate(reader, start=1):
            if len(row) < 2:
                print(f"Warning: Row {row_number} has fewer than 2 columns, skipping.")
                continue
            second_column_values.append(row[1])

    with output_json_path.open(mode='w', encoding='utf-8') as out_file:
        json.dump(second_column_values, out_file, ensure_ascii=False, indent=2)

    print(f"Extracted {len(second_column_values)} entries into '{output_json_path}'.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_second_column.py <input_csv_file>")
        sys.exit(1)
    
    extract_second_column_to_json(sys.argv[1])
