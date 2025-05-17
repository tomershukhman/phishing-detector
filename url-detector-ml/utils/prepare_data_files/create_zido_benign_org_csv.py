import os
import pandas as pd
import glob


def unify_csv_files(directory, output_file):
    # Get list of all CSV files in the specified directory and its subdirectories
    csv_files = glob.glob(os.path.join(
        directory, '**', '*.csv'), recursive=True)

    if not csv_files:
        print(f"No CSV files found in {directory}")
        return False

    print(f"Found {len(csv_files)} CSV files")

    # Initialize an empty list to store dataframes
    dfs = []

    # Read each CSV file and append to the list
    for csv_file in csv_files:
        try:
            print(f"Reading {csv_file}")
            df = pd.read_csv(csv_file)
            # Keep only the url column
            if 'url' in df.columns:
                df = df[['url']]
                # Add label and resukt columns
                df['label'] = 'benign'
                df['resukt'] = 0
                dfs.append(df)
            else:
                print(f"Warning: 'url' column not found in {csv_file}")
        except Exception as e:
            print(f"Error reading {csv_file}: {e}")

    if not dfs:
        print("No data was read from CSV files")
        return False

    # Concatenate all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)

    # Save to output file
    combined_df.to_csv(output_file, index=False)
    print(f"Successfully created {output_file} with {len(combined_df)} rows")
    return True


if __name__ == "__main__":
    zido_data_dir = "zido_data"
    output_file = "zido_data.csv"

    unify_csv_files(zido_data_dir, output_file)
