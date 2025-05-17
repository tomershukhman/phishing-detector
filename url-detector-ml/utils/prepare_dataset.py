import pandas as pd
import os
from urllib.parse import urlparse, urlunparse
import random
import tldextract


def extract_hostname(url):
    """
    Normalize a URL by extracting its hostname using tldextract
    """
    try:
        extracted = tldextract.extract(url)
        hostname = f"{extracted.domain}.{extracted.suffix}"
        if extracted.subdomain:
            hostname = f"{extracted.subdomain}.{hostname}"
        return hostname.lower()
    except:
        return None


def normalize_url(url):
    """
    Normalize a URL by removing / at the end if present
    """
    if url.endswith('/'):
        return url[:-1]
    return url

def balance_datasets():
    """
    Main function to process datasets:
    1. Load zido_benign_org.csv for benign URLs
    2. Load phishing data from phishtank_org.csv and phishing_feed_30_org.csv
    3. Load additional URLs from balanced_urls_old.csv if it exists
    4. Normalize URLs
    5. Remove duplicate hostnames
    6. Output the combined data to data/balanced_urls.csv
    """
    # Track dataset statistics for final report
    stats = {
        'benign': {
            'original': 0,
            'after_normalization': 0,
            'after_deduplication': 0
        },
        'phishing': {
            'sources': {},
            'combined': 0,
            'after_normalization': 0,
            'after_deduplication': 0
        },
        'old_balanced': {
            'benign': 0,
            'phishing': 0,
            'total': 0
        },
        'final': {
            'benign': 0,
            'phishing': 0,
            'total': 0
        }
    }

    # Ensure output directory exists
    os.makedirs('data', exist_ok=True)

    print("Loading benign URLs dataset...")
    benign_df = pd.read_csv('data/org/zido_benign_org.csv')
    print(f"Benign dataset shape: {benign_df.shape}")
    print(f"Benign columns: {benign_df.columns}")

    # Store original count
    stats['benign']['original'] = benign_df.shape[0]

    # Ensure benign dataset has required columns
    if 'url' not in benign_df.columns:
        if 'URL' in benign_df.columns:
            benign_df.rename(columns={'URL': 'url'}, inplace=True)
        else:
            raise ValueError(
                "Benign dataset must have a 'url' or 'URL' column")

    # Add result column if not present
    if 'result' not in benign_df.columns:
        benign_df['result'] = 0  # 0 = benign

    # Add label column if not present
    if 'label' not in benign_df.columns:
        benign_df['label'] = 'benign'

    # Load phishing datasets
    print("Loading phishing datasets...")
    phishtank_df = pd.read_csv('data/org/phishtank_org.csv')
    print(f"PhishTank dataset shape: {phishtank_df.shape}")
    print(f"PhishTank columns: {phishtank_df.columns}")

    # Store source counts
    stats['phishing']['sources']['phishtank'] = phishtank_df.shape[0]

    phishing_feed_df = pd.read_csv('data/org/phishing_feed_30_org.csv')
    print(f"Phishing feed dataset shape: {phishing_feed_df.shape}")
    print(f"Phishing feed columns: {phishing_feed_df.columns}")

    # Store source counts
    stats['phishing']['sources']['phishing_feed'] = phishing_feed_df.shape[0]

    # Ensure phishing datasets have required columns
    phishing_dfs = []

    # Process PhishTank data
    if 'url' not in phishtank_df.columns:
        if 'URL' in phishtank_df.columns:
            phishtank_df.rename(columns={'URL': 'url'}, inplace=True)
        else:
            # Try to find the URL column
            url_cols = [
                col for col in phishtank_df.columns if 'url' in col.lower()]
            if url_cols:
                phishtank_df.rename(columns={url_cols[0]: 'url'}, inplace=True)
            else:
                print("Warning: Could not find URL column in PhishTank data")
                # Skip this dataset if we can't find a URL column
                phishtank_df = None

    if phishtank_df is not None:
        phishtank_df['result'] = 1  # 1 = phishing
        phishtank_df['label'] = 'phishing'
        phishing_dfs.append(phishtank_df)

    # Process Phishing Feed data
    if 'url' not in phishing_feed_df.columns:
        if 'URL' in phishing_feed_df.columns:
            phishing_feed_df.rename(columns={'URL': 'url'}, inplace=True)
        else:
            # Try to find the URL column
            url_cols = [
                col for col in phishing_feed_df.columns if 'url' in col.lower()]
            if url_cols:
                phishing_feed_df.rename(
                    columns={url_cols[0]: 'url'}, inplace=True)
            else:
                print("Warning: Could not find URL column in Phishing feed data")
                # Skip this dataset if we can't find a URL column
                phishing_feed_df = None

    if phishing_feed_df is not None:
        phishing_feed_df['result'] = 1  # 1 = phishing
        phishing_feed_df['label'] = 'phishing'
        phishing_dfs.append(phishing_feed_df)

    # Combine all phishing data
    if phishing_dfs:
        combined_phishing_df = pd.concat(phishing_dfs, ignore_index=True)
        print(f"Combined phishing dataset shape: {combined_phishing_df.shape}")

        # Store combined count
        stats['phishing']['combined'] = combined_phishing_df.shape[0]
    else:
        raise ValueError("No valid phishing data found")
        
    # Load old balanced URLs dataset if it exists
    old_balanced_df = None
    try:
        print("Loading old balanced URLs dataset...")
        old_balanced_df = pd.read_csv('data/balanced_urls_old.csv')
        print(f"Old balanced dataset shape: {old_balanced_df.shape}")
        print(f"Old balanced columns: {old_balanced_df.columns}")
        
        # Ensure it has the required columns
        if 'url' not in old_balanced_df.columns:
            if 'URL' in old_balanced_df.columns:
                old_balanced_df.rename(columns={'URL': 'url'}, inplace=True)
            else:
                print("Warning: Could not find URL column in old balanced dataset")
                old_balanced_df = None
                
        # Ensure it has result and label columns    
        if old_balanced_df is not None:
            # Add result column if not present
            if 'result' not in old_balanced_df.columns:
                # Try to infer from label column
                if 'label' in old_balanced_df.columns:
                    old_balanced_df['result'] = old_balanced_df['label'].apply(
                        lambda x: 1 if x == 'phishing' else 0)
                else:
                    print("Warning: Could not determine results for old balanced dataset")
                    old_balanced_df = None
                    
            # Add label column if not present
            if old_balanced_df is not None and 'label' not in old_balanced_df.columns:
                old_balanced_df['label'] = old_balanced_df['result'].apply(
                    lambda x: 'phishing' if x == 1 else 'benign')
                    
        # Track stats for old balanced dataset
        if old_balanced_df is not None:
            stats['old_balanced']['total'] = old_balanced_df.shape[0]
            stats['old_balanced']['benign'] = len(old_balanced_df[old_balanced_df['result'] == 0])
            stats['old_balanced']['phishing'] = len(old_balanced_df[old_balanced_df['result'] == 1])
            
            print(f"Old balanced dataset loaded with {stats['old_balanced']['total']} entries:")
            print(f"  - Benign: {stats['old_balanced']['benign']}")
            print(f"  - Phishing: {stats['old_balanced']['phishing']}")
        else:
            print("Warning: Old balanced dataset could not be loaded or processed")
            
    except FileNotFoundError:
        print("Warning: data/balanced_urls_old.csv not found, continuing without it.")
    except Exception as e:
        print(f"Error loading old balanced dataset: {e}")
        
    # Normalize URLs for all datasets
    print("Extracting hostnames...")
    benign_df['hostname'] = benign_df['url'].apply(extract_hostname)
    combined_phishing_df['hostname'] = combined_phishing_df['url'].apply(extract_hostname)
    
    if old_balanced_df is not None:
        print("Extracting hostnames for old balanced dataset...")
        old_balanced_df['hostname'] = old_balanced_df['url'].apply(extract_hostname)

    print("normalizing urls...")
    benign_df['url'] = benign_df['url'].apply(normalize_url)
    combined_phishing_df['url'] = combined_phishing_df['url'].apply(normalize_url)
    
    if old_balanced_df is not None:
        print("Normalizing URLs for old balanced dataset...")
        old_balanced_df['url'] = old_balanced_df['url'].apply(normalize_url)

    # Remove rows with None hostnames
    benign_df = benign_df.dropna(subset=['hostname'])
    combined_phishing_df = combined_phishing_df.dropna(subset=['hostname'])
    
    if old_balanced_df is not None:
        old_balanced_df = old_balanced_df.dropna(subset=['hostname'])

    print(f"Benign dataset after normalization: {benign_df.shape}")
    print(f"Phishing dataset after normalization: {combined_phishing_df.shape}")
    if old_balanced_df is not None:
        print(f"Old balanced dataset after normalization: {old_balanced_df.shape}")

    # Store after normalization counts
    stats['benign']['after_normalization'] = benign_df.shape[0]
    stats['phishing']['after_normalization'] = combined_phishing_df.shape[0]

    # Remove duplicate hostnames within each category
    print("Removing duplicate hostnames within each category...")
    benign_df = benign_df.drop_duplicates(subset=['hostname'])
    combined_phishing_df = combined_phishing_df.drop_duplicates(subset=['hostname'])

    print(f"Benign dataset after deduplication: {benign_df.shape}")
    print(f"Phishing dataset after deduplication: {combined_phishing_df.shape}")

    # Store after deduplication counts
    stats['benign']['after_deduplication'] = benign_df.shape[0]
    stats['phishing']['after_deduplication'] = combined_phishing_df.shape[0]

    # Use all entries from both datasets
    print("Using all entries from both datasets...")

    # Combine the datasets
    print("Combining data...")
    if old_balanced_df is not None:
        combined_df = pd.concat([benign_df, combined_phishing_df, old_balanced_df])
        print(f"Combined with old balanced dataset. New shape: {combined_df.shape}")
    else:
        combined_df = pd.concat([benign_df, combined_phishing_df])
        
    # Remove duplicates based on hostname across the entire dataset
    if old_balanced_df is not None:
        print("Removing duplicates across the entire combined dataset...")
        original_size = combined_df.shape[0]
        combined_df = combined_df.drop_duplicates(subset=['hostname'])
        removed = original_size - combined_df.shape[0]
        print(f"Removed {removed} duplicates from the combined dataset")

    # Drop the hostname column from the output
    print("Preparing final output...")
    combined_df = combined_df[['url', 'label', 'result']]

    # REMOVED: www variant duplication
    # print("Skipping URL duplication with www prefix...")

    # Shuffle the dataset and reset indices
    print("Shuffling dataset...")
    combined_df = combined_df.sample(
        frac=1, random_state=42).reset_index(drop=True)

    # Save the combined dataset
    print("Saving combined dataset...")

    combined_df.to_csv('data/balanced_urls.csv', index=False)
    print(f"Combined dataset saved with shape: {combined_df.shape}")
    print(f"Benign entries: {len(combined_df[combined_df['result'] == 0])}")
    print(f"Phishing entries: {len(combined_df[combined_df['result'] == 1])}")

    # Store final counts
    stats['final']['benign'] = len(combined_df[combined_df['result'] == 0])
    stats['final']['phishing'] = len(combined_df[combined_df['result'] == 1])
    stats['final']['total'] = combined_df.shape[0]

    # Verify no duplicate hostnames in the final dataset
    duplicates_found = verify_no_duplicate_hostnames('data/balanced_urls.csv')

    # Print final summary report
    print_summary_report(stats, duplicates_found)


def verify_no_duplicate_hostnames(csv_path):
    """
    Verify that there are no duplicate hostnames in the CSV file.
    Also checks if the same hostname appears in both result categories (0 and 1).
    Returns True if duplicates were found, False otherwise.
    """
    print("\nVerifying no duplicate hostnames in the output file...")

    # Load the CSV
    df = pd.read_csv(csv_path)

    # Normalize URLs to extract hostnames
    print("Re-calculating hostnames for verification...")
    df['hostname'] = df['url'].apply(extract_hostname)

    # Count hostnames
    total_records = len(df)
    unique_hostnames = len(df['hostname'].unique())
    duplicates = df[df.duplicated(subset=['hostname'], keep=False)]

    print(f"Total records: {total_records}")
    print(f"Unique hostnames: {unique_hostnames}")

    has_duplicates = False

    if len(duplicates) > 0:
        has_duplicates = True
        print(
            f"WARNING: Found {len(duplicates)} records with duplicate hostnames!")
        # Group by hostname and show counts
        duplicate_counts = duplicates['hostname'].value_counts()
        print("\nTop duplicate hostnames:")
        print(duplicate_counts.head(10))

        # Save duplicates to a separate file for inspection
        duplicates.to_csv('data/duplicate_hostnames.csv', index=False)
        print("Duplicate records saved to data/duplicate_hostnames.csv for inspection")
    else:
        print("SUCCESS: No duplicate hostnames found in the balanced dataset.")

    # Check for hostnames that appear in both result categories
    print("\nChecking for hostnames that appear in both result categories...")
    hostname_by_result = {}

    # Group hostnames by result
    for result in df['result'].unique():
        hostname_by_result[result] = set(
            df[df['result'] == result]['hostname'])

    # Check for overlaps between categories
    overlapping_hostnames = set()
    for result1 in hostname_by_result:
        for result2 in hostname_by_result:
            if result1 < result2:  # Avoid comparing the same sets twice
                overlap = hostname_by_result[result1].intersection(
                    hostname_by_result[result2])
                if overlap:
                    overlapping_hostnames.update(overlap)
                    print(
                        f"Found {len(overlap)} hostnames that appear in both result={result1} and result={result2}")

    if overlapping_hostnames:
        has_duplicates = True
        print(
            f"WARNING: Found {len(overlapping_hostnames)} hostnames that appear in multiple result categories!")
        # Get the problematic records
        cross_category_records = df[df['hostname'].isin(overlapping_hostnames)]
        cross_category_records.to_csv(
            'data/cross_category_hostnames.csv', index=False)
        print("Cross-category records saved to data/cross_category_hostnames.csv for inspection")

        # Show some examples
        print("\nExamples of problematic hostnames:")
        for hostname in list(overlapping_hostnames)[:5]:
            records = df[df['hostname'] == hostname]
            print(f"\nHostname: {hostname}")
            print(records[['url', 'result', 'hostname']])
    else:
        print("SUCCESS: No hostnames appear in multiple result categories.")

    return has_duplicates


def print_summary_report(stats, has_duplicates):
    """
    Print a clear, concise summary report of the dataset preparation process.
    """
    print("\n" + "="*80)
    print("DATASET PREPARATION SUMMARY REPORT")
    print("="*80)

    # Input datasets
    print("\nINPUT DATASETS:")
    print(
        f"  Legitimate URLs (zido_benign_org.csv): {stats['benign']['original']:,}")

    phishing_total = sum(stats['phishing']['sources'].values())
    print("\n  Phishing URLs:")
    for source, count in stats['phishing']['sources'].items():
        print(f"    - {source}: {count:,} ({count/phishing_total:.1%})")
    print(f"    Total phishing URLs: {phishing_total:,}")
    
    # Additional dataset - old balanced URLs
    if 'old_balanced' in stats and stats['old_balanced']['total'] > 0:
        print("\n  Old balanced URLs (balanced_urls_old.csv):")
        print(f"    - Total: {stats['old_balanced']['total']:,}")
        print(f"    - Legitimate URLs: {stats['old_balanced']['benign']:,} ({stats['old_balanced']['benign']/stats['old_balanced']['total']:.1%})")
        print(f"    - Phishing URLs: {stats['old_balanced']['phishing']:,} ({stats['old_balanced']['phishing']/stats['old_balanced']['total']:.1%})")

    # Processing results
    print("\nPROCESSING RESULTS:")

    # Legitimate URLs
    print("\n  Legitimate URLs:")
    print(f"    - Original count: {stats['benign']['original']:,}")
    norm_removed = stats['benign']['original'] - \
        stats['benign']['after_normalization']
    print(
        f"    - After normalization: {stats['benign']['after_normalization']:,} ({norm_removed:,} removed)")
    dedup_removed = stats['benign']['after_normalization'] - \
        stats['benign']['after_deduplication']
    print(
        f"    - After deduplication: {stats['benign']['after_deduplication']:,} ({dedup_removed:,} duplicates removed)")

    # Phishing URLs
    print("\n  Phishing URLs:")
    print(f"    - Combined count: {stats['phishing']['combined']:,}")
    norm_removed = stats['phishing']['combined'] - \
        stats['phishing']['after_normalization']
    print(
        f"    - After normalization: {stats['phishing']['after_normalization']:,} ({norm_removed:,} removed)")
    dedup_removed = stats['phishing']['after_normalization'] - \
        stats['phishing']['after_deduplication']
    print(
        f"    - After deduplication: {stats['phishing']['after_deduplication']:,} ({dedup_removed:,} duplicates removed)")

    # Final dataset
    print("\nFINAL DATASET (balanced_urls.csv):")
    print(f"  Total URLs: {stats['final']['total']:,}")
    print(
        f"  Legitimate URLs: {stats['final']['benign']:,} ({stats['final']['benign']/stats['final']['total']:.1%})")
    print(
        f"  Phishing URLs: {stats['final']['phishing']:,} ({stats['final']['phishing']/stats['final']['total']:.1%})")

    # Data integrity
    print("\nDATA INTEGRITY:")
    if has_duplicates:
        print("  ⚠️ WARNING: Duplicate hostnames detected. See above for details.")
    else:
        print("  ✅ SUCCESS: No duplicate hostnames found.")

    print("\n" + "="*80)


if __name__ == "__main__":
    balance_datasets()
