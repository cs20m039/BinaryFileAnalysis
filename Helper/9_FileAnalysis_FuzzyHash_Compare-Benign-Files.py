import ssdeep
import os
import csv
import logging

# Set up logging to capture more detailed information
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_hashes_from_csv(csv_file):
    """
    Loads the file hashes from a CSV file.
    Returns a dictionary mapping file paths to their fuzzy hashes.
    """
    hashes_a = {}
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header row
        for rows in reader:
            if rows:  # Ensure row is not empty
                hashes_a[rows[0]] = rows[1]
    logging.debug(f'Loaded {len(hashes_a)} hashes from {csv_file}')
    return hashes_a

def hash_and_compare(directory_b, hashes_a, results_csv):
    """
    Hashes files in directory B and compares them against the hashes from directory A.
    Writes matches with a similarity above 70% to a CSV file, including the original file from A.
    """
    matches_summary = {}  # Dictionary to hold actual similarity percentages
    matches_found = 0  # Counter for matches found

    with open(results_csv, 'w', newline='') as csvfile:
        fieldnames = ['file_a', 'hash_a', 'file_b', 'similarity']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for root, _, files in os.walk(directory_b):
            for file in files:
                file_path_b = os.path.join(root, file)
                logging.debug(f'Processing file: {file_path_b}')
                try:
                    with open(file_path_b, 'rb') as f:
                        file_content = f.read()
                    hash_b = ssdeep.hash(file_content)
                    logging.debug(f'Hash for {file_path_b}: {hash_b}')

                    for file_a, hash_a in hashes_a.items():
                        similarity = ssdeep.compare(hash_a, hash_b)

                        if similarity > 70:
                            writer.writerow({
                                'file_a': file_a,
                                'hash_a': hash_a,
                                'file_b': file_path_b,
                                'similarity': similarity
                            })
                            matches_found += 1
                            logging.info(f'Match found: {file_path_b} matches {file_a} with {similarity}% similarity')
                            matches_summary[similarity] = matches_summary.get(similarity, 0) + 1
                except Exception as e:
                    logging.error(f'Error processing {file_path_b}: {e}')

    # Log the summary of matches for each real percentage
    for similarity, count in sorted(matches_summary.items(), key=lambda item: item[0], reverse=True):
        logging.info(f'Matches found with {similarity}% similarity: {count}')
    logging.info(f'Comparison complete. {matches_found} matches found with similarity > 70%.')

if __name__ == '__main__':
    hashes_a_csv = 'datashare/hashes_malicious.csv'  # Replace with your actual file path
    directory_b = '/home/cs20m039/thesis/dataset_test'  # Replace with your actual directory path
    results_csv = 'datashare/hashes_results-compare-benign-with-malicious.csv'  # Output CSV file path

    logging.info(f'Loading hashes from {hashes_a_csv}...')
    hashes_a = load_hashes_from_csv(hashes_a_csv)

    logging.info(f'Starting comparison of files in {directory_b} against hashes from {hashes_a_csv}...')
    hash_and_compare(directory_b, hashes_a, results_csv)
