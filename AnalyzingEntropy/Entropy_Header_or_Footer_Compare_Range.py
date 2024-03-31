import csv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO,  # Adjust as needed
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('../Logfiles/comparison_output.log', mode='w'),
                        logging.StreamHandler()
                    ])

def read_entropy_values_with_hashes(csv_path):
    """Read entropy values and corresponding hashes from a CSV file."""
    logging.debug(f"Opening CSV file: {csv_path}")
    entropy_hashes = {}  # Initialize to ensure a return value
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            headers = next(csvreader)[1:]  # Assumes first row is headers and skips 'Hash'
            entropy_hashes = {header: {} for header in headers}
            for row in csvreader:
                hash_value = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:  # Ensure the value is not empty
                        value = float(value)
                        if value not in entropy_hashes[header]:
                            entropy_hashes[header][value] = [hash_value]
                        else:
                            entropy_hashes[header][value].append(hash_value)
    except Exception as e:
        logging.error(f"Error reading CSV file {csv_path}: {e}")
    return entropy_hashes

def compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign):
    """Compare entropy values from malicious dataset with all values from benign dataset,
    focusing on exact matches. Logs the count of matching benign hashes."""
    logging.info("Starting comparison of entropy values...")
    for header in entropy_hashes_malicious:
        logging.info(f"Processing {header}:")
        for value_malicious, hashes_malicious in entropy_hashes_malicious[header].items():
            logging.debug(f"Checking malicious value: {value_malicious}")
            if value_malicious in entropy_hashes_benign[header]:
                hashes_benign = entropy_hashes_benign[header][value_malicious]
                count_benign = len(hashes_benign)

                logging.info(f"{header} - Entropy Value: {value_malicious} - Match found with {count_benign} benign hashes.")
                for hash_malicious in hashes_malicious:
                    logging.debug(f"  - Malicious Hash: {hash_malicious}")
                for hash_benign in hashes_benign:
                    logging.debug(f"  - Benign Hash: {hash_benign}")
            else:
                logging.debug(f"Entropy Value: {value_malicious} - No match found in benign hashes.")
    logging.info("Comparison of entropy values completed.")


# Main execution
if __name__ == "__main__":
    # Adjust these file paths according to your environment
    MALICIOUS_INPUT_CSV = "../DataExchange/datafile_read_entropy_malicious_1-1000.csv"
    BENIGN_INPUT_CSV = "../DataExchange/datafile_read_entropy_benign_1-1000.csv"

    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious is not None and entropy_hashes_benign is not None:
        compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
