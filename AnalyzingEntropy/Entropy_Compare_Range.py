import csv
import datetime
import logging

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_FILE_PATH = f'../Logfiles/log_entropy_compare_{timestamp}.txt'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])


def read_entropy_values_with_hashes(csv_path):
    logging.debug(f"Opening CSV file: {csv_path}")
    entropy_hashes = {}
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            headers = next(csvreader)[1:]  # Skip the 'Hash' column
            entropy_hashes = {header: {} for header in headers}
            for row in csvreader:
                hash_value = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:
                        value = float(value)
                        if value not in entropy_hashes[header]:
                            entropy_hashes[header][value] = [hash_value]
                        else:
                            entropy_hashes[header][value].append(hash_value)
    except Exception as e:
        logging.error(f"Error reading CSV file {csv_path}: {e}")
    return entropy_hashes


def compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign):
    logging.info("Starting comparison of entropy values...")
    for header in entropy_hashes_malicious:
        logging.debug(f"Processing {header}:")
        for value_malicious, hashes_malicious in entropy_hashes_malicious[header].items():
            logging.debug(f"Checking malicious value: {value_malicious}")
            if value_malicious in entropy_hashes_benign[header]:
                hashes_benign = entropy_hashes_benign[header][value_malicious]
                count_benign = len(hashes_benign)

                logging.info(f"{header} - Entropy Value: {value_malicious} - Match: {count_benign}")
                for hash_malicious in hashes_malicious:
                    logging.debug(f"  - Malicious Hash: {hash_malicious}")
                for hash_benign in hashes_benign:
                    logging.debug(f"  - Benign Hash: {hash_benign}")
            else:
                logging.debug(f"Entropy Value: {value_malicious} - No match found in benign hashes.")
    logging.info("Comparison of entropy values completed.")


if __name__ == "__main__":
    READ_MODE = 'header'  # Adjust based on the mode used for generating CSVs
    MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_entropy_malicious_{READ_MODE}_4-500.csv"
    BENIGN_INPUT_CSV = f"../DataExchange/datafile_entropy_benign_{READ_MODE}_4-500.csv"
    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious and entropy_hashes_benign:
        compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
