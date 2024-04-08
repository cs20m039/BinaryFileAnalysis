import csv
import datetime
import logging

READ_MODE = 'footer'  # Adjust based on the mode used for generating CSVs
MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_entropy_malicious_{READ_MODE}_1-10.csv"
BENIGN_INPUT_CSV = f"../DataExchange/datafile_entropy_benign_{READ_MODE}_1-10.csv"

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_entropy_compare_{timestamp}.log'
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


def compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign, read_mode):
    logging.info(f"Starting comparison of entropy values in {read_mode} mode...")

    header_matches = {}
    footer_matches = {}

    # Dictionary to store header matches
    for header_malicious, footer_malicious in entropy_hashes_malicious.items():
        if header_malicious.startswith("Header_Entropy"):
            corresponding_footer = header_malicious.replace("Header", "Footer")
            if corresponding_footer in entropy_hashes_benign:
                for entropy_key, value_malicious in footer_malicious.items():
                    if entropy_key in entropy_hashes_benign[corresponding_footer]:
                        value_benign = entropy_hashes_benign[corresponding_footer][entropy_key]
                        header_matches[header_malicious] = entropy_key
                        footer_matches[corresponding_footer] = entropy_key
                        logging.info(
                            f"{header_malicious} - Entropy Value: {entropy_key} - Match"
                        )

    # Output header matches
    for header, entropy_value in header_matches.items():
        logging.info(
            f"{header} - Entropy Value: {entropy_value} - Match"
        )

    # Output footer matches
    logging.info("Starting comparison of entropy values in footer mode...")
    for footer, entropy_value in footer_matches.items():
        logging.info(
            f"{footer} - Entropy Value: {entropy_value} - Match"
        )


if __name__ == "__main__":
    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious and entropy_hashes_benign:
        compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign, READ_MODE)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
