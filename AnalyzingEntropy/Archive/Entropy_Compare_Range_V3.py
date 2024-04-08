import csv
import datetime
import logging

READ_MODE = 'both'  # Adjust based on the mode used for generating CSVs
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
            entropy_hashes = {header: [] for header in headers}  # Use a list to maintain row order
            for row_index, row in enumerate(csvreader):
                hash_value = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:
                        entropy_hashes[header].append((float(value), hash_value, row_index))
    except Exception as e:
        logging.error(f"Error reading CSV file {csv_path}: {e}")
    return entropy_hashes



def compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign, read_mode):
    logging.info(f"Starting comparison of entropy values in {read_mode} mode...")
    if read_mode == 'both':
        for header in entropy_hashes_malicious:
            if 'Header' in header:
                corresponding_footer = header.replace('Header', 'Footer')
                for value_malicious, hash_malicious, row_index_malicious in entropy_hashes_malicious[header]:
                    # Find matching benign header value and row index
                    matching_benign_values = [(value_benign, hash_benign) for value_benign, hash_benign, row_index_benign in entropy_hashes_benign.get(header, []) if row_index_malicious == row_index_benign]
                    for value_benign, hash_benign in matching_benign_values:
                        # Now find the corresponding footer value for the same row in benign data
                        footer_values_benign = [(v, h) for v, h, r in entropy_hashes_benign.get(corresponding_footer, []) if r == row_index_malicious]
                        for value_footer_benign, hash_footer_benign in footer_values_benign:
                            logging.info(f"Match found - {header}: {value_malicious} with {corresponding_footer} real value {value_footer_benign} (Malicious hash: {hash_malicious}, Benign header hash: {hash_benign}, Benign footer hash: {hash_footer_benign})")


if __name__ == "__main__":
    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious and entropy_hashes_benign:
        compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign, READ_MODE)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
