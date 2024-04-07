import csv
import datetime
import logging

READ_MODE = 'both'  # Adjust based on the mode used for generating CSVs
MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_entropy_malicious_{READ_MODE}_1-500.csv"
BENIGN_INPUT_CSV = f"../DataExchange/datafile_entropy_benign_{READ_MODE}_1-500.csv"

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

    if read_mode == 'both':
        for header in entropy_hashes_malicious:
            if 'Header' in header:
                corresponding_footer = header.replace('Header', 'Footer')
                for value_malicious, hashes_malicious in entropy_hashes_malicious[header].items():
                    if value_malicious in entropy_hashes_benign[
                        header] and value_malicious in entropy_hashes_benign.get(corresponding_footer, {}):
                        hashes_benign_header = entropy_hashes_benign[header][value_malicious]
                        hashes_benign_footer = entropy_hashes_benign[corresponding_footer][value_malicious]
                        logging.info(
                            f"Match found - {header}: {value_malicious} ({len(hashes_malicious)} malicious, {len(hashes_benign_header)} benign matches), "
                            f"{corresponding_footer}: {value_malicious} ({len(hashes_malicious)} malicious, {len(hashes_benign_footer)} benign matches)")
    else:
        for header in entropy_hashes_malicious:
            if (read_mode.capitalize() in header) or (read_mode == 'header' and 'Header' in header) or (
                    read_mode == 'footer' and 'Footer' in header):
                for value_malicious, hashes_malicious in entropy_hashes_malicious[header].items():
                    if value_malicious in entropy_hashes_benign[header]:
                        logging.info(f"{header} - Entropy Value: {value_malicious} - Match")


if __name__ == "__main__":
    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious and entropy_hashes_benign:
        compare_entropy_values_and_print_hashes(entropy_hashes_malicious, entropy_hashes_benign, READ_MODE)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
