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


def compare_entropy_values_and_output_files(entropy_hashes_malicious, entropy_hashes_benign, read_mode):
    unique_malicious_file_path = f'unique_malicious_{timestamp}.txt'
    unique_benign_file_path = f'unique_benign_{timestamp}.txt'

    with open(unique_malicious_file_path, 'w', encoding='utf-8') as umf, open(unique_benign_file_path, 'w', encoding='utf-8') as ubf:
        for header in entropy_hashes_malicious:
            for value_malicious, hashes_malicious in entropy_hashes_malicious[header].items():
                if value_malicious not in entropy_hashes_benign.get(header, {}):
                    umf.write(f"{header} - {value_malicious}: {', '.join(hashes_malicious)}\n")

        for header in entropy_hashes_benign:
            for value_benign, hashes_benign in entropy_hashes_benign[header].items():
                if value_benign not in entropy_hashes_malicious.get(header, {}):
                    ubf.write(f"{header} - {value_benign}: {', '.join(hashes_benign)}\n")


if __name__ == "__main__":
    READ_MODE = 'header'  # Adjust based on the mode used for generating CSVs
    MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_entropy_malicious_{READ_MODE}_1-1000.csv"
    BENIGN_INPUT_CSV = f"../DataExchange/datafile_entropy_benign_{READ_MODE}_1-1000.csv"
    entropy_hashes_malicious = read_entropy_values_with_hashes(MALICIOUS_INPUT_CSV)
    entropy_hashes_benign = read_entropy_values_with_hashes(BENIGN_INPUT_CSV)

    if entropy_hashes_malicious and entropy_hashes_benign:
        compare_entropy_values_and_output_files(entropy_hashes_malicious, entropy_hashes_benign, READ_MODE)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
