import csv
import datetime
import logging

# Adjust based on the mode used for generating CSVs
READ_MODE = 'both'  # Can be 'header', 'footer', or 'both'
MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_signature_malicious_{READ_MODE}_1-400.csv"
BENIGN_INPUT_CSV = f"../DataExchange/datafile_signature_benign_{READ_MODE}_1-400.csv"

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_bytes_compare_{timestamp}.log'

logging.basicConfig(level=logging.DEBUG,  # Changed to DEBUG for verbosity
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])


def read_byte_sequences_with_hashes(csv_path):
    logging.debug(f"Attempting to open CSV file: {csv_path}")
    byte_sequences_hashes = {}
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            headers = next(csvreader)[1:]  # Assumes 'FileHash' is the first column
            byte_sequences_hashes = {header: {} for header in headers}
            for row in csvreader:
                file_hash = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:
                        if value not in byte_sequences_hashes[header]:
                            byte_sequences_hashes[header][value] = [file_hash]
                        else:
                            byte_sequences_hashes[header][value].append(file_hash)
        logging.debug(f"Successfully read and processed {csv_path}")
    except Exception as e:
        logging.error(f"Error reading or processing CSV file {csv_path}: {e}")
    return byte_sequences_hashes


def compare_byte_sequences_and_print_hashes(byte_sequences_hashes_malicious, byte_sequences_hashes_benign, read_mode):
    logging.info(f"Starting comparison of byte sequences in {read_mode} mode...")
    for header in byte_sequences_hashes_malicious:
        match_found = False
        for sequence, hashes_malicious in byte_sequences_hashes_malicious[header].items():
            if sequence in byte_sequences_hashes_benign.get(header, {}):
                match_found = True
                hashes_benign = byte_sequences_hashes_benign[header][sequence]
                logging.info(
                    f"{header} - Byte Sequence: {sequence} - Match ({len(hashes_malicious)} malicious, {len(hashes_benign)} benign matches)")
        if not match_found:
            logging.debug(f"No matches found for {header} in {read_mode} mode.")


if __name__ == "__main__":
    byte_sequences_hashes_malicious = read_byte_sequences_with_hashes(MALICIOUS_INPUT_CSV)
    byte_sequences_hashes_benign = read_byte_sequences_with_hashes(BENIGN_INPUT_CSV)

    if byte_sequences_hashes_malicious and byte_sequences_hashes_benign:
        compare_byte_sequences_and_print_hashes(byte_sequences_hashes_malicious, byte_sequences_hashes_benign,
                                                READ_MODE)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
