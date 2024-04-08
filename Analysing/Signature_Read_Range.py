import csv
import datetime
import logging
import os

# Constants
INTERVAL_START = 1
INTERVAL_END = 10
READ_MODE = 'both'  # Can be 'header', 'footer', or 'both'
MALICIOUS_DIRECTORY = "/home/cs20m039/thesis/dataset0/malicious"
BENIGN_DIRECTORY = "/home/cs20m039/thesis/dataset0/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_signature_"
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_signature_{timestamp}.txt'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename=LOG_FILE_PATH,
                    filemode='w')


def setup_logger():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        filename=LOG_FILE_PATH,
                        filemode='w')


def read_file_bytes(file_path, read_mode, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    """Reads bytes from the beginning and end of a file based on the read mode."""
    try:
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)
            data = {}

            if read_mode in ['header', 'both']:
                file.seek(0)
                header_bytes = file.read(interval_end)
                data.update({f'Header{i}': header_bytes[:i].hex() for i in range(interval_start, interval_end + 1)})

            if read_mode in ['footer', 'both']:
                file.seek(max(file_size - interval_end, 0))
                footer_bytes = file.read(interval_end)
                data.update({f'Footer{i}': footer_bytes[-i:].hex() for i in range(interval_start, interval_end + 1)})

            return data
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}


def analyze_files(directory_path, output_file_name, read_mode):
    """Analyzes files in a directory and writes the byte signatures to a CSV file."""
    file_count = 0
    headers = ['FileName'] + \
              [f'Header{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)] + \
              [f'Footer{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)] if read_mode == 'both' else \
        [f'Byte{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)]

    with open(output_file_name, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()

        for root, _, files in os.walk(directory_path):
            if files:
                logging.info(f"Processing {len(files)} files in {root}")
                for file in files:
                    full_path = os.path.join(root, file)
                    bytes_data = read_file_bytes(full_path, read_mode)
                    if bytes_data:
                        bytes_data['FileName'] = os.path.splitext(file)[0]
                        writer.writerow(bytes_data)
                        file_count += 1

    logging.info(f"Total files analyzed in {directory_path}: {file_count}")


def main():
    setup_logger()
    output_malicious = f"{OUTPUT_CSV_PREFIX}malicious_{READ_MODE}_{INTERVAL_START}-{INTERVAL_END}.csv"
    output_benign = f"{OUTPUT_CSV_PREFIX}benign_{READ_MODE}_{INTERVAL_START}-{INTERVAL_END}.csv"

    analyze_files(MALICIOUS_DIRECTORY, output_malicious, READ_MODE)
    analyze_files(BENIGN_DIRECTORY, output_benign, READ_MODE)


if __name__ == "__main__":
    main()
