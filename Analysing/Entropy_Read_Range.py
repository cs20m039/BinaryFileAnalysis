import csv
import datetime
import logging
import os
import math
from collections import Counter

# Constants
INTERVAL_START = 1
INTERVAL_END = 600
READ_MODE = 'both'
MALICIOUS_DIRECTORY = "/home/cs20m039/thesis/dataset3/malicious"
BENIGN_DIRECTORY = "/home/cs20m039/thesis/dataset3/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_entropy_ds3_"
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_signature_read_both_1-600_DS3_{timestamp}.txt'

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename=LOG_FILE_PATH, filemode='w')


def entropy(data):
    """Calculate the entropy of a given data set."""
    if not data:
        return 0
    data_length = len(data)
    frequencies = Counter(data)
    probabilities = [freq / data_length for freq in frequencies.values()]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def read_file_bytes(file_path, read_mode, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    """Reads bytes from the beginning and end of a file based on the read mode and calculates entropy for each segment."""
    try:
        file_size = os.path.getsize(file_path)
        min_required_size = interval_end if read_mode in ['header', 'footer'] else 2 * interval_end

        if file_size < min_required_size:
            logging.warning(f"File {file_path} is too small for the selected read mode ({read_mode}). Required minimum size: {min_required_size}, File size: {file_size}")
            return {}

        with open(file_path, 'rb') as file:
            data = {}

            if read_mode in ['header', 'both']:
                file.seek(0)
                header_bytes = file.read(interval_end)
                for i in range(interval_start, interval_end + 1):
                    segment = header_bytes[:i]
                    data[f'Header{i}'] = entropy(segment)

            if read_mode in ['footer', 'both']:
                file.seek(max(file_size - interval_end, 0))
                footer_bytes = file.read(interval_end)
                for i in range(interval_start, interval_end + 1):
                    segment = footer_bytes[-i:]
                    data[f'Footer{i}'] = entropy(segment)

            return data
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}


def analyze_files(directory_path, output_file_name, read_mode):
    headers = ['FileName'] + \
              [f'Header{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)] + \
              [f'Footer{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)] if read_mode == 'both' else \
              [f'Byte{i}' for i in range(INTERVAL_START, INTERVAL_END + 1)]

    with open(output_file_name, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()

        for root, _, files in os.walk(directory_path):
            logging.info(f"Processing {len(files)} files in {root}")
            for file in files:
                full_path = os.path.join(root, file)
                bytes_data = read_file_bytes(full_path, read_mode)
                if bytes_data:
                    bytes_data['FileName'] = os.path.splitext(file)[0]
                    writer.writerow(bytes_data)


def main():
    output_malicious = f"{OUTPUT_CSV_PREFIX}malicious_{READ_MODE}_{INTERVAL_START}-{INTERVAL_END}.csv"
    output_benign = f"{OUTPUT_CSV_PREFIX}benign_{READ_MODE}_{INTERVAL_START}-{INTERVAL_END}.csv"

    analyze_files(MALICIOUS_DIRECTORY, output_malicious, READ_MODE)
    analyze_files(BENIGN_DIRECTORY, output_benign, READ_MODE)


if __name__ == "__main__":
    main()
