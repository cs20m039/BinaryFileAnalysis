import csv
import datetime
import logging
import os

# Setup basic logging and timestamp
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_signature_{timestamp}.txt'
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')

# Configuration
INTERVAL_START = 1
INTERVAL_END = 400  # Adjusted according to the setup configuration
READ_MODE = 'header'  # Options: 'header', 'footer', 'both'
READ_LENGTH = INTERVAL_END  # Adjusted according to the setup configuration
MALICIOUS_DIRECTORY = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_DIRECTORY = "/home/cs20m039/thesis/dataset1/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_signature_"


def read_bytes_of_file(file_path, read_mode='both', interval_start=1, interval_end=200, read_length=200):
    try:
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)
            bytes_data = {}

            if read_mode == 'header':
                bytes_read = file.read(read_length)
                bytes_data.update({f'{length}Byte': bytes_read[:length].hex() for length in
                                   range(interval_start, min(len(bytes_read) + 1, interval_end + 1))})
            elif read_mode == 'footer':
                file.seek(max(file_size - read_length, 0))
                bytes_read = file.read(read_length)
                bytes_data.update({f'{length}Byte': bytes_read[-length:].hex() for length in
                                   range(interval_start, min(len(bytes_read), interval_end) + 1)})
            elif read_mode == 'both':
                bytes_read_header = file.read(interval_end)
                file.seek(max(file_size - interval_end, 0))
                bytes_read_footer = file.read(interval_end)
                bytes_data.update({f'{length}ByteHeader': bytes_read_header[:length].hex() for length in
                                   range(interval_start, min(len(bytes_read_header) + 1, interval_end + 1))})
                bytes_data.update({f'{length}ByteFooter': bytes_read_footer[-length:].hex() for length in
                                   range(interval_start, min(len(bytes_read_footer), interval_end) + 1)})

            return bytes_data
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}


def analyze_files_recursive(directory_path, output_prefix, file_type, read_mode='both', interval_start=1, interval_end=200):
    csv_path = f"{output_prefix}{file_type}_{read_mode}_{interval_start}-{interval_end}.csv"
    file_count = 0
    headers = ['FileHash'] + [f'{i}ByteHeader' for i in range(interval_start, interval_end + 1)] + \
              [f'{i}ByteFooter' for i in range(interval_start, interval_end + 1)] if read_mode == 'both' else \
              ['FileHash'] + [f'{i}Byte' for i in range(interval_start, interval_end + 1)]

    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()
        for dirpath, _, filenames in os.walk(directory_path):
            logging.info(f"Processing {len(filenames)} files in {dirpath}") if filenames else logging.debug(
                f"No files found in {dirpath}")
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                bytes_data = read_bytes_of_file(full_path, read_mode, interval_start, interval_end, READ_LENGTH)
                if bytes_data:
                    bytes_data['FileHash'] = os.path.splitext(filename)[0]
                    writer.writerow(bytes_data)
                    file_count += 1

    logging.info(f"Total files analyzed in {file_type} directory: {file_count}")

if __name__ == "__main__":
    analyze_files_recursive(MALICIOUS_DIRECTORY, OUTPUT_CSV_PREFIX, 'malicious', READ_MODE, INTERVAL_START, INTERVAL_END)
    analyze_files_recursive(BENIGN_DIRECTORY, OUTPUT_CSV_PREFIX, 'benign', READ_MODE, INTERVAL_START, INTERVAL_END)
