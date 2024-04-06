# This script reads all files of a directory with subdirectories
# and writes the combination of header and footer to a csv-file

import csv
import os
import logging
import datetime

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_FILE_PATH = f'../Logfiles/log-read-headerFooter_{timestamp}.txt'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')

INTERVAL_START = 4
INTERVAL_END = 300
READ_LENGTH = INTERVAL_END
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'
CSV_PATH = f'../DataExchange/datafile_signature_header_and_footer_malicious_{INTERVAL_START}-{INTERVAL_END}.csv'

def read_bytes_of_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_size = os.path.getsize(file_path)
            bytes_data = {}
            bytes_read = file.read(READ_LENGTH)
            file.seek(max(0, file_size - READ_LENGTH))
            last_bytes_read = file.read(READ_LENGTH)
            for length in range(INTERVAL_START, INTERVAL_END + 1):
                first_bytes = bytes_read[:length].hex() if len(bytes_read) >= length else bytes_read.hex()
                last_bytes = last_bytes_read[-length:].hex() if len(last_bytes_read) >= length else last_bytes_read.hex()
                bytes_data[f'{length}ByteFirst'] = first_bytes
                bytes_data[f'{length}ByteLast'] = last_bytes
            return bytes_data
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}

def analyze_files_recursive(directory_path, csv_path):
    file_count = 0
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        headers = ['FileHash'] + [f'{i}ByteFirst' for i in range(INTERVAL_START, INTERVAL_END + 1)] + [f'{i}ByteLast' for i in range(INTERVAL_START, INTERVAL_END + 1)]
        writer.writerow(headers)

        for dirpath, dirnames, filenames in os.walk(directory_path):
            if filenames:
                logging.info(f"Processing {len(filenames)} files in {dirpath}")
                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)
                    bytes_data = read_bytes_of_file(full_path)
                    if bytes_data:
                        hash_value = filename.split('.')[0]
                        row = [hash_value] + [bytes_data.get(f'{i}ByteFirst', '') for i in range(INTERVAL_START, INTERVAL_END + 1)] + [bytes_data.get(f'{i}ByteLast', '') for i in range(INTERVAL_START, INTERVAL_END + 1)]
                        writer.writerow(row)
                        file_count += 1
            else:
                logging.debug(f"No files found in {dirpath}")
    logging.info(f"Total files analyzed: {file_count}")

analyze_files_recursive(DIRECTORY_PATH, CSV_PATH)
