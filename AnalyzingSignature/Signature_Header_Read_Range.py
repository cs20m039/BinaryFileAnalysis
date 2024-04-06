import csv
import datetime
import logging
import os

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

INTERVAL_START = 500
INTERVAL_END = 500

LOG_FILE_PATH = f'../Logfiles/log_signature_header_benign_{INTERVAL_START}-{INTERVAL_END}_{timestamp}.txt'
READ_LENGTH = INTERVAL_END
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/benign'
CSV_PATH = f'../DataExchange/datafile_signature_header_benign_{INTERVAL_START}-{INTERVAL_END}.csv'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')


def read_bytes_of_file(file_path, read_length=READ_LENGTH, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    try:
        with open(file_path, 'rb') as file:
            bytes_data = {'FileHash': os.path.splitext(os.path.basename(file_path))[0]}
            bytes_read = file.read(read_length)
            bytes_data.update({f'{length}Byte': bytes_read[:length].hex() for length in
                               range(interval_start, min(len(bytes_read) + 1, interval_end + 1))})
            return bytes_data
    except Exception as e:
        logging.error(f"Error processing file '{file_path}': {e}")
        return {}


def analyze_files_recursive(directory_path, csv_path, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    file_count = 0
    headers = ['FileHash'] + [f'{i}Byte' for i in range(interval_start, interval_end + 1)]
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()
        for dirpath, _, filenames in os.walk(directory_path):
            if filenames:
                logging.info(f"Processing {len(filenames)} files in {dirpath}")
                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)
                    try:
                        bytes_data = read_bytes_of_file(full_path)
                        if bytes_data:
                            writer.writerow(bytes_data)
                            file_count += 1
                    except Exception as e:
                        logging.error(f"Error processing file '{full_path}': {e}")
    logging.info(f"Total files analyzed: {file_count}")


analyze_files_recursive(DIRECTORY_PATH, CSV_PATH)
