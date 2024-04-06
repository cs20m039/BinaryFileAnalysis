import csv
import os
import logging
import datetime

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_FILE_PATH = f'../Logfiles/log_signature_read_footer-benignFiles_{timestamp}.txt'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')

INTERVAL_START = 6300
INTERVAL_END = 6500

READ_LENGTH = INTERVAL_END
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/benign'
CSV_PATH = f'../DataExchange/datafile_signature_footer_benign_{INTERVAL_START}-{INTERVAL_END}.csv'

def read_bytes_of_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file.seek(max(os.path.getsize(file_path) - READ_LENGTH, 0))
            bytes_read = file.read(READ_LENGTH)
            return {f'{length}Byte': bytes_read[-length:].hex() for length in range(INTERVAL_START, min(len(bytes_read), INTERVAL_END) + 1)}
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}

def analyze_files_recursive(directory_path, csv_path):
    file_count = 0
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['FileHash'] + [f'{i}Byte' for i in range(INTERVAL_START, INTERVAL_END + 1)])

        for dirpath, _, filenames in os.walk(directory_path):
            logging.info(f"Processing {len(filenames)} files in {dirpath}") if filenames else logging.debug(f"No files found in {dirpath}")
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                bytes_data = read_bytes_of_file(full_path)
                if bytes_data:
                    writer.writerow([os.path.splitext(filename)[0]] + [bytes_data.get(f'{i}Byte', '') for i in range(INTERVAL_START, INTERVAL_END + 1)])
                    file_count += 1

    logging.info(f"Total files analyzed: {file_count}")

analyze_files_recursive(DIRECTORY_PATH, CSV_PATH)
