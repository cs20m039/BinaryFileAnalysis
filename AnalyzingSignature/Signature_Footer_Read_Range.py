import csv
import os
import logging
import datetime

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define the log file path with the timestamp included in the filename
LOG_FILE_PATH = f'../Logfiles/log-read_footer-maliciousFiles_{timestamp}.txt'

# Setup basic configuration for logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')  # 'w' to overwrite the log file each time

INTERVAL_START = 9060
INTERVAL_END = 9260
READ_LENGTH = INTERVAL_END  # Assuming reading up to INTERVAL_END byte
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'
CSV_PATH = f'../DataExchange/datafile_signature_footer_malicious_{INTERVAL_START}-{INTERVAL_END}.csv'

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
        writer.writerow(['FileHash'] + [f'{i}Byte' for i in range(INTERVAL_START, INTERVAL_END + 1)]) #SHA256 FileHash

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
