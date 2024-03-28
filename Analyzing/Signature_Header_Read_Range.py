# Read the defined interval of binary patterns for header signatures of malicious
# Writes to content to a file


import csv
import datetime
import logging
import os

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define the log file path with the timestamp included in the filename
LOG_FILE_PATH = f'../Logfiles/log-readHeader-maliciousFiles_{timestamp}.txt'

# Setup basic configuration for logging to write to a file
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')  # Use 'w' to overwrite the log file each time or

INTERVAL_START = 4
INTERVAL_END = 150
READ_LENGTH = INTERVAL_END  # Assuming you want to read up to the INTERVAL_END byte
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'
CSV_PATH = '../DataExchange/data_headerSignature_maliciousFiles_4-150_Bytes.csv'


def read_bytes_of_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            bytes_data = {}
            bytes_read = file.read(READ_LENGTH)

            for length in range(INTERVAL_START, INTERVAL_END + 1):  # +1 to include INTERVAL_END
                if len(bytes_read) >= length:
                    bytes_data[f'{length}Byte'] = bytes_read[:length].hex()
                else:
                    bytes_data[f'{length}Byte'] = bytes_read.hex()
                    break

            return bytes_data
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return {}


def analyze_files_recursive(directory_path, csv_path):
    file_count = 0  # Initialize the file counter
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        headers = ['FilePath'] + [f'{i}Byte' for i in range(INTERVAL_START, INTERVAL_END + 1)]
        writer.writerow(headers)

        for dirpath, dirnames, filenames in os.walk(directory_path):
            if filenames:  # Check if the directory has files
                logging.info(f"Processing {len(filenames)} files in {dirpath}")  # Log only if there are files
                for filename in filenames:
                    full_path = os.path.join(dirpath, filename)
                    bytes_data = read_bytes_of_file(full_path)
                    if bytes_data:
                        relative_path = os.path.relpath(full_path, directory_path)
                        row = [relative_path] + [bytes_data.get(f'{i}Byte', '') for i in
                                                 range(INTERVAL_START, INTERVAL_END + 1)]
                        writer.writerow(row)
                        file_count += 1
            else:
                logging.debug(f"No files found in {dirpath}")
                pass  # Currently does nothing for empty directories

    logging.info(f"Total files analyzed: {file_count}")


analyze_files_recursive(DIRECTORY_PATH, CSV_PATH)
