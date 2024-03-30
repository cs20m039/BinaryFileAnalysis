import csv
import datetime
import logging
import os

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

INTERVAL_START = 4
INTERVAL_END = 400

# Define the log file path with the timestamp included in the filename
LOG_FILE_PATH = f'../Logfiles/log_signature_header_malicious_{INTERVAL_START}-{INTERVAL_END}_{timestamp}.txt'
READ_LENGTH = INTERVAL_END  # Assuming you want to read up to the INTERVAL_END byte
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'
CSV_PATH = f'../DataExchange/datafile_signature_header_malicious_{INTERVAL_START}-{INTERVAL_END}.csv'


# Setup basic configuration for logging to write to a file
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')  # Use 'w' to overwrite the log file each time


def read_bytes_of_file(file_path, read_length=READ_LENGTH, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    """Reads the specified number of bytes from a file and returns a dictionary of byte lengths."""
    try:
        with open(file_path, 'rb') as file:
            bytes_data = {'FileHash': os.path.splitext(os.path.basename(file_path))[0]}  # Hash included in output
            bytes_read = file.read(read_length)
            bytes_data.update({f'{length}Byte': bytes_read[:length].hex() for length in range(interval_start, min(len(bytes_read)+1, interval_end + 1))})
            return bytes_data
    except Exception as e:
        logging.error(f"Error processing file '{file_path}': {e}")
        return {}


def analyze_files_recursive(directory_path, csv_path, interval_start=INTERVAL_START, interval_end=INTERVAL_END):
    """Walks through a directory recursively, reads file bytes, and writes them into a CSV."""
    file_count = 0
    headers = ['FileHash'] + [f'{i}Byte' for i in range(interval_start, interval_end + 1)]  # SHA256 FileHash

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
