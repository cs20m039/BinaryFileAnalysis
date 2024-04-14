import csv
import logging
import math
import os
import datetime

# Constants
START_BYTE = 1
END_BYTE = 600
READ_MODE = 'both'  # Can be 'header', 'footer', or 'both'
MALICIOUS_FILE_PATH = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_FILE_PATH = "/home/cs20m039/thesis/dataset1/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_entropy_"
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_entropy_read_{TIMESTAMP}.log'

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])

def shannon_entropy(data):
    """Calculates the Shannon entropy of a given data segment."""
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy

def calculate_entropy_values(data_segment, start_byte, end_byte):
    """Calculates entropy values for given data segment within byte range."""
    entropy_values = []
    for current_end_byte in range(start_byte, end_byte + 1):
        segment = data_segment[start_byte - 1:current_end_byte]
        entropy_value = shannon_entropy(segment) if segment else ''
        entropy_values.append(entropy_value)
    return entropy_values

def process_files(directory, output_csv_path, read_mode, start_byte, end_byte):
    """Processes files in a directory to calculate and write their entropy values."""
    total_files_attempted, total_files_read, files_skipped_due_to_length = 0, 0, 0

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = ['FileName'] + [f'{read_mode.capitalize()}_Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)] if read_mode != 'both' else ['FileName'] + [f'Header{i}' for i in range(start_byte, end_byte + 1)] + [f'Footer{i}' for i in range(start_byte, end_byte + 1)]
        csvwriter.writerow(headers)

        for root, _, files in os.walk(directory):
            for file in files:
                total_files_attempted += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        file_size = os.path.getsize(file_path)
                        if (read_mode in ['header', 'footer'] and file_size < end_byte) or (read_mode == 'both' and file_size < 2 * end_byte):
                            logging.info(f"Skipping {file_path} due to insufficient length for '{read_mode}' mode.")
                            files_skipped_due_to_length += 1
                            continue

                        data = f.read()
                        header_data, footer_data = data[:end_byte], data[-end_byte:] if read_mode in ['footer', 'both'] else b''
                        logging.debug(f"{data}")
                        entropy_values = calculate_entropy_values(header_data, start_byte, end_byte) if read_mode in ['header', 'both'] else []
                        if read_mode in ['footer', 'both']:
                            entropy_values += calculate_entropy_values(footer_data, start_byte, end_byte)
                        hash_value = os.path.basename(file_path).split('.')[0]
                        csvwriter.writerow([hash_value] + entropy_values)
                        total_files_read += 1
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")

    return total_files_attempted, total_files_read, files_skipped_due_to_length

if __name__ == "__main__":
    # Process malicious files
    malicious_output_csv = f"{OUTPUT_CSV_PREFIX}malicious_{READ_MODE}_{START_BYTE}-{END_BYTE}.csv"
    malicious_stats = process_files(MALICIOUS_FILE_PATH, malicious_output_csv, READ_MODE, START_BYTE, END_BYTE)
    logging.info(f"Malicious files - Total attempted: {malicious_stats[0]}, Total read: {malicious_stats[1]}, Skipped due to length: {malicious_stats[2]}")

    # Process benign files
    benign_output_csv = f"{OUTPUT_CSV_PREFIX}benign_{READ_MODE}_{START_BYTE}-{END_BYTE}.csv"
    benign_stats = process_files(BENIGN_FILE_PATH, benign_output_csv, READ_MODE, START_BYTE, END_BYTE)
    logging.info(f"Benign files - Total attempted: {benign_stats[0]}, Total read: {benign_stats[1]}, Skipped due to length: {benign_stats[2]}")
