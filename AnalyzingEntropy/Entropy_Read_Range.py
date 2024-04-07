import csv
import logging
import math
import os
from datetime import datetime

START_BYTE = 1
END_BYTE = 500
READ_MODE = ('header')  # Can be 'header', 'footer', or 'both'
MALICIOUS_FILE = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset1/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_entropy_"

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_entropy_read_{timestamp}.log'
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])


def shannon_entropy(data):
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def extract_hash_from_filepath(filepath):
    filename = os.path.basename(filepath)
    hash_value = filename.split('.')[0]
    return hash_value


def calculate_and_write_entropy(directory, output_csv_prefix, start_byte, end_byte, read_mode, file_type):
    total_files_attempted = 0
    total_files_read = 0
    files_skipped_due_to_length = 0
    if read_mode == 'both':
        output_csv_path = f"{output_csv_prefix}{file_type}_{read_mode}_{start_byte}-{end_byte}.csv"
    else:
        output_csv_path = f"{output_csv_prefix}{file_type}_{read_mode}_{start_byte}-{end_byte}.csv"

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = ['Hash'] + [f'{read_mode.capitalize()}_Entropy_{start_byte}-{i}' for i in
                              range(start_byte, end_byte + 1)] if read_mode != 'both' else \
            ['Hash'] + [f'Header_Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)] + \
            [f'Footer_Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)]
        csvwriter.writerow(headers)

        for root, _, files in os.walk(directory):
            for file in files:
                total_files_attempted += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        file_size = os.path.getsize(file_path)
                        if (read_mode in ['header', 'footer'] and file_size < end_byte) or \
                                (read_mode == 'both' and file_size < 2 * end_byte):
                            logging.info(f"Skipping {file_path} due to insufficient length for '{read_mode}' mode.")
                            files_skipped_due_to_length += 1
                            continue
                        data = f.read()
                        header_data = data[:end_byte]
                        footer_data = data[-end_byte:] if read_mode in ['footer', 'both'] else b''
                        entropy_values = []
                        if read_mode in ['header', 'both']:
                            for current_end_byte in range(start_byte, end_byte + 1):
                                segment = header_data[start_byte - 1:current_end_byte]
                                entropy_value = shannon_entropy(segment) if segment else ''
                                entropy_values.append(entropy_value)
                        if read_mode in ['footer', 'both']:
                            for current_end_byte in range(start_byte, end_byte + 1):
                                segment = footer_data[-current_end_byte:]
                                entropy_value = shannon_entropy(segment) if segment else ''
                                entropy_values.append(entropy_value)
                        hash_value = extract_hash_from_filepath(file_path)
                        csvwriter.writerow([hash_value] + entropy_values)
                        total_files_read += 1
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")
    return total_files_attempted, total_files_read, files_skipped_due_to_length


if __name__ == "__main__":
    malicious_stats = calculate_and_write_entropy(MALICIOUS_FILE, OUTPUT_CSV_PREFIX, START_BYTE, END_BYTE, READ_MODE,
                                                  'malicious')
    logging.info(
        f"Malicious files - Total attempted: {malicious_stats[0]}, Total read: {malicious_stats[1]}, Skipped due to length: {malicious_stats[2]}")
    benign_stats = calculate_and_write_entropy(BENIGN_FILE, OUTPUT_CSV_PREFIX, START_BYTE, END_BYTE, READ_MODE,
                                               'benign')
    logging.info(
        f"Benign files - Total attempted: {benign_stats[0]}, Total read: {benign_stats[1]}, Skipped due to length: {benign_stats[2]}")
