import csv
import logging
import math
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

START_BYTE = 4
END_BYTE = 500
READ_MODE = 'both'  # Can be 'header', 'footer', or 'both'

MALICIOUS_FILE = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset1/benign"
OUTPUT_CSV_PREFIX = "../DataExchange/datafile_entropy_"

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
    if read_mode == 'both':
        output_csv_path = f"{output_csv_prefix}{file_type}_{read_mode}_header_footer_{start_byte}-{end_byte}.csv"
    else:
        output_csv_path = f"{output_csv_prefix}{file_type}_{read_mode}_{start_byte}-{end_byte}.csv"

    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        if read_mode == 'both':
            headers = ['Hash'] + [f'Header_Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)] + [
                f'Footer_Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)]
        else:
            headers = ['Hash'] + [f'Entropy_{start_byte}-{i}' for i in range(start_byte, end_byte + 1)]

        csvwriter.writerow(headers)

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        file_size = os.path.getsize(file_path)
                        data = f.read()
                        header_data = data[:end_byte]
                        footer_data = data[-end_byte:] if read_mode in ['footer', 'both'] else b''
                        entropy_values = []

                        # Calculate entropy for the header or for 'both' mode's header part
                        if read_mode in ['header', 'both']:
                            for current_end_byte in range(start_byte, end_byte + 1):
                                segment = header_data[start_byte - 1:current_end_byte]
                                entropy_value = shannon_entropy(segment) if segment else ''
                                entropy_values.append(entropy_value)

                        # Calculate entropy for the footer, if applicable
                        if read_mode in ['footer', 'both']:
                            for current_end_byte in range(start_byte, end_byte + 1):
                                segment = footer_data[-current_end_byte:]
                                entropy_value = shannon_entropy(segment) if segment else ''
                                entropy_values.append(entropy_value)

                        hash_value = extract_hash_from_filepath(file_path)
                        csvwriter.writerow([hash_value] + entropy_values)
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")


# Example usage for different modes
calculate_and_write_entropy(MALICIOUS_FILE, OUTPUT_CSV_PREFIX, START_BYTE, END_BYTE, READ_MODE, 'malicious')
calculate_and_write_entropy(BENIGN_FILE, OUTPUT_CSV_PREFIX, START_BYTE, END_BYTE, READ_MODE, 'benign')

