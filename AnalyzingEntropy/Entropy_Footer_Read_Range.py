import os
import csv
import math
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

START_BYTE = 1
END_BYTE = 3000
STEP = 1

MALICIOUS_FILE = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset1/benign"

MALICIOUS_OUTPUT_CSV = "../DataExchange/entropy_values_malicious_lastBytes_2000.csv"
BENIGN_OUTPUT_CSV = "../DataExchange/entropy_values_benign_lastBytes_2000.csv"

def shannon_entropy(data):
    """Calculate the Shannon entropy of a given dataset."""
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_hash_from_filepath(filepath):
    """Extract hash value from the file path."""
    # Assuming hash is the last part of the file path before extension
    filename = os.path.basename(filepath)
    hash_value = filename.split('.')[0]  # Extracting hash before the first dot
    return hash_value

def calculate_and_write_entropy(directory, csv_file_path, start_byte, end_byte, step):
    """Calculate Shannon entropy of files within a directory for given intervals and write to CSV."""
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = ['Hash'] + [f'Entropy{i}' for i in range(start_byte, end_byte + 1, step)]
        csvwriter.writerow(headers)

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                        file_length = len(data)
                        entropy_values = []
                        for current_start_byte in range(start_byte, end_byte + 1, step):
                            # Calculate the start index from the end of the file
                            segment_start_index = max(file_length - current_start_byte, 0)
                            # The segment now starts from segment_start_index to the end of the file
                            segment = data[segment_start_index:]
                            if segment:
                                entropy_value = shannon_entropy(segment)
                                entropy_values.append(entropy_value)
                            else:
                                entropy_values.append('')
                        hash_value = extract_hash_from_filepath(file_path)
                        csvwriter.writerow([hash_value] + entropy_values)
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")

# Example usage
calculate_and_write_entropy(MALICIOUS_FILE, MALICIOUS_OUTPUT_CSV, START_BYTE, END_BYTE, STEP)
calculate_and_write_entropy(BENIGN_FILE, BENIGN_OUTPUT_CSV, START_BYTE, END_BYTE, STEP)
