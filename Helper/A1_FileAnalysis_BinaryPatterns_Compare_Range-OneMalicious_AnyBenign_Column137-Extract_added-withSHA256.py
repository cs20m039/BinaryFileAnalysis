import os
import csv
import math
import hashlib
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ENTROPY_BYTE_COUNT = 137

MALICIOUS_FILE = "/home/cs20m039/thesis/dataset/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset/benign"

MALICIOUS_OUTPUT_CSV = "datashare/entropy_values_malicious_firstBytes.csv"
BENIGN_OUTPUT_CSV = "datashare/entropy_values_benign_firstBytes.csv"

def shannon_entropy(data):
    """Calculate the Shannon entropy of a given dataset."""
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_and_write_entropy(directory, csv_file_path):
    """Calculate Shannon entropy of files within a directory for the first 137 bytes and write to CSV."""
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['SHA256', 'Entropy'])

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                        entropy_value = shannon_entropy(data[:ENTROPY_BYTE_COUNT])
                        sha256_hash = hashlib.sha256(data).hexdigest()
                        csvwriter.writerow([sha256_hash, entropy_value])
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")


# Example usage
calculate_and_write_entropy(MALICIOUS_FILE, MALICIOUS_OUTPUT_CSV)
calculate_and_write_entropy(BENIGN_FILE, BENIGN_OUTPUT_CSV)
