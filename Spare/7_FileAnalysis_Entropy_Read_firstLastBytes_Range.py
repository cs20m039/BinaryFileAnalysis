import os
import csv
import math
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

START_BYTE  =   1
END_BYTE    =   1000
STEP        =   1

MALICIOUS_FILE = "/home/cs20m039/thesis/dataset/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset/benign"

MALICIOUS_OUTPUT_CSV = "output/entropy_values_malicious_FirstLastBytes.csv"
BENIGN_OUTPUT_CSV = "output/entropy_values_benign_FirstLastBytes.csv"

def shannon_entropy(data):
    """Calculate the Shannon entropy of a given dataset."""
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_and_write_entropy(directory, csv_file_path, start_byte, end_byte, step):
    """Calculate Shannon entropy of files within a directory for given intervals and write to CSV."""
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Adjust headers to indicate header and footer entropy values
        headers = ['FilePath'] + [f'HeaderEntropy{i}' for i in range(start_byte, end_byte + 1, step)] + [f'FooterEntropy{i}' for i in range(start_byte, end_byte + 1, step)]
        csvwriter.writerow(headers)

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                        header_entropy_values = []
                        footer_entropy_values = []
                        for i in range(start_byte, end_byte + 1, step):
                            # Header segment
                            header_segment = data[:i]
                            if header_segment:
                                header_entropy_value = shannon_entropy(header_segment)
                                header_entropy_values.append(header_entropy_value)
                            else:
                                header_entropy_values.append('')

                            # Footer segment
                            if len(data) >= i:  # Ensure there's enough data for footer
                                footer_segment = data[-i:]
                                footer_entropy_value = shannon_entropy(footer_segment)
                                footer_entropy_values.append(footer_entropy_value)
                            else:
                                footer_entropy_values.append('')

                        # Combine header and footer entropy values for the current file
                        csvwriter.writerow([file_path] + header_entropy_values + footer_entropy_values)
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")



# Example usage
calculate_and_write_entropy(MALICIOUS_FILE, MALICIOUS_OUTPUT_CSV,START_BYTE ,END_BYTE ,STEP)
calculate_and_write_entropy(BENIGN_FILE, BENIGN_OUTPUT_CSV,START_BYTE ,END_BYTE ,STEP)