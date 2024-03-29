import csv
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

'''MALICIOUS_INPUT_CSV = "output/entropy_values_malicious.csv"
BENIGN_INPUT_CSV = "output/entropy_values_benign.csv"'''

MALICIOUS_INPUT_CSV = "datashare/entropy_values_malicious_firstBytes.csv"
BENIGN_INPUT_CSV = "datashare/entropy_values_benign_firstBytes.csv"

def read_entropy_values_with_files(csv_path):
    """Read entropy values and corresponding file paths from a CSV file."""
    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)
        headers = next(csvreader)[1:]  # Skip 'File Path' and get entropy headers
        entropy_files = {header: {} for header in headers}  # Maps entropy values to file paths
        for row in csvreader:
            file_path = row[0]
            for header, value in zip(headers, row[1:]):
                if value:  # Ensure the value is not empty
                    value = float(value)
                    if value not in entropy_files[header]:
                        entropy_files[header][value] = [file_path]
                    else:
                        entropy_files[header][value].append(file_path)
    return entropy_files

import logging


def compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign):
    """Compare entropy values from malicious dataset with all values from benign dataset,
    focusing on exact matches. Logs only the count of matching benign files at INFO level,
    and no matches at DEBUG level."""
    logging.info("Starting comparison of entropy values...")

    for header in entropy_files_malicious:
        logging.debug(f"Processing {header}:")  # Using DEBUG for processing messages
        for value_malicious, files_malicious in entropy_files_malicious[header].items():
            if value_malicious in entropy_files_benign[header]:
                files_benign = entropy_files_benign[header][value_malicious]
                count_benign = len(files_benign)  # Get the count of matching benign files

                # Log matches at INFO level
                logging.debug(f"{header} - Entropy Value: {value_malicious} - Match found with {count_benign} benign files.")
            else:
                # Log no matches at DEBUG level
                logging.debug(f"Entropy Value: {value_malicious} - No match found in benign files.")

    logging.info("Comparison of entropy values completed.")


# Example usage
entropy_files_malicious = read_entropy_values_with_files(MALICIOUS_INPUT_CSV)
entropy_files_benign = read_entropy_values_with_files(BENIGN_INPUT_CSV)
compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign)
