import csv
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MALICIOUS_INPUT_CSV = "output/entropy_values_malicious.csv"
BENIGN_INPUT_CSV = "output/entropy_values_benign.csv"

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

def compare_entropy_values_and_print_files(entropy_files_a, entropy_files_b):
    """Compare entropy values between two datasets, showing matches and their corresponding files."""
    for header in entropy_files_a:
        values_a = set(entropy_files_a[header].keys())
        values_b = set(entropy_files_b[header].keys())
        matches = values_a & values_b
        if matches:
            logging.info(f"Matches found for {header}:")
            for match in matches:
                files_a = entropy_files_a[header][match]
                files_b = entropy_files_b[header][match]
                logging.info(f"  Entropy Value: {match}")
                logging.info(f"  Files from Set A: {', '.join(files_a)}")
                logging.info(f"  Files from Set B: {', '.join(files_b)}")

# Example usage
entropy_files_malicious = read_entropy_values_with_files(MALICIOUS_INPUT_CSV)
entropy_files_benign = read_entropy_values_with_files(BENIGN_INPUT_CSV)
compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign)
