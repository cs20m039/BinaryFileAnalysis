import csv
import logging
from collections import defaultdict
import datetime

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Set up logging to file
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=f'../Logfiles/log_entropy_compare_headerfooter_benign{timestamp}.log',  # Log file path
                    filemode='w')  # 'w' for overwrite, 'a' for append



# Update these paths to the correct locations of your CSV files
MALICIOUS_INPUT_CSV = "../DataExchange/datafile_entropy_headerfooter_benign_1-500.csv"
BENIGN_INPUT_CSV = "../DataExchange/datafile_entropy_headerfooter_malicious_1-500.csv"

def read_entropy_values(csv_path):
    """Read entropy values and corresponding file paths from a CSV file."""
    entropy_values = defaultdict(lambda: defaultdict(list))
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                file_path = row.pop('FileHash')  # Assuming 'FileHash' is the unique identifier
                for key, value in row.items():
                    if value:  # Check if the value is not empty
                        entropy_values[key][float(value)].append(file_path)
    except IOError as e:
        logging.error(f"Failed to read file {csv_path}: {e}")
    return entropy_values

def compare_entropy_values(entropy_files_malicious, entropy_files_benign):
    """Compare entropy values and print files with matching header and footer entropy values."""
    logging.info("Starting comparison of entropy values...")

    # Extract header and footer entropy keys
    header_keys = [key for key in entropy_files_malicious.keys() if 'HeaderEntropy' in key]
    footer_keys = [key for key in entropy_files_malicious.keys() if 'FooterEntropy' in key]

    for header_key, footer_key in zip(header_keys, footer_keys):
        for header_value, malicious_header_files in entropy_files_malicious[header_key].items():
            for footer_value, malicious_footer_files in entropy_files_malicious[footer_key].items():
                # Find malicious files with both matching header and footer values
                malicious_matches = set(malicious_header_files).intersection(malicious_footer_files)

                benign_header_files = entropy_files_benign[header_key].get(header_value, [])
                benign_footer_files = entropy_files_benign[footer_key].get(footer_value, [])
                # Find benign files with both matching header and footer values
                benign_matches = set(benign_header_files).intersection(benign_footer_files)

                if malicious_matches and benign_matches:
                    logging.info(f"Match found: Header {header_key} with value {header_value} and Footer {footer_key} with value {footer_value} match in {len(benign_matches)} benign files.")
                else:
                    logging.debug(f"No match found for Header {header_key} with value {header_value} and Footer {footer_key} with value {footer_value}.")

    logging.info("Comparison completed.")

# Main execution
if __name__ == "__main__":
    entropy_files_malicious = read_entropy_values(MALICIOUS_INPUT_CSV)
    entropy_files_benign = read_entropy_values(BENIGN_INPUT_CSV)
    compare_entropy_values(entropy_files_malicious, entropy_files_benign)
