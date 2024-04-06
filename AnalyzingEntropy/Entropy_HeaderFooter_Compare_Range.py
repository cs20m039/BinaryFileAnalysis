import csv
import logging
from collections import defaultdict
import datetime

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=f'../Logfiles/log_entropy_compare_headerfooter_benign{timestamp}.log',
                    filemode='w')

MALICIOUS_INPUT_CSV = "../DataExchange/datafile_entropy_headerfooter_benign_1-500.csv"
BENIGN_INPUT_CSV = "../DataExchange/datafile_entropy_headerfooter_malicious_1-500.csv"

def read_entropy_values(csv_path):
    entropy_values = defaultdict(lambda: defaultdict(list))
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                file_path = row.pop('FileHash')
                for key, value in row.items():
                    if value:
                        entropy_values[key][float(value)].append(file_path)
    except IOError as e:
        logging.error(f"Failed to read file {csv_path}: {e}")
    return entropy_values

def compare_entropy_values(entropy_files_malicious, entropy_files_benign):
    logging.info("Starting comparison of entropy values...")
    header_keys = [key for key in entropy_files_malicious.keys() if 'HeaderEntropy' in key]
    footer_keys = [key for key in entropy_files_malicious.keys() if 'FooterEntropy' in key]
    for header_key, footer_key in zip(header_keys, footer_keys):
        for header_value, malicious_header_files in entropy_files_malicious[header_key].items():
            for footer_value, malicious_footer_files in entropy_files_malicious[footer_key].items():
                malicious_matches = set(malicious_header_files).intersection(malicious_footer_files)
                benign_header_files = entropy_files_benign[header_key].get(header_value, [])
                benign_footer_files = entropy_files_benign[footer_key].get(footer_value, [])
                benign_matches = set(benign_header_files).intersection(benign_footer_files)
                if malicious_matches and benign_matches:
                    logging.info(f"Match found: Header {header_key} with value {header_value} and Footer {footer_key} with value {footer_value} match in {len(benign_matches)} benign files.")
                else:
                    logging.debug(f"No match found for Header {header_key} with value {header_value} and Footer {footer_key} with value {footer_value}.")
    logging.info("Comparison completed.")

if __name__ == "__main__":
    entropy_files_malicious = read_entropy_values(MALICIOUS_INPUT_CSV)
    entropy_files_benign = read_entropy_values(BENIGN_INPUT_CSV)
    compare_entropy_values(entropy_files_malicious, entropy_files_benign)
