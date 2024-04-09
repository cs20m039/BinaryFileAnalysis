import csv
import datetime
import logging
import re
from collections import defaultdict

def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')
mode = 'header'   # Can be 'header', 'footer', or 'both'

TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_entropy_read_{TIMESTAMP}.log'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])

def find_max_index(csv_data):
    max_index = 0
    pattern = re.compile(r'(Header|Footer)(\d+)')
    for row in csv_data:
        for key in row.keys():
            match = pattern.match(key)
            if match:
                index = int(match.group(2))
                max_index = max(max_index, index)
    return max_index

max_header_footer_index = max(find_max_index(malicious_csv), find_max_index(benign_csv))

header_footer_aggregate = defaultdict(lambda: {"patterns": 0, "malicious": 0, "benign": 0})

for index in range(1, max_header_footer_index + 1):
    header_key = f'Header{index}' if mode in ['header', 'both'] else None
    footer_key = f'Footer{index}' if mode in ['footer', 'both'] else None
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0})

    for row in malicious_csv + benign_csv:
        csv_type = "malicious" if row in malicious_csv else "benign"
        if mode == 'both':
            value = (row.get(header_key, ''), row.get(footer_key, ''))
        elif mode == 'header':
            value = row.get(header_key, '')
        else:  # mode == 'footer'
            value = row.get(footer_key, '')

        if value:  # Skip empty values
            header_footer_values[value][csv_type] += 1

    # Aggregate results for this header/footer
    for value, counts in header_footer_values.items():
        if counts['malicious'] > 0 and counts['benign'] > 0:
            header_footer_aggregate[index]["patterns"] += 1
            header_footer_aggregate[index]["malicious"] += counts["malicious"]
            header_footer_aggregate[index]["benign"] += counts["benign"]

# Logging the aggregated results
for index, info in header_footer_aggregate.items():
    logging.info(f"Header{index}: Patterns = {info['patterns']}, "
                 f"Ransomware Matches = {info['malicious']}, "
                 f"Benign Matches = {info['benign']}")

