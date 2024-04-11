import csv
import datetime
import logging
import re
from collections import defaultdict

def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

# Load the CSV data
malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')
mode = 'both'   # Can be 'header', 'footer', or 'both'

# Setup logging
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_entropy_read_{TIMESTAMP}.log'

"""logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])"""

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename=LOG_FILE_PATH,
                    filemode='w')

def find_max_index(csv_data):
    """Find the maximum index for headers and footers."""
    max_index = 0
    pattern = re.compile(r'(Header|Footer)(\d+)')
    for row in csv_data:
        for key in row.keys():
            match = pattern.match(key)
            if match:
                index = int(match.group(2))
                max_index = max(max_index, index)
    return max_index

print(f"Malicious CSV Entries: {len(malicious_csv)}")
print(f"Benign CSV Entries: {len(benign_csv)}")

max_header_footer_index = max(find_max_index(malicious_csv), find_max_index(benign_csv))
header_keys = [f'Header{i}' for i in range(1, max_header_footer_index + 1)]
footer_keys = [f'Footer{i}' for i in range(1, max_header_footer_index + 1)]

# Initialize the dictionary for matches
matches = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}, "origin": set()})

# Iterate through header and footer keys
for index, (header_key, footer_key) in enumerate(zip(header_keys, footer_keys), start=1):
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}, "origin": set()})

    # Process the malicious CSV
    for row in malicious_csv:
        if mode == 'both':
            value = (row[header_key], row[footer_key])
        elif mode == 'header':
            value = row[header_key]
        else:  # mode == 'footer'
            value = row[footer_key]
        # Debug print statement for malicious CSV
        print(f"Processing row with value: {value} from malicious CSV")
        header_footer_values[value]["origin"].add("malicious")
        header_footer_values[value]["files"]["malicious"].append(row["FileName"])

    # Process the benign CSV
    for row in benign_csv:
        if mode == 'both':
            value = (row[header_key], row[footer_key])
        elif mode == 'header':
            value = row[header_key]
        else:  # mode == 'footer'
            value = row[footer_key]
        # Debug print statement for benign CSV
        print(f"Processing row with value: {value} from benign CSV")
        header_footer_values[value]["origin"].add("benign")
        header_footer_values[value]["files"]["benign"].append(row["FileName"])

    # Collect matches
    for value, data in header_footer_values.items():
        if data["malicious"] > 0 or data["benign"] > 0:
            match_key = ((header_key, footer_key) + value) if mode == 'both' else (
                        (header_key if mode == 'header' else footer_key,) + value)
            matches[match_key] = data

# Log matches
for match_key, info in matches.items():
    # Debugging print statement
    print(f"Logging match for {match_key}: {info}")


    origin = ", ".join(sorted(info['origin']))  # Sort to keep consistent order
    if mode == 'both':
        header_key, footer_key, header_value, footer_value = match_key
        logging.info(
            f"MATCH (Origin: {origin}): {header_key} Value = '{header_value}' from {origin}, {footer_key} Value = '{footer_value}' from {origin}, "
            f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
            f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")
    else:
        key, value = match_key[0], match_key[1]
        logging.info(f"MATCH (Origin: {origin}): {key} Value = '{value}' from {origin}, "
                     f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
                     f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")

