import csv
from collections import defaultdict
import os
import re

# Choose mode here: 'header-mode', 'footer-mode', 'both-mode'
mode = 'both-mode'

print("Current Working Directory:", os.getcwd())

def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')

def find_max_index(csv_data, key_prefix):
    max_index = 0
    pattern = re.compile(rf'{key_prefix}(\d+)')
    for row in csv_data:
        for key in row.keys():
            match = pattern.match(key)
            if match:
                index = int(match.group(1))
                max_index = max(max_index, index)
    return max_index

# Adjust the generation of header and footer keys based on the selected mode
keys_to_compare = []
if mode in ['header-mode', 'both-mode']:
    max_header_index = max(find_max_index(malicious_csv, 'Header'), find_max_index(benign_csv, 'Header'))
    keys_to_compare.extend([f'Header{i}' for i in range(1, max_header_index + 1)])
if mode in ['footer-mode', 'both-mode']:
    max_footer_index = max(find_max_index(malicious_csv, 'Footer'), find_max_index(benign_csv, 'Footer'))
    keys_to_compare.extend([f'Footer{i}' for i in range(1, max_footer_index + 1)])

matches = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

for key in keys_to_compare:
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})
    for row in malicious_csv:
        value = row[key]
        header_footer_values[value]["malicious"] += 1
        header_footer_values[value]["files"]["malicious"].append(row["FileName"])
    for row in benign_csv:
        value = row[key]
        if value in header_footer_values:
            header_footer_values[value]["benign"] += 1
            header_footer_values[value]["files"]["benign"].append(row["FileName"])

    for value_key, value_info in header_footer_values.items():
        if value_info["malicious"] > 0 and value_info["benign"] > 0:
            # Correctly form the key as a tuple
            composite_key = (key, value_key)  # No concatenation, directly use a tuple
            matches[composite_key] = value_info

# Correct the printing section to unpack the tuple key and access info correctly
for (column_key, match_value), info in matches.items():
    print(f"MATCH: {column_key} Value = '{match_value}', "
          f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
          f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")
