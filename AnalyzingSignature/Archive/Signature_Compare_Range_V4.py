import csv
from collections import defaultdict
import os
print("Current Working Directory:", os.getcwd())

# Function to read CSV content into a dictionary
def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')

# Generate header and footer keys
header_keys = [f'Header{i}' for i in range(1, 11)]
footer_keys = [f'Footer{i}' for i in range(1, 11)]

# Prepare to aggregate matches
matches = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

# Iterate through each header and corresponding footer
for index, (header_key, footer_key) in enumerate(zip(header_keys, footer_keys), start=1):
    # Aggregate matches for this header-footer pair
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

    # Count occurrences in malicious CSV and track filenames
    for row in malicious_csv:
        value = (row[header_key], row[footer_key])
        header_footer_values[value]["malicious"] += 1
        header_footer_values[value]["files"]["malicious"].append(row["FileName"])

    # Count occurrences in benign CSV and track filenames
    for row in benign_csv:
        value = (row[header_key], row[footer_key])
        if value in header_footer_values:
            header_footer_values[value]["benign"] += 1
            header_footer_values[value]["files"]["benign"].append(row["FileName"])

    # Aggregate matches with counts for both files and accumulate filenames
    for key, value in header_footer_values.items():
        if value["malicious"] > 0 and value["benign"] > 0:  # Found in both
            matches[(header_key, footer_key) + key] = value

# Print aggregated matches with occurrences and filenames
for (header_key, footer_key, header_value, footer_value), info in matches.items():
    print(f"MATCH: {header_key} Value = '{header_value}', {footer_key} Value = '{footer_value}', "
          f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
          f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")
