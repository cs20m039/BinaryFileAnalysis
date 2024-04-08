import csv
from collections import defaultdict

# Function to read CSV content into a dictionary
def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

# Load both CSV files
malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')

# Generate header and footer keys
header_keys = [f'Header{i}' for i in range(1, 11)]
footer_keys = [f'Footer{i}' for i in range(1, 11)]

# Prepare to aggregate matches
matches = defaultdict(lambda: {"malicious": 0, "benign": 0})

# Iterate through each header and corresponding footer
for header_key, footer_key in zip(header_keys, footer_keys):
    # Aggregate matches for this header-footer pair
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0})

    # Count occurrences in malicious CSV
    for row in malicious_csv:
        header_footer_values[(row[header_key], row[footer_key])]["malicious"] += 1

    # Count occurrences in benign CSV
    for row in benign_csv:
        if (row[header_key], row[footer_key]) in header_footer_values:
            header_footer_values[(row[header_key], row[footer_key])]["benign"] += 1

    # Aggregate matches with counts for both files
    for key, value in header_footer_values.items():
        if value["malicious"] > 0 and value["benign"] > 0:  # Found in both
            matches[key] = value

# Print aggregated matches with occurrences
for (header_value, footer_value), counts in matches.items():
    print(f"MATCH: Header Value = '{header_value}', Footer Value = '{footer_value}', "
          f"Occurrences in Malicious = {counts['malicious']}, "
          f"Occurrences in Benign = {counts['benign']}")
