import csv
import datetime
import logging
import re
from collections import defaultdict

def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

# Configuration settings
mode = 'both'   # Can be 'header', 'footer', or 'both'
prefix = 'SC'   # This example uses 'SC' for simplicity

# Read CSV data
malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-600.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-600.csv')

# Calculate totals
total_malicious = len(malicious_csv)
total_benign = len(benign_csv)

# Setup logging
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_compare_signature_read_{TIMESTAMP}.log'
logging.basicConfig(level=logging.INFO, format='%(message)s',
                    handlers=[logging.FileHandler(LOG_FILE_PATH, mode='w'), logging.StreamHandler()])

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

# Initialize data structure for aggregation
header_footer_aggregate = defaultdict(lambda: {"patterns": 0, "malicious": 0, "benign": 0})

# Aggregation logic
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

    for value, counts in header_footer_values.items():
        increment_factor = 2 if mode == 'both' else 1  # Double in 'both' mode
        if counts['malicious'] > 0 and counts['benign'] > 0:
            header_footer_aggregate[index]["patterns"] += increment_factor
            header_footer_aggregate[index]["malicious"] += counts["malicious"] * increment_factor
            header_footer_aggregate[index]["benign"] += counts["benign"] * increment_factor

# Prepare results with corrected logic
results = {'BFPL': [], f'{prefix}PC': [], f'{prefix}RC': [], f'{prefix}RP': [], f'{prefix}BC': [], f'{prefix}BP': []}

sequential_index = 2  # Start with 2 because BFPL is intended to start from 2
last_known_info = None  # To remember the last known good values

# Ensure results are aggregated correctly
for index in range(1, max_header_footer_index + 1):
    if index in header_footer_aggregate:
        info = header_footer_aggregate[index]
        last_known_info = info  # Update last known values for future gaps
    else:
        info = last_known_info if last_known_info else {"patterns": 0, "malicious": 0, "benign": 0}

    # Calculate percentages
    malicious_percentage = (info['malicious'] / total_malicious) * 100
    benign_percentage = (info['benign'] / total_benign) * 100

    # Log and store results
    logging.info(
        f"{sequential_index}, {info['patterns']}, {info['malicious']}, {malicious_percentage:.2f}, {info['benign']}, {benign_percentage:.2f}")
    results['BFPL'].append(sequential_index)
    results[f'{prefix}PC'].append(info['patterns'])
    results[f'{prefix}RC'].append(info['malicious'])
    results[f'{prefix}RP'].append(round(malicious_percentage, 1))
    results[f'{prefix}BC'].append(info['benign'])
    results[f'{prefix}BP'].append(round(benign_percentage, 1))

    sequential_index += 1  # Ensure BFPL indexes are sequential

# Print results outside the for-loop to ensure it's done once
for key, values in results.items():
    print(f"{key}: {values}")