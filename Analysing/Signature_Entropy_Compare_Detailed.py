import csv
import datetime
import logging
import re
from collections import defaultdict


def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


malicious_csv = read_csv('../DataExchange/datafile_entropy_malicious_both_1-800.csv')
benign_csv = read_csv('../DataExchange/datafile_entropy_benign_both_1-800.csv')
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

header_keys = [f'Header{i}' for i in range(1, max_header_footer_index + 1)]
footer_keys = [f'Footer{i}' for i in range(1, max_header_footer_index + 1)]

matches = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

for index, (header_key, footer_key) in enumerate(zip(header_keys, footer_keys), start=1):
    header_footer_values = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

    for row in malicious_csv:
        if mode == 'both':
            value = (row[header_key], row[footer_key])
        elif mode == 'header':
            value = (row[header_key],)
        else:  # mode == 'footer'
            value = (row[footer_key],)

        header_footer_values[value]["malicious"] += 1
        header_footer_values[value]["files"]["malicious"].append(row["FileName"])

    for row in benign_csv:
        if mode == 'both':
            value = (row[header_key], row[footer_key])
        elif mode == 'header':
            value = (row[header_key],)
        else:  # mode == 'footer'
            value = (row[footer_key],)

        if value in header_footer_values:
            header_footer_values[value]["benign"] += 1
            header_footer_values[value]["files"]["benign"].append(row["FileName"])

    for key, value in header_footer_values.items():
        if value["malicious"] > 0 and value["benign"] > 0:
            match_key = ((header_key, footer_key) + key) if mode == 'both' else (
                    (header_key if mode == 'header' else footer_key,) + key)
            matches[match_key] = value

for match_key, info in matches.items():
    if mode == 'both':
        header_key, footer_key, header_value, footer_value = match_key
        logging.info(f"MATCH: {header_key} Value = '{header_value}', {footer_key} Value = '{footer_value}', "
                     f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
                     f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")
    else:
        key = match_key[0]
        value = match_key[1]
        logging.info(f"MATCH: {key} Value = '{value}', "
                     f"Occurrences in Malicious = {info['malicious']} ({', '.join(info['files']['malicious'])}), "
                     f"Occurrences in Benign = {info['benign']} ({', '.join(info['files']['benign'])})")

