import csv
import os
import re
from collections import defaultdict

# Choose mode here: 'header-mode', 'footer-mode', 'both-mode'
mode = 'both-mode'

print("Current Working Directory:", os.getcwd())

def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

malicious_csv = read_csv('../DataExchange/datafile_entropy_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_entropy_benign_both_1-10.csv')

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

header_keys = []
footer_keys = []
if mode in ['header-mode', 'both-mode']:
    max_header_index = max(find_max_index(malicious_csv, 'Header'), find_max_index(benign_csv, 'Header'))
    header_keys = [f'Header{i}' for i in range(1, max_header_index + 1)]
if mode in ['footer-mode', 'both-mode']:
    max_footer_index = max(find_max_index(malicious_csv, 'Footer'), find_max_index(benign_csv, 'Footer'))
    footer_keys = [f'Footer{i}' for i in range(1, max_footer_index + 1)]

matches = defaultdict(lambda: {"malicious": 0, "benign": 0, "files": {"malicious": [], "benign": []}})

# Logic to compare headers and footers as per the chosen mode
if mode in ['header-mode', 'footer-mode']:
    keys_to_compare = header_keys if mode == 'header-mode' else footer_keys
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
                composite_key = (key, value_key)
                matches[composite_key] = value_info

elif mode == 'both-mode':
    # Compare both headers and footers together for each row
    for row_m in malicious_csv:
        for row_b in benign_csv:
            match_found = True
            for h_key, f_key in zip(header_keys, footer_keys):
                if row_m[h_key] != row_b[h_key] or row_m[f_key] != row_b[f_key]:
                    match_found = False
                    break
            if match_found:
                composite_key = tuple([(h_key, row_m[h_key], f_key, row_m[f_key]) for h_key, f_key in zip(header_keys, footer_keys)])
                matches[composite_key]["malicious"] += 1
                matches[composite_key]["files"]["malicious"].append(row_m["FileName"])
                matches[composite_key]["benign"] += 1
                matches[composite_key]["files"]["benign"].append(row_b["FileName"])

# Reporting Matches
if mode in ['header-mode', 'footer-mode']:
    for (column_key, match_value), info in matches.items():
        mode_key = "Header" if mode == 'header-mode' else "Footer"
        print(f"MATCH: {mode_key} {column_key.split(mode_key)[-1]} Value = '{match_value}', "
              f"Occurrences in Malicious = {info['malicious']} ({', '.join(set(info['files']['malicious']))}), "
              f"Occurrences in Benign = {info['benign']} ({', '.join(set(info['files']['benign']))})")
elif mode == 'both-mode':
    for composite_keys, info in matches.items():
        for h_key, h_value, f_key, f_value in composite_keys:
            print(f"MATCH: {h_key} Value = '{h_value}', {f_key} Value = '{f_value}', "
                  f"Occurrences in Malicious = {info['malicious']} ({', '.join(set(info['files']['malicious']))}), "
                  f"Occurrences in Benign = {info['benign']} ({', '.join(set(info['files']['benign']))})")
