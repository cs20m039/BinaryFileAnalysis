import csv
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

'''MALICIOUS_INPUT_CSV = "output/entropy_values_malicious.csv"
BENIGN_INPUT_CSV = "output/entropy_values_benign.csv"'''

MALICIOUS_INPUT_CSV = "output/entropy_values_malicious_FirstLastBytes.csv"
BENIGN_INPUT_CSV = "output/entropy_values_benign_FirstLastBytes.csv"

def read_entropy_values_with_files(csv_path):
    """Read entropy values and corresponding file paths from a CSV file."""
    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)
        headers = next(csvreader)[1:]  # Skip 'File Path' and get entropy headers
        entropy_files = {header: {} for header in headers}  # Maps entropy values to file paths
        for row in csvreader:
            file_path = row[0]
            for header, value in zip(headers, row[1:]):
                if value:  # Ensure the value is not empty
                    value = float(value)
                    if value not in entropy_files[header]:
                        entropy_files[header][value] = [file_path]
                    else:
                        entropy_files[header][value].append(file_path)
    return entropy_files

import logging


def compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign):
    """Compare header and footer entropy values from malicious dataset with all values from benign dataset,
    considering a match only when both header and footer entropy values match."""
    logging.info("Starting comparison of header and footer entropy values...")

    # Split headers into header and footer groups for easier processing
    headers_malicious = list(entropy_files_malicious.keys())
    headers_benign = list(entropy_files_benign.keys())
    header_headers = [h for h in headers_malicious if 'HeaderEntropy' in h]
    footer_headers = [h for h in headers_malicious if 'FooterEntropy' in h]

    for header_header, footer_header in zip(header_headers, footer_headers):
        for value_malicious_header, files_malicious_header in entropy_files_malicious[header_header].items():
            for value_malicious_footer, files_malicious_footer in entropy_files_malicious[footer_header].items():
                # Ensure we're looking at the same malicious file(s) for both header and footer
                common_files_malicious = set(files_malicious_header).intersection(files_malicious_footer)
                if not common_files_malicious:
                    continue  # Skip if there's no common malicious file between header and footer

                # Check for matches in benign dataset
                if value_malicious_header in entropy_files_benign[header_header] and value_malicious_footer in entropy_files_benign[footer_header]:
                    common_files_benign_header = set(entropy_files_benign[header_header][value_malicious_header])
                    common_files_benign_footer = set(entropy_files_benign[footer_header][value_malicious_footer])

                    # Intersection of benign files that match both header and footer entropy values
                    common_files_benign = common_files_benign_header.intersection(common_files_benign_footer)

                    if common_files_benign:
                        logging.info(f"Match found for both header and footer entropy values with {len(common_files_benign)} benign files.")

    logging.info("Comparison of header and footer entropy values completed.")

# Example usage
entropy_files_malicious = read_entropy_values_with_files(MALICIOUS_INPUT_CSV)
entropy_files_benign = read_entropy_values_with_files(BENIGN_INPUT_CSV)
compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign)
