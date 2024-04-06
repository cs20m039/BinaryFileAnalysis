# Imports the information of the CSV-File
# Reads all patterns from malicious and compares to a benign folder

import csv
import datetime
import logging
import os

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_FILE_PATH = f'../Logfiles/log-signature_compare_header-benign_{timestamp}.txt'
CSV_PATH = '../DataExchange/datafile_signature_header_benign_4-140.csv'
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')
def get_byte_range_from_csv(csv_path):
    logging.debug('Determining the byte range from the CSV headers.')
    with open(csv_path, mode='r', newline='') as csv_file:
        reader = csv.reader(csv_file)
        headers = next(reader)
    byte_headers = [header for header in headers if header.endswith('Byte')]
    byte_lengths = [int(header.replace('Byte', '')) for header in byte_headers]
    min_byte_length, max_byte_length = min(byte_lengths), max(byte_lengths)
    logging.debug(f'Minimum byte length: {min_byte_length}, Maximum byte length: {max_byte_length}')
    return min_byte_length, max_byte_length


def load_csv_data(csv_path):
    logging.debug('Loading CSV data.')
    hex_data_by_length = {}
    pattern_sources = {}
    with open(csv_path, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            source_file = row['FileHash']
            for length, hex_value in row.items():
                if hex_value and length != 'FileHash':
                    byte_length = int(length.replace('Byte', ''))
                    pattern_key = f"{byte_length}_{hex_value}"
                    if byte_length not in hex_data_by_length:
                        hex_data_by_length[byte_length] = set()
                    hex_data_by_length[byte_length].add(pattern_key)
                    pattern_sources[pattern_key] = source_file
    logging.debug('CSV data loaded successfully.')
    return hex_data_by_length, pattern_sources


def find_pattern_matches(directory_path, hex_data_by_length, pattern_sources, min_length, max_length):
    logging.debug('Starting pattern matching process.')
    pattern_match_counts = {}
    for length in range(max_length, min_length - 1, -1):
        logging.debug(f'Checking patterns of length {length} bytes.')
        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                with open(full_path, 'rb') as file:
                    file_start = file.read(max_length)
                    for pattern_key in hex_data_by_length.get(length, []):
                        hex_value = pattern_key.split('_')[1]
                        pattern_bytes = bytes.fromhex(hex_value)
                        if file_start.startswith(pattern_bytes):
                            if pattern_key not in pattern_match_counts:
                                pattern_match_counts[pattern_key] = 1
                            else:
                                pattern_match_counts[pattern_key] += 1
                            break
    for pattern_key, count in pattern_match_counts.items():
        byte_length, hex_value = pattern_key.split('_')
        logging.info(f'Byte Length: {byte_length}, Pattern: {hex_value}, Matches: {count}')
    logging.debug('Pattern matching process completed.')


if __name__ == '__main__':
    logging.info('Script started.')
    min_length, max_length = get_byte_range_from_csv(CSV_PATH)
    hex_data_by_length, pattern_sources = load_csv_data(CSV_PATH)
    find_pattern_matches(DIRECTORY_PATH, hex_data_by_length, pattern_sources, min_length, max_length)

    logging.info('Script finished.')

