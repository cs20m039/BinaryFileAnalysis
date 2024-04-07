import csv
import datetime
import logging
import os

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

LOG_FILE_PATH = f'../Logfiles/log-analyse-headerFooter_{timestamp}.txt'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')

CSV_PATH = '../DataExchange/datafile_signature_header_and_footer_malicious_4-300.csv'
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/benign'


def get_byte_range_from_csv(csv_path):
    logging.debug('Determining the byte range from the CSV headers.')
    with open(csv_path, mode='r', newline='') as csv_file:
        reader = csv.reader(csv_file)
        headers = next(reader)
    byte_headers = [header for header in headers if 'ByteFirst' in header or 'ByteLast' in header]
    byte_lengths = set(int(header.split('Byte')[0]) for header in byte_headers)
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
            file_hash = row['FileHash']
            for key, hex_value in row.items():
                if hex_value and key != 'FileHash':
                    byte_length, position = key.split('Byte')
                    byte_length = int(byte_length)
                    if position.endswith('First') or position.endswith('Last'):
                        if byte_length not in hex_data_by_length:
                            hex_data_by_length[byte_length] = {'First': set(), 'Last': set()}
                        hex_data_by_length[byte_length][position].add(hex_value)
                        pattern_sources[hex_value] = file_hash
    logging.debug('CSV data loaded successfully.')
    return hex_data_by_length, pattern_sources


def find_pattern_matches(directory_path, hex_data_by_length, pattern_sources, min_length, max_length):
    logging.info('Starting pattern matching process.')
    previous_match_count = None
    for length in range(max_length, min_length - 1, -1):
        match_count = 0
        logging.debug(f'Checking patterns of length {length} bytes.')
        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                file_size = os.path.getsize(full_path)
                with open(full_path, 'rb') as file:
                    file_start = file.read(length)
                    file.seek(max(0, file_size - length))
                    file_end = file.read(length)
                    start_patterns = hex_data_by_length.get(length, {}).get('First', set())
                    end_patterns = hex_data_by_length.get(length, {}).get('Last', set())
                    start_match = any(file_start.startswith(bytes.fromhex(pat)) for pat in start_patterns)
                    end_match = any(file_end.endswith(bytes.fromhex(pat)) for pat in end_patterns)
                    if start_match and end_match:
                        match_count += 1
        if match_count > 0 and match_count != previous_match_count:
            logging.info(
                f"Length {length} bytes: {match_count} files found with matching patterns at both start and end.")
            previous_match_count = match_count
    logging.info('Pattern matching process completed.')


def main():
    logging.info('Script started.')
    min_length, max_length = get_byte_range_from_csv(CSV_PATH)
    hex_data_by_length, pattern_sources = load_csv_data(CSV_PATH)
    find_pattern_matches(DIRECTORY_PATH, hex_data_by_length, pattern_sources, min_length, max_length)
    logging.info('Script finished.')


if __name__ == '__main__':
    main()
