import csv
import os
import logging
import datetime
from multiprocessing import Pool
from functools import partial

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define the log file path with the timestamp included in the filename
LOG_FILE_PATH = f'../Logfiles/log_signature_compare_Footer-benignFiles_{timestamp}.txt'

# Setup basic configuration for logging to write to a file
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')  # Use 'w' to overwrite the log file each time or

CSV_PATH = '../DataExchange/datafile_signature_footer_benign_8600-8700.csv'  # Path to CSV with patterns from benign files
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/malicious'  # Directory containing malicious files

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
    logging.debug('Loading CSV data with hash values as identifiers.')
    hex_data_by_length = {}
    pattern_sources = {}  # Maps pattern keys to hash values
    with open(csv_path, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            hash_value = row['FileHash']  # Assuming 'HashValue' is the column name for the hash
            for length, hex_value in row.items():
                if hex_value and length != 'FileHash':  # Adjusted from 'FilePath'
                    byte_length = int(length.replace('Byte', ''))
                    pattern_key = f"{byte_length}_{hex_value}"  # Unique key for each pattern
                    if byte_length not in hex_data_by_length:
                        hex_data_by_length[byte_length] = set()
                    hex_data_by_length[byte_length].add(pattern_key)
                    pattern_sources[pattern_key] = hash_value  # Store hash value for each pattern
    logging.debug('CSV data loaded successfully with hash value identifiers.')
    return hex_data_by_length, pattern_sources

def find_matches_in_file(file_path, patterns):
    matches = []
    with open(file_path, 'rb') as file:
        file_end = file.read()[-max_length:]  # Read up to max_length bytes from the end
        for pattern in patterns:
            if file_end.endswith(pattern):
                matches.append(pattern)
    return matches

def find_pattern_matches(directory_path, hex_data_by_length, pattern_sources, min_length, max_length):
    logging.debug('Starting pattern matching process.')
    previous_match_count = None

    # Iterate over patterns from benign files
    for length in range(max_length, min_length - 1, -1):
        current_match_count = 0
        logging.debug(f'Checking patterns of length {length} bytes.')

        patterns = [bytes.fromhex(pattern_key.split('_')[1]) for pattern_key in hex_data_by_length.get(length, [])]

        # Parallelize file processing
        with Pool() as pool:
            matches = pool.map(partial(find_matches_in_file, patterns=patterns), file_paths)

        current_match_count = sum(len(match) for match in matches)

        if current_match_count != previous_match_count:
            logging.info(f"Length {length} bytes: {current_match_count} files found with a pattern at the end.")
            previous_match_count = current_match_count
        else:
            logging.debug(f"No change for length {length} bytes.")

    logging.debug('Pattern matching process completed.')

if __name__ == '__main__':
    logging.info('Script started.')
    min_length, max_length = get_byte_range_from_csv(CSV_PATH)
    hex_data_by_length, pattern_sources = load_csv_data(CSV_PATH)

    # Get list of file paths
    file_paths = [os.path.join(dirpath, filename) for dirpath, _, filenames in os.walk(DIRECTORY_PATH) for filename in filenames]

    # Call function to find matches between malicious and benign patterns
    find_pattern_matches(DIRECTORY_PATH, hex_data_by_length, pattern_sources, min_length, max_length)

    logging.info('Script finished.')
