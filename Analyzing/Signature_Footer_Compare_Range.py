import csv
import os
import logging
import datetime

# Generate a timestamp string in the desired format
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define the log file path with the timestamp included in the filename
LOG_FILE_PATH = f'logfiles/log-compareFooter-benignFiles-with-maliciousFooters_{timestamp}.txt'

# Setup basic configuration for logging to write to a file
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='w')  # Use 'w' to overwrite the log file each time or

CSV_PATH = '../DataExchange/data_footerSignature_maliciousFiles_varyingLengths.csv'  # Path to CSV with patterns from benign files
DIRECTORY_PATH = '/home/cs20m039/thesis/dataset1/benign'  # Directory containing malicious files

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
    pattern_sources = {}  # New dictionary to keep track of pattern sources
    with open(csv_path, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            source_file = row['FilePath']  # Assuming 'FilePath' column exists
            for length, hex_value in row.items():
                if hex_value and length != 'FilePath':
                    byte_length = int(length.replace('Byte', ''))
                    pattern_key = f"{byte_length}_{hex_value}"  # Unique key for each pattern
                    if byte_length not in hex_data_by_length:
                        hex_data_by_length[byte_length] = set()
                    hex_data_by_length[byte_length].add(pattern_key)
                    pattern_sources[pattern_key] = source_file  # Store source file for each pattern
    logging.debug('CSV data loaded successfully.')
    return hex_data_by_length, pattern_sources

def find_pattern_matches(directory_path, hex_data_by_length, pattern_sources, min_length, max_length):
    logging.debug('Starting pattern matching process.')
    previous_match_count = None

    # Iterate over patterns from benign files
    for length in range(max_length, min_length - 1, -1):
        current_match_count = 0
        logging.debug(f'Checking patterns of length {length} bytes.')

        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                with open(full_path, 'rb') as file:
                    file_end = file.read()[::-1][:max_length]  # Read up to max_length bytes from the end and reverse
                    for pattern_key in hex_data_by_length.get(length, []):
                        hex_value = pattern_key.split('_')[1]
                        pattern_bytes = bytes.fromhex(hex_value)
                        if file_end.endswith(pattern_bytes):  # Check if the end matches the pattern
                            current_match_count += 1
                            source_file = pattern_sources[pattern_key]
                            logging.debug(f'Match found: Pattern "{hex_value}" from "{source_file}" in file "{filename}" at the end')
                            break  # Found a match at the end, no need to check further patterns for this file

        if current_match_count != previous_match_count:
            logging.info(f"Length {length} bytes: {current_match_count} files found with a pattern at the end.")
            previous_match_count = current_match_count
        else:
            logging.debug(f"No change for length {length} bytes.")

    logging.debug('Pattern matching process completed.')

def main():
    logging.info('Script started.')
    min_length, max_length = get_byte_range_from_csv(CSV_PATH)
    hex_data_by_length, pattern_sources = load_csv_data(CSV_PATH)

    # Call function to find matches between malicious and benign patterns
    find_pattern_matches(DIRECTORY_PATH, hex_data_by_length, pattern_sources, min_length, max_length)

    logging.info('Script finished.')

if __name__ == '__main__':
    main()
