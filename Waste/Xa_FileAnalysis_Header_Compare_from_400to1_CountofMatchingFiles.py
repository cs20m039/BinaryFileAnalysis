import csv
import os

def load_csv_data(csv_path):
    """
    Load hex data from the CSV file, organized by the length of the hex pattern.
    """
    hex_data_by_length = {}
    with open(csv_path, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            # Adjusted to include patterns down to 1 byte
            for length in range(2, 501):
                hex_value = row.get(f'{length}Bytes')
                if hex_value:
                    if length not in hex_data_by_length:
                        hex_data_by_length[length] = set()
                    hex_data_by_length[length].add(hex_value)
    return hex_data_by_length

def find_pattern_matches(directory_path, hex_data_by_length):
    """
    Check each binary file for matching patterns from 290 down to 1 byte. Print out the count of matching files
    for each length when it changes from the count for the previous length.
    """
    previous_match_count = None  # Initialize the previous match count for comparison

    for length in range(500, 0, -1):  # Iterate from 290 to 1 byte
        current_match_count = 0  # Initialize the match counter for the current length
        for dirpath, _, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                with open(full_path, 'rb') as file:
                    file_content = file.read()
                    for hex_value in hex_data_by_length.get(length, []):
                        pattern_bytes = bytes.fromhex(hex_value)
                        if file_content.startswith(pattern_bytes):
                            current_match_count += 1  # Increment the match counter
                            break  # Found a match, no need to check other hex values for this file

        # Only print if the count has changed from the previous length checked
        if current_match_count != previous_match_count:
            print(f"Length{length}bytes: {current_match_count} files")
            previous_match_count = current_match_count

# Load hex data from CSV
csv_path = 'output_bytes_varying_lengths.csv'
hex_data_by_length = load_csv_data(csv_path)

# Directory to compare
directory_path = '/home/cs20m039/thesis/dataset/benign'
find_pattern_matches(directory_path, hex_data_by_length)

