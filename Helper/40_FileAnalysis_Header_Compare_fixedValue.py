import csv
import os

def load_csv_data(csv_path):
    """
    Load hex data from the CSV file, specifically looking for hex patterns of a fixed length (e.g., 290 bytes).
    """
    hex_data = set()  # Now using a simple set as we're only interested in one length
    with open(csv_path, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            hex_value = row.get('290 Bytes')  # Focus on the specific column for 290-byte patterns
            if hex_value:
                hex_data.add(hex_value)
    return hex_data

def find_max_pattern_match(directory_path, hex_data):
    """
    For each binary file in the directory and subdirectories, check from the beginning of the file
    for hex patterns of a fixed length (290 bytes), reporting any matches found.
    """
    file_count = 0
    match_count = 0
    for dirpath, _, filenames in os.walk(directory_path):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            file_count += 1
            with open(full_path, 'rb') as file:
                file_content = file.read()
                # Directly check for matches of the fixed length pattern
                for hex_value in hex_data:
                    pattern_bytes = bytes.fromhex(hex_value)
                    if file_content.startswith(pattern_bytes):
                        match_count += 1
                        print(f"Pattern match in {full_path}: 290 bytes, Pattern: {hex_value}")
                        break  # Since we're only looking for one pattern length, we can stop after the first match

    print(f"Total files analyzed: {file_count}")
    print(f"Total files matched: {match_count}")

# Load hex data from CSV
csv_path = 'output_fixed_bytes.csv'  # Adjust the path to your CSV file
hex_data = load_csv_data(csv_path)

# Directory to compare
directory_path = '/home/cs20m039/thesis/dataset'  # Adjust to your target directory path
find_max_pattern_match(directory_path, hex_data)
