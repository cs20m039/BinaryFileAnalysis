import csv
import logging
import os
import platform
from datetime import datetime

# Set up basic logging and paths
current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = f'hex_signature_analyzer_{current_datetime}.log'
logging.basicConfig(filename=log_file_name, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('hex_signature_matcher')
logger.setLevel(logging.DEBUG)

# Data paths
hex_malicious_file = "Patterns/datafile_signature_malicious_both_1-600.csv"
hex_benign_file = "Patterns/datafile_signature_benign_both_1-600.csv"

signature_lengths = [100, 150, 200, 300]
scan_mode = 'headers_footers'  # Options: 'headers' or 'headers_footers'


def get_scan_paths():
    if platform.system() == 'Windows':
        username = os.environ.get('USERNAME')
        directory = "C:\\"
        exclusions = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData',
                      f'C:\\Users\\{username}\\AppData']
    elif platform.system() == 'Darwin':
        directory = "/"
        exclusions = ['/System', '/Library', '/sbin', '/usr/bin', '/usr/sbin', '/Volumes', '/private',
                      '/.Spotlight-V100', '/.fseventsd', '/dev']
    elif platform.system() == 'Linux':
        directory = "/home/cs20m039/thesis/dataset1/"
        exclusions = ['/sys/kernel/security']
    return directory, exclusions


# Define file paths and exclusion directories based on operating system
directory_to_scan, exclusion_directories = get_scan_paths()


def read_hex_patterns(csv_file, num_bytes, mode):
    csv_values = []
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                file_hash = row['FileName']
                pattern = row.get(f"Header{num_bytes}", "") if mode == 'headers' else row.get(f"Footer{num_bytes}", "")
                malware_flag = 1 if 'malicious' in csv_file else 0
                csv_values.append((file_hash, pattern, malware_flag))
        logger.info(f"Loaded hex patterns from {csv_file} for {mode} {num_bytes}.")
    except Exception as e:
        logger.error(f"Failed to read hex patterns from {csv_file}: {e}")
    return csv_values



def extract_file_signatures(file_path, num_bytes):
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read()  # Read the file's content
            hex_signatures = [file_bytes[:i + 1].hex() for i in range(num_bytes) if i < len(file_bytes)]
            return hex_signatures
    except Exception as e:
        logger.error(f"Error extracting hex signatures from {file_path}: {e}")
        return []


def compare_hex_signatures(directory, patterns, num_bytes):
    matches = {"benign": [], "malware": [], "unknown": []}
    files_scanned = 0

    for root, dirs, files in os.walk(directory, topdown=True):
        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1
            hex_signature = extract_file_signatures(file_path, num_bytes)

            match_found = False
            for file_hash, pattern, flag in patterns:
                if hex_signature.startswith(pattern):  # Correct usage assuming hex_signature is a string
                    category = "malware" if flag == 1 else "benign"
                    matches[category].append((file_path, file_hash))
                    logger.debug(f"Match found: {file_path} classified as {category} using pattern from {file_hash}")
                    match_found = True
                    break

            if not match_found:
                matches["unknown"].append((file_path, None))
                logger.debug(f"No match for {file_path}")

    return files_scanned, len(matches['benign']), len(matches['malware']), len(matches['unknown'])






def extract_file_signatures(file_path, num_bytes):
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read(num_bytes)  # Read only the specified number of bytes
            hex_signature = file_bytes.hex()  # Convert these bytes to a single hex string
            return hex_signature
    except Exception as e:
        logger.error(f"Error extracting hex signatures from {file_path}: {e}")
        return ""



import time


def main():
    print(f"Directory to scan: {directory_to_scan}")
    print("Pattern, Total Scanned, Malware, Benign, Unknown, Time")

    for length in signature_lengths:
        bytes_to_read = length
        start_time = time.time()

        malicious_patterns = read_hex_patterns(hex_malicious_file, bytes_to_read, scan_mode)
        benign_patterns = read_hex_patterns(hex_benign_file, bytes_to_read, scan_mode)
        combined_patterns = malicious_patterns + benign_patterns

        files_scanned, num_benign, num_malware, num_unknown = compare_hex_signatures(directory_to_scan,
                                                                                     combined_patterns, bytes_to_read)

        duration = time.time() - start_time
        print(f"{bytes_to_read}, {files_scanned}, {num_malware}, {num_benign}, {num_unknown}, {duration:.2f}")
        logger.info(f"{bytes_to_read}, {files_scanned}, {num_malware}, {num_benign}, {num_unknown}, {duration:.2f}")


if __name__ == "__main__":
    main()
