import csv
import logging
import math
import os
import platform
import sys
import time
from datetime import datetime

# Get the current date and time
current_datetime = datetime.now()

# Format the current date and time as a string
datetime_str = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")

# Paths
log_file_name = f'entropy_value_analyzer_{datetime_str}.log'

entropy_malicious_file = "Patterns/datafile_entropy_malicious_both_1-600.csv"
entropy_benign_file = "Patterns/datafile_entropy_benign_both_1-600.csv"

signature_lengths = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500]
scan_mode = 'headers'  # Options: 'headers' or 'headers_footers'

if platform.system() == 'Windows':
    username = os.environ.get('USERNAME')
    directory_to_scan = "C:\\"
    exclusion_directories = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData',
                             f'C:\\Users\\{username}\\AppData']
elif platform.system() == 'Darwin':
    directory_to_scan = "/"
    exclusion_directories = ['/System', '/Library', os.path.expanduser('~/Library'), '/sbin', '/usr/bin', '/usr/sbin',
                             '/Volumes', '/private', '/.Spotlight-V100', '/.fseventsd', '/dev']
elif platform.system() == 'Linux':
    directory_to_scan = "/home/cs20m039/thesis/dataset1/"  # Customise: target directory for Linux
    exclusion_directories = ['/sys/kernel/security']
#  exclusion_directories = ['/sys', '/proc', '/dev', '/snap']

logging.basicConfig(filename=log_file_name, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('entropy_value_matcher')
logger.setLevel(logging.DEBUG)

def read_entropy_values(csv_file, bytes_to_read, mode, malware_flag):
    """Read entropy values from CSV file for the specified bytes and mode (headers only or headers and footers), tagging with malware flag."""
    csv_values = []
    header_col = f"Header{bytes_to_read}"
    footer_col = f"Footer{bytes_to_read}" if mode == "headers_footers" else None

    if not os.path.exists(csv_file):
        logger.error(f"CSV file does not exist: {csv_file}")
        sys.exit("Exiting due to missing CSV file.")

    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                file_hash = row['FileName']
                header_entropy = float(row[header_col])
                footer_entropy = float(row[footer_col]) if footer_col and row[footer_col] else None

                # Append with malware_flag
                csv_values.append((file_hash, header_entropy, footer_entropy, malware_flag))
        logger.info(f"Loaded entropy values for {bytes_to_read} bytes from {csv_file}.")
    except Exception as e:
        logger.error(f"Failed to read entropy values from {csv_file}: {e}")
    return csv_values



def calculate_file_entropy(file_path, bytes_to_read):
    """Calculate the entropy of the first `bytes_to_read` bytes of each scanned file, if it's a regular file and at least 500 bytes."""
    try:
        if not os.path.isfile(file_path):  # Check if the path is a regular file
            logger.debug(f"Skipping non-regular file: {file_path}")
            return None

        # Check if the file is at least 500 bytes
        if os.path.getsize(file_path) < 500:
            logger.debug(f"Skipping file due to size < 500 bytes: {file_path}")
            return None

        with open(file_path, 'rb') as f:
            byte_arr = [0] * 256
            file_bytes = f.read(bytes_to_read)
            if not file_bytes:
                return 0
            for byte in file_bytes:
                byte_arr[byte] += 1
            entropy = -sum(f / len(file_bytes) * math.log(f / len(file_bytes), 2) for f in byte_arr if f > 0)
            return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy for {file_path}: {e}")
        return None


def compare_entropy(directory, patterns):
    matches = {"benign": [], "malware": [], "unknown": []}
    files_scanned = 0
    files_processed = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        if any(os.path.abspath(root).startswith(ex_dir) for ex_dir in exclusion_directories):
            logger.debug(f"Skipping directory: {root}")
            continue

        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1
            if os.path.getsize(file_path) < 500:
                continue  # Skip small files

            files_processed += 1
            entropy = calculate_file_entropy(file_path, bytes_to_read)
            if entropy is None:
                continue

            match_found = False
            for file_hash, header_entropy, footer_entropy, flag in patterns:
                # Check if it's a header or both and compare entropy
                target_entropy = header_entropy if scan_mode == 'headers' else (header_entropy + footer_entropy) / 2
                if abs(entropy - target_entropy) < 0.000001: #3.443017689988497
                    category = "malware" if flag == 1 else "benign"
                    matches[category].append((file_path, entropy, file_hash))
                    match_found = True
                    break

            if not match_found:
                matches["unknown"].append((file_path, entropy, None))

    logger.info(f"Scanning completed. Files scanned: {files_scanned}, Files processed: {files_processed}, Matches found: {len(matches['benign'])} benign, {len(matches['malware'])} malware, and {len(matches['unknown'])} unknown.")
    return files_scanned, files_processed, matches




def main():
    start_time = time.time()
    print(f"Directory to scan: {directory_to_scan}")
    print("Pattern, Total Scanned, Processed, Malware, Benign, Unknown, Time")

    for length in signature_lengths:
        config_start_time = time.time()
        global bytes_to_read
        bytes_to_read = length

        # Process and tag malicious patterns
        malicious_patterns = read_entropy_values(entropy_malicious_file, bytes_to_read, scan_mode, 1)
        # Process and tag benign patterns
        benign_patterns = read_entropy_values(entropy_benign_file, bytes_to_read, scan_mode, 0)

        # Combine patterns to pass to the scanning function
        combined_patterns = malicious_patterns + benign_patterns

        files_scanned, files_processed, matches = compare_entropy(directory_to_scan, combined_patterns)
        config_duration = time.time() - config_start_time

        print(f"{bytes_to_read}, {files_scanned}, {files_processed}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {config_duration:.2f}")
        logger.info(f"{bytes_to_read}, {files_scanned}, {files_processed}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {config_duration:.2f}")

    duration = time.time() - start_time
    print(f"\nTotal scanning completed in {duration:.2f} seconds.")


if __name__ == "__main__":
    main()
