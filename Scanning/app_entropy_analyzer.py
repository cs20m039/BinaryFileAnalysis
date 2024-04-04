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

# Format the current date and time as a string, for example, '2023-03-25_15-30-00'
datetime_str = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")

# Paths
log_file_name = f'entropy_value_analyzer_{datetime_str}.log'
#entropy_values_csv = 'Entropy/datafile_entropy_header_50.csv'  # Updated CSV format
#bytes_to_read = 50

entropy_scan_configs = [
    {"csv_file": "Entropy/datafile_entropy_header_50.csv", "bytes_to_read": 50},
    {"csv_file": "Entropy/datafile_entropy_header_100.csv", "bytes_to_read": 100},
    {"csv_file": "Entropy/datafile_entropy_header_150.csv", "bytes_to_read": 150},
    {"csv_file": "Entropy/datafile_entropy_header_200.csv", "bytes_to_read": 200},
    {"csv_file": "Entropy/datafile_entropy_header_250.csv", "bytes_to_read": 250},
    {"csv_file": "Entropy/datafile_entropy_header_300.csv", "bytes_to_read": 300},
    {"csv_file": "Entropy/datafile_entropy_header_350.csv", "bytes_to_read": 350},
    {"csv_file": "Entropy/datafile_entropy_header_400.csv", "bytes_to_read": 400},
    {"csv_file": "Entropy/datafile_entropy_header_450.csv", "bytes_to_read": 450},
    {"csv_file": "Entropy/datafile_entropy_header_500.csv", "bytes_to_read": 500},
]

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

# Logging configuration
logging.basicConfig(filename=log_file_name,
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('entropy_value_matcher')
logger.setLevel(logging.DEBUG)


def read_entropy_values(csv_file):
    """Read entropy values from CSV file, returning a list of tuples (hash, malware_flag, entropy_value)."""
    csv_values = []
    # Check if the file exists
    if not os.path.exists(csv_file):
        logger.error(f"CSV file does not exist: {csv_file}")
        sys.exit("Exiting due to missing CSV file.")

    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip the header row
            for row in reader:
                if len(row) == 3:  # Adjusted for three columns
                    file_hash = row[0]  # Hash of the origin file
                    try:
                        malware_flag = int(row[1])  # Try converting to int
                        if malware_flag not in [0, 1]:
                            raise ValueError("Malware flag must be 0 or 1")  # Ensure it's 0 or 1
                    except ValueError:
                        logger.error(
                            f"Malware flag is not valid (0 or 1 expected, got {row[1]}), treating as 'unknown'")
                        malware_flag = -1  # Use -1 or another unique value to represent 'unknown'
                    entropy_value = float(row[2])  # Entropy value
                    csv_values.append((file_hash, malware_flag, entropy_value))
        logger.info(f"Loaded {len(csv_values)} entropy values from CSV.")
    except Exception as e:
        logger.error(f"Failed to read entropy values from {csv_file}: {e}")
    return csv_values


def calculate_file_entropy(file_path):
    """Calculate the entropy of the first 137 bytes of each scanned file, if it's a regular file."""
    try:
        if not os.path.isfile(file_path):  # Check if the path is a regular file
            logger.debug(f"Skipping non-regular file: {file_path}")
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
    matches = {"benign": [], "malware": [], "unknown": [], "non_matching": 0}
    files_scanned = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        if any(os.path.abspath(root).startswith(ex_dir) for ex_dir in exclusion_directories):
            logger.debug(f"Skipping directory: {root}")
            continue

        sys.stdout.write(f'\rScanning: {root[:70]}...')
        sys.stdout.flush()

        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1

            try:
                entropy = calculate_file_entropy(file_path)
                match_found = False

                if entropy is not None:
                    for file_hash, malware_flag, target_entropy in patterns:
                        if abs(entropy - target_entropy) < 0.01:
                            if malware_flag is None:
                                logger.debug(f"Unknown found: {file_path}, SHA256={file_hash}, Pattern={file_hash}")
                                match_category = "unknown"
                            elif malware_flag == 1:
                                logger.debug(f"Malware found: {file_path}, SHA256={file_hash}, Pattern={file_hash}")
                                match_category = "malware"
                            elif malware_flag == 0:
                                logger.debug(f"Benign found: {file_path}, SHA256={file_hash}, Pattern={file_hash}")
                                match_category = "benign"
                            else:
                                logger.debug(f"Unknown malware flag for file {file_path}: {malware_flag}")
                                match_category = "unknown"

                            matches[match_category].append((file_path, entropy, file_hash))
                            match_found = True
                            break

                if not match_found:
                    matches["unknown"].append((file_path, entropy, None))  # Categorize non-matching files as "unknown"

            except Exception as e:
                logger.warning(f"Error for file {file_path}: {e}")

    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()

    logger.info(
        f"Scanning completed. Files scanned: {files_scanned}, Matches found: {len(matches['benign'])} benign, {len(matches['malware'])} malware, and {len(matches['unknown'])} unknown. Non-matching files: {matches['non_matching']}.")
    return files_scanned, matches


#entropy_patterns = read_entropy_values(entropy_values_csv)
#files_scanned, matches = compare_entropy(directory_to_scan, entropy_patterns)


def main():
    start_time = time.time()
    print(f"Directory to scan: {directory_to_scan}")
    print("Pattern, Total, Ransomware, Benign, Unknown, Time")

    for config in entropy_scan_configs:
        config_start_time = time.time()
        global bytes_to_read
        bytes_to_read = config["bytes_to_read"]

        #print(f"\nScanning with config: {config}")

        entropy_patterns = read_entropy_values(config["csv_file"])
        files_scanned, matches = compare_entropy(directory_to_scan, entropy_patterns)
        config_duration = time.time() - config_start_time
        #print(f"Directory to scan: {directory_to_scan}")
        #print(f"CSV File: {config['csv_file']}")
        #print(f"Bytes to read: {bytes_to_read}")
        #print(f"Total files analyzed: {files_scanned}")
        #print(f"Malware found: {len(matches['malware'])}")
        #print(f"Benign found: {len(matches['benign'])}")
        #print(f"Unknown found: {len(matches['unknown'])}")
        #print(f"Duration of this scan: {config_duration:.2f} seconds")
        print(f"{bytes_to_read}, {files_scanned}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {config_duration:.2f}")
        logger.info(f"{bytes_to_read}, {files_scanned}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {config_duration:.2f}")

    duration = time.time() - start_time
    print(f"\nTotal scanning completed in {duration:.2f} seconds.")


if __name__ == "__main__":
    main()
