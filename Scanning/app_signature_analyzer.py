import csv
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path

# Get: current date and time
current_datetime = datetime.now()

# Format: current date and time as a string
datetime_str = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")

# Application Paths
log_file_name = f'binary_signature_analyzer_{datetime_str}.log'
binary_signatures_csv = "datafile_signature-test.csv"  # Format: SHA256,bool,binary_signature
bytes_to_read = 137

if platform.system() == 'Windows':
    username = os.environ.get('USERNAME')  # Username for Windows
    directory_to_scan = "C:\\"  # Customise: target directory for Windows
    exclusion_directories = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData',
                             f'C:\\Users\\{username}\\AppData']
elif platform.system() == 'Darwin':  # macOS
    directory_to_scan = "/"  # Customise: target directory for macOS
    exclusion_directories = ['/System', '/Library', os.path.expanduser('~/Library'), '/sbin', '/usr/bin', '/usr/sbin',
                             '/Volumes', '/private', '/.Spotlight-V100', '/.fseventsd', '/dev']
elif platform.system() == 'Linux':
    directory_to_scan = "/"  # Customise: target directory for Linux
    exclusion_directories = ['/sys/kernel/security']
  #  exclusion_directories = ['/sys', '/proc', '/dev', '/snap']

# Logging
logging.basicConfig(filename=log_file_name,
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Logger instance
logger = logging.getLogger('binary_pattern_matcher')


def read_binary_signatures(csv_file):
    """Read binary signatures from CSV file"""
    csv_values = []
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                sha256_hash, boolean, binary_pattern = row
                csv_values.append((sha256_hash, boolean, binary_pattern))  # Tuple of (SHA256,bool,pattern)
        logger.info(f"Loaded {len(csv_values)} patterns from CSV.")
    except FileNotFoundError:
        logger.error(f"CSV file does not exist: {csv_file}")
        print(f"Error: The specified CSV file does not exist: {csv_file}")
        sys.exit(1)  # Terminate the script with an error status
    except Exception as e:
        logger.error(f"Failed to read patterns from {csv_file}: {e}")
        print(f"Error: Failed to read patterns from {csv_file}. Exception: {e}")
        sys.exit(1)  # Terminate the script with an error status
    return csv_values


def compare_file_header(file_path, patterns):
    """Check if the first 137 bytes of the scanned files match any binary patterns from the CSV"""
    try:
        with open(file_path, 'rb') as file:
            file_header = file.read(bytes_to_read).hex()  # Read and convert to hex
            for sha256_hash, boolean, pattern in patterns:
                if file_header.startswith(pattern):
                    logger.debug(f"Match found for: {file_path}, Pattern: {pattern}, Boolean: {boolean}")
                    return sha256_hash, boolean, pattern  # Return the SHA256 hash, boolean, and pattern that matched
            logger.debug(f"No match for: {file_path}")  # Log when no match is found
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
    return None  # Return None if no pattern matches


def compare_signatures(directory, patterns):
    """Scan directory for files with headers matching binary patterns."""
    if not Path(directory).exists():
        logger.error(f"Directory does not exist: {directory}")
        return 0, 0, 0, 0

    malware_count = 0
    benign_count = 0
    unknown_count = 0
    files_analyzed = 0

    for root, dirs, files in os.walk(directory, followlinks=False):
        if any(os.path.abspath(root).startswith(ex_dir) for ex_dir in exclusion_directories):
            logger.debug(f"Skipping directory: {root}")
            continue

        sys.stdout.write(f'\rScanning: {root[:70]}...')  # Dynamic console output
        sys.stdout.flush()

        for file in files:  # Correct placement inside the os.walk loop
            file_path = Path(root) / file
            if file_path.is_symlink() or not file_path.is_file():
                continue

            try:
                files_analyzed += 1
                match_result = compare_file_header(file_path, patterns)
                if match_result is not None:
                    sha256_hash, boolean, matching_pattern = match_result
                    if boolean == '1':
                        malware_count += 1
                        logger.debug(f"Malware found: {file_path}, SHA256={sha256_hash}, Pattern={matching_pattern}")
                    elif boolean == '0':
                        benign_count += 1
                        logger.debug(
                            f"Benign file found: {file_path}, SHA256={sha256_hash}, Pattern={matching_pattern}")
                    else:
                        unknown_count += 1
                        logger.debug(
                            f"Unknown file type for: {file_path}, SHA256={sha256_hash}, Boolean={boolean}, Pattern={matching_pattern}")
                else:
                    # If no pattern matches, treat as unknown
                    unknown_count += 1
                    logger.debug(f"File does not match any known patterns: {file_path}")

            except PermissionError:
                logger.warning(f"Permission denied: {file_path}")

    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()

    logger.info(
        f"Scanning completed. Malware found: {malware_count}, Benign found: {benign_count}, Unknown found: {unknown_count}")
    return malware_count, benign_count, unknown_count, files_analyzed


if __name__ == "__main__":
    start_time = time.time()

    binary_patterns = read_binary_signatures(binary_signatures_csv)
    malware_count, benign_count, unknown_count, files_analyzed = compare_signatures(directory_to_scan, binary_patterns)

    duration = time.time() - start_time

    print(f"Directory to scan: {directory_to_scan}")
    print(f"Total files analyzed: {files_analyzed}")
    print(f"Ransomware found: {malware_count}")
    print(f"Benign found: {benign_count}")
    print(f"Unknown found: {unknown_count}")
    print(f"Scanning completed in {duration:.2f} seconds.")
