import csv
import logging
import os
import platform
import time
from datetime import datetime

import psutil

# Set up basic logging and paths
current_datetime = datetime.now()
datetime_str = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = f'signature_value_analyzer_{datetime_str}.log'
logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('signature_value_matcher')

# Data paths
hex_malicious_file = "Patterns/datafile_signature_malicious_both_1-600.csv"
hex_benign_file = "Patterns/datafile_signature_benign_both_1-600.csv"

signature_lengths = [10]
scan_mode = 'headers'  # Options: 'headers' or 'headers_footers'

directory = "/home/cs20m039/thesis/dataset3"
exclusions = []

if platform.system() == 'Windows':
    username = os.environ.get('USERNAME')
    directory = "C:\\"
    exclusions = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData',
                  f"C:\\Users\\{username}\\AppData"]
elif platform.system() == 'Darwin':
    exclusions = ['/System', '/Library', '/sbin', '/usr/bin', '/usr/sbin', '/Volumes', '/private', '/.Spotlight-V100',
                  '/.fseventsd', '/dev']
elif platform.system() == 'Linux':
    exclusions = ['/sys/kernel/security']
else:
    logger.warning("Platform not recognized, using default directory and no exclusions")

logger.info(f"Exclusions for {platform.system()}: {exclusions}")


def get_system_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    return memory.percent, cpu_percent


def read_patterns(csv_file, num_bytes, mode):
    csv_values = []
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                file_hash = row['FileName']
                if mode == 'headers':
                    pattern = row.get(f"Header{num_bytes}", "")
                elif mode == 'headers_footers':
                    header = row.get(f"Header{num_bytes}", "")
                    footer = row.get(f"Footer{num_bytes}", "")
                    pattern = header + footer  # Concatenate header and footer

                    # Log for missing header or footer data
                    if not header or not footer:
                        logger.debug(
                            f"Missing header or footer for pattern at FileHash {file_hash}: Header({header}), Footer({footer})")

                malware_flag = 1 if 'malicious' in csv_file else 0
                csv_values.append((file_hash, pattern, malware_flag))
        logger.info(f"Loaded patterns from {csv_file} for {mode} {num_bytes}.")
    except Exception as e:
        logger.error(f"Failed to read patterns from {csv_file}: {e}")
    return csv_values


def extract_file_signatures(file_path, num_bytes, mode):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
            header_signature = file_content[:num_bytes].hex() if len(file_content) >= num_bytes else file_content.hex()
            footer_signature = file_content[-num_bytes:].hex() if len(file_content) >= num_bytes else ""
    except Exception as e:
        logger.error(f"Error extracting signatures from {file_path}: {e}")
        header_signature = ""
        footer_signature = ""

    return header_signature, footer_signature


def compare_signatures(directory, patterns, num_bytes, mode):
    matches = {"benign": [], "malware": [], "unknown": []}
    files_scanned = 0
    files_processed = 0  # Initialize files processed counter

    for root, dirs, files in os.walk(directory, topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclusions]  # Apply exclusions

        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1  # Count every file encountered

            # Check if the file exists and is readable
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                logger.error(f"Cannot access file: {file_path}")
                continue

            # Check if the file meets the minimum size requirement
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1200:  # Skip files that are too small to process
                    continue

                header_signature, footer_signature = extract_file_signatures(file_path, num_bytes, mode)

                if header_signature or footer_signature:  # Check if signatures were successfully extracted
                    files_processed += 1  # Count as processed only if signatures are extracted
                    combined_signature = header_signature + footer_signature if mode == 'headers_footers' else header_signature

                    match_found = False
                    for file_hash, pattern, flag in patterns:
                        if combined_signature.startswith(pattern):
                            category = "malware" if flag == 1 else "benign"
                            matches[category].append((file_path, file_hash))
                            logger.debug(
                                f"Match found: {file_path} classified as {category} using pattern from {file_hash}")
                            match_found = True
                            break

                    if not match_found:
                        matches["unknown"].append((file_path, None))
                        logger.debug(f"No match for {file_path}")

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")

    return files_scanned, files_processed, len(matches['benign']), len(matches['malware']), len(matches['unknown'])


def main():
    print(f"Directory to scan: {directory}")
    print("Pattern, Total Scanned, Total Processed, Malware, Benign, Unknown, Time, Memory Usage (%), CPU Usage (%)")

    # Data structure to hold results
    data = {'Pattern': [], 'Total Scanned': [], 'Total Processed': [], 'Malware': [],
            'Benign': [], 'Unknown': [], 'Time': [], 'Memory Usage (%)': [], 'CPU Usage (%)': []}

    for length in signature_lengths:
        bytes_to_read = length
        start_time = time.time()

        # Log system usage before processing patterns
        memory_usage_before, cpu_usage_before = get_system_usage()

        malicious_patterns = read_patterns(hex_malicious_file, bytes_to_read, scan_mode)
        benign_patterns = read_patterns(hex_benign_file, bytes_to_read, scan_mode)
        combined_patterns = malicious_patterns + benign_patterns

        files_scanned, files_processed, num_benign, num_malware, num_unknown = compare_signatures(
            directory, combined_patterns, bytes_to_read, scan_mode)

        # Log system usage after processing
        memory_usage_after, cpu_usage_after = get_system_usage()

        duration = time.time() - start_time
        avg_memory_usage = (memory_usage_before + memory_usage_after) / 2
        avg_cpu_usage = (cpu_usage_before + cpu_usage_after) / 2

        # Print results for each pattern
        print(f"{bytes_to_read}, {files_scanned}, {files_processed}, {num_malware}, {num_benign}, {num_unknown}, "
              f"{duration:.2f}, {avg_memory_usage:.2f}, {avg_cpu_usage:.2f}")


if __name__ == "__main__":
    main()
