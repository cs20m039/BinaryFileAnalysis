import csv
import logging
import math
import os
import platform
import sys
import time
from datetime import datetime

import psutil

current_datetime = datetime.now()
datetime_str = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = f'entropy_value_analyzer_{datetime_str}.log'
logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('entropy_value_matcher')

entropy_malicious_file = "Patterns/datafile_entropy_malicious_both_1-600.csv"
entropy_benign_file = "Patterns/datafile_entropy_benign_both_1-600.csv"
signature_lengths = [50]
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


def read_entropy_values(csv_file, bytes_to_read, mode, malware_flag):
    csv_values = []
    header_col = f"Header{bytes_to_read}"
    footer_col = f"Footer{bytes_to_read}" if mode == "headers_footers" else None

    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                file_hash = row['FileName']
                header_entropy = float(row[header_col])
                footer_entropy = float(row[footer_col]) if footer_col and row[footer_col] else None
                csv_values.append((file_hash, header_entropy, footer_entropy, malware_flag))
        logger.info(f"Loaded entropy values for {bytes_to_read} bytes from {csv_file}.")
    except Exception as e:
        logger.error(f"Failed to read entropy values from {csv_file}: {e}")
        sys.exit("Exiting due to file read failure.")
    return csv_values


def calculate_file_entropy(file_path, bytes_to_read, footer=False):
    try:
        with open(file_path, 'rb') as file:
            if footer:
                file.seek(-bytes_to_read, os.SEEK_END)
            file_bytes = file.read(bytes_to_read)
            if not file_bytes:
                return None
            byte_arr = [0] * 256
            for byte in file_bytes:
                byte_arr[byte] += 1
            entropy = -sum(
                (count / len(file_bytes)) * math.log(count / len(file_bytes), 2) for count in byte_arr if count > 0)
            return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy for {file_path}: {e}")
        return None


def compare_entropy(directory, patterns, bytes_to_read):
    matches = {"benign": [], "malware": [], "unknown": []}
    files_scanned = 0
    files_processed = 0

    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclusions]  # Apply exclusions to directories
        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1

            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                logger.error(f"Cannot access file: {file_path}")
                continue

            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1200:  # Skip files that are too small to process
                    continue

                header_entropy = calculate_file_entropy(file_path, bytes_to_read)
                footer_entropy = calculate_file_entropy(file_path, bytes_to_read,
                                                        footer=True) if scan_mode == 'headers_footers' else None
                file_processed = False

                for file_hash, target_header_entropy, target_footer_entropy, flag in patterns:
                    header_match = abs(
                        header_entropy - target_header_entropy) < 0.000001 if header_entropy is not None else False
                    footer_match = abs(
                        footer_entropy - target_footer_entropy) < 0.000001 if footer_entropy is not None else False
                    match = header_match and footer_match if scan_mode == 'headers_footers' else header_match

                    if match:
                        category = "malware" if flag == 1 else "benign"
                        matches[category].append((file_path, header_entropy, footer_entropy, file_hash))
                        logger.debug(f"Match found: {file_path} classified as {category}.")
                        file_processed = True
                        break

                if not file_processed:
                    matches["unknown"].append((file_path, header_entropy, footer_entropy, None))
                    logger.debug(f"No match: {file_path}.")

                files_processed += 1

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {str(e)}")

    return files_scanned, files_processed, matches


def main():
    print(f"Directory to scan: {directory}")
    print("Pattern, Total Scanned, Total Processed, Malware, Benign, Unknown, Time, Memory Usage (%), CPU Usage (%)")

    data = {'Pattern': [], 'Total Scanned': [], 'Total Processed': [], 'Malware': [], 'Benign': [], 'Unknown': [],
            'Time': [], 'Memory Usage (%)': [], 'CPU Usage (%)': []}

    for length in signature_lengths:
        bytes_to_read = length

        start_time = time.time()

        memory_usage_before, cpu_usage_before = get_system_usage()
        malicious_patterns = read_entropy_values(entropy_malicious_file, bytes_to_read, scan_mode, 1)
        benign_patterns = read_entropy_values(entropy_benign_file, bytes_to_read, scan_mode, 0)
        combined_patterns = malicious_patterns + benign_patterns

        files_scanned, files_processed, matches = compare_entropy(directory, combined_patterns, bytes_to_read)

        memory_usage_after, cpu_usage_after = get_system_usage()

        duration = time.time() - start_time
        avg_memory_usage = (memory_usage_before + memory_usage_after) / 2
        avg_cpu_usage = (cpu_usage_before + cpu_usage_after) / 2

        print(
            f"{bytes_to_read}, {files_scanned}, {files_processed}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {duration:.2f}, {avg_memory_usage:.2f}, {avg_cpu_usage:.2f}")


if __name__ == "__main__":
    main()
