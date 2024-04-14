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
logging.basicConfig(filename=log_file_name, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('entropy_value_matcher')
logger.setLevel(logging.DEBUG)

entropy_malicious_file = "Patterns/datafile_entropy_malicious_both_1-600.csv"
entropy_benign_file = "Patterns/datafile_entropy_benign_both_1-600.csv"
signature_lengths = [100, 200, 300, 400, 500]
scan_mode = 'headers_footers'  # Options: 'headers' or 'headers_footers'

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
    directory_to_scan = "/home/cs20m039/thesis/dataset1/"
    exclusion_directories = ['/sys/kernel/security']


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
        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1
            if os.path.getsize(file_path) < 1200:
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

    return files_scanned, files_processed, matches


def main():
    print("Pattern, Total Scanned, Processed, Malware, Benign, Unknown, Time, Memory Usage (%), CPU Usage (%)")

    data = {'Pattern': [], 'Total Scanned': [], 'Total Processed': [], 'Malware': [], 'Benign': [], 'Unknown': [],
            'Time': [], 'Memory Usage (%)': [], 'CPU Usage (%)': []}

    for length in signature_lengths:
        bytes_to_read = length

        start_time = time.time()

        memory_usage_before, cpu_usage_before = get_system_usage()
        malicious_patterns = read_entropy_values(entropy_malicious_file, bytes_to_read, scan_mode, 1)
        benign_patterns = read_entropy_values(entropy_benign_file, bytes_to_read, scan_mode, 0)
        combined_patterns = malicious_patterns + benign_patterns

        files_scanned, files_processed, matches = compare_entropy(directory_to_scan, combined_patterns, bytes_to_read)

        memory_usage_after, cpu_usage_after = get_system_usage()

        duration = time.time() - start_time
        avg_memory_usage = (memory_usage_before + memory_usage_after) / 2
        avg_cpu_usage = (cpu_usage_before + cpu_usage_after) / 2

        print(
            f"{bytes_to_read}, {files_scanned}, {files_processed}, {len(matches['malware'])}, {len(matches['benign'])}, {len(matches['unknown'])}, {duration:.2f}, {avg_memory_usage:.2f}, {avg_cpu_usage:.2f}")

        data['Pattern'].append(bytes_to_read)
        data['Total Scanned'].append(files_scanned)
        data['Total Processed'].append(files_processed)
        data['Malware'].append(len(matches['malware']))
        data['Benign'].append(len(matches['benign']))
        data['Unknown'].append(len(matches['unknown']))
        data['Time'].append(duration)
        data['Memory Usage (%)'].append(avg_memory_usage)
        data['CPU Usage (%)'].append(avg_cpu_usage)

    print("\nCompleted scan, summary of results:")
    for key in data:
        print(f"{key}: {data[key]}")

    # Export to CSV
    with open('entropy_scan_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(data.keys())
        writer.writerows(zip(*data.values()))


if __name__ == "__main__":
    main()
