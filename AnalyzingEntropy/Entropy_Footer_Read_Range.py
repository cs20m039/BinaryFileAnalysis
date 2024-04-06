import os
import csv
import math
import logging
from multiprocessing import Pool, cpu_count

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

START_BYTE = 10000
END_BYTE = 11000
STEP = 1

MALICIOUS_FILE = "/home/cs20m039/thesis/dataset1/malicious"
BENIGN_FILE = "/home/cs20m039/thesis/dataset1/benign"
MALICIOUS_OUTPUT_CSV = f"../DataExchange/datafile_entropy_footer_malicious_{START_BYTE}-{END_BYTE}.csv"
BENIGN_OUTPUT_CSV = f"../DataExchange/datafile_entropy_footer_benign_{START_BYTE}-{END_BYTE}.csv"

def shannon_entropy(data):
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_hash_from_filepath(filepath):
    filename = os.path.basename(filepath)
    hash_value = filename.split('.')[0]
    return hash_value

def calculate_entropy_for_file(file_path, start_byte, end_byte, step):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            file_length = len(data)
            entropy_values = []
            for current_start_byte in range(start_byte, end_byte + 1, step):
                segment_start_index = max(file_length - current_start_byte, 0)
                segment = data[segment_start_index:]
                if segment:
                    entropy_value = shannon_entropy(segment)
                    entropy_values.append(entropy_value)
                else:
                    entropy_values.append('')
            hash_value = extract_hash_from_filepath(file_path)
            return [hash_value] + entropy_values
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return []

def worker_task(args):
    return calculate_entropy_for_file(*args)

def calculate_and_write_entropy_parallel(directory, csv_file_path, start_byte, end_byte, step):
    args_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            args_list.append((file_path, start_byte, end_byte, step))

    num_processes = cpu_count()

    with Pool(processes=num_processes) as pool:
        results = pool.map(worker_task, args_list)

    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = ['Hash'] + [f'Entropy{i}' for i in range(start_byte, end_byte + 1, step)]
        csvwriter.writerow(headers)
        for result in results:
            if result:  # Ensure the result is not empty
                csvwriter.writerow(result)

calculate_and_write_entropy_parallel(MALICIOUS_FILE, MALICIOUS_OUTPUT_CSV, START_BYTE, END_BYTE, STEP)
calculate_and_write_entropy_parallel(BENIGN_FILE, BENIGN_OUTPUT_CSV, START_BYTE, END_BYTE, STEP)
