import csv
import logging
import math
import os
import time
from collections import defaultdict
import numpy as np
from scipy.cluster.hierarchy import fclusterdata

# Configuration
LOG_FILE = 'logfiles/entropy_analysis.log'
PARENT_DIRECTORY = "/home/cs20m039/thesis/dataset/malicious"
#PARENT_DIRECTORY = "/home/cs20m039/thesis/dataset/benign/data"
#PARENT_DIRECTORY = "/home/cs20m039/thesis/dataset/benign/system"
ANALYZE_FULL_FILE = False
BYTES_TO_READ = 350
CSV_FILE_PATH_TEMPLATE = 'datashare/entropy_{}.csv'  # Template for naming CSV files

# Setup logging
logging.basicConfig(filename=LOG_FILE, filemode='w', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def calculate_entropy(file_content):
    """Calculate the Shannon entropy of given file content."""
    if not file_content:
        return 0
    frequency = defaultdict(int)
    for byte in file_content:
        frequency[byte] += 1
    entropy = -sum((freq / len(file_content)) * math.log2(freq / len(file_content)) for freq in frequency.values())
    return entropy

def scan_and_calculate_entropy(directory, analyze_full_file, bytes_to_read):
    """Scan directory and subdirectories, calculate entropy for each file."""
    entropy_values = []
    for root, _, files in os.walk(directory):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    bytes_ = f.read() if analyze_full_file else f.read(bytes_to_read)
                entropy = calculate_entropy(bytes_)
                logging.debug(f"File: {file_path}, Entropy: {entropy}")
                entropy_values.append((file_path, entropy))
            except Exception as e:
                logging.error(f"Error processing {file_path}: {e}")
    return entropy_values

def cluster_entropies(entropy_values):
    """Cluster entropy values."""
    if not entropy_values:
        return {}
    entropies = np.array([entropy for _, entropy in entropy_values]).reshape(-1, 1)
    labels = fclusterdata(entropies, t=1, criterion='distance', metric='euclidean')
    clustered = defaultdict(list)
    for label, value in zip(labels, entropy_values):
        clustered[label].append(value)
    return clustered

def write_to_csv(clustered_entropies, output_file):
    """Write entropy values and their clusters to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Cluster', 'File Path', 'Entropy'])
        for cluster, values in sorted(clustered_entropies.items()):
            for file_path, entropy in values:
                writer.writerow([cluster, file_path, entropy])

if __name__ == "__main__":
    start_time = time.time()
    for subfolder_name in os.listdir(PARENT_DIRECTORY):
        subfolder_path = os.path.join(PARENT_DIRECTORY, subfolder_name)
        if os.path.isdir(subfolder_path):  # Ensure it's a directory
            logging.info(f"Processing directory: {subfolder_path}")
            entropy_values = scan_and_calculate_entropy(subfolder_path, ANALYZE_FULL_FILE, BYTES_TO_READ)
            clustered = cluster_entropies(entropy_values)
            csv_file_path = CSV_FILE_PATH_TEMPLATE.format(subfolder_name.replace(" ", "_").lower())
            write_to_csv(clustered, csv_file_path)
            logging.info(f"Results saved to '{csv_file_path}'.")
    elapsed_time = time.time() - start_time
    logging.info(f"Total execution time: {elapsed_time:.2f} seconds.")
    print(f"Finished processing. Total execution time: {elapsed_time:.2f} seconds.")
