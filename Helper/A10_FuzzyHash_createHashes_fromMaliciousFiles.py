import ssdeep
import os
import csv
import logging

# Configure logging
logging.basicConfig(filename='logfiles/hash_generation.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def generate_fuzzy_hashes(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    fuzzy_hash = ssdeep.hash(content)
                    hashes[file_path] = fuzzy_hash
                    logging.info(f"Hash generated for {file_path}")
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {str(e)}")
    return hashes

def save_hashes_to_csv(hashes, csv_file_path):
    with open(csv_file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['file_path', 'hash'])
        for path, hash_value in hashes.items():
            writer.writerow([path, hash_value])
    logging.info(f"Hashes saved to {csv_file_path}")

folder_a = '/home/cs20m039/thesis/dataset/malicious/'
csv_file_path = 'BinaryFileScanning/folder_a_hashes.csv'

hashes_a = generate_fuzzy_hashes(folder_a)
save_hashes_to_csv(hashes_a, csv_file_path)
