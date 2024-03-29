import ssdeep
import os
import csv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def hash_files_in_directory(directory_path):
    """
    Hash all files in the specified directory, including subdirectories.
    Returns a list of tuples (file path, fuzzy hash).
    """
    file_hashes = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                file_hash = ssdeep.hash(file_content)
                file_hashes.append((file_path, file_hash))
                logging.info(f'Hashed {file_path}')
            except Exception as e:
                logging.error(f'Error hashing {file_path}: {e}')
    return file_hashes


def write_hashes_to_csv(file_hashes, csv_file):
    """
    Writes the file hashes to a CSV file.
    """
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['file_path', 'hash']
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)
        for file_path, file_hash in file_hashes:
            writer.writerow([file_path, file_hash])


if __name__ == '__main__':
    directory = '/home/cs20m039/thesis/dataset/malicious/'  # Replace with the path to directory A
    hashes_csv = 'datashare/hashes_malicious.csv'

    # Hash files in directory A
    logging.info('Hashing files in directory A...')
    hashes_a = hash_files_in_directory(directory)

    # Write hashes to CSV
    logging.info(f'Writing hashes to {hashes_csv}...')
    write_hashes_to_csv(hashes_a, hashes_csv)
