import csv
import datetime
import logging

# Constants for file paths
READ_MODE = 'both'  # Options: 'header', 'footer', 'both'
MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_signature_malicious_{READ_MODE}_1-400.csv"
BENIGN_INPUT_CSV = f"../DataExchange/datafile_signature_benign_{READ_MODE}_1-400.csv"
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_bytes_compare_{timestamp}.log'

# Setup logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])

def read_byte_sequences_with_hashes(csv_path):
    """Read byte sequences and their hashes from a CSV file."""
    try:
        with open(csv_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)[1:]  # Skip 'FileHash'
            byte_seq_hashes = {header: {} for header in headers}
            for row in reader:
                file_hash, *sequences = row
                for header, value in zip(headers, sequences):
                    if value:
                        byte_seq_hashes[header].setdefault(value, []).append(file_hash)
        logging.debug(f"Successfully processed {csv_path}")
        return byte_seq_hashes
    except Exception as e:
        logging.error(f"Failed processing {csv_path}: {e}")
        return {}

def compare_byte_sequences_and_log(byte_seq_hashes_mal, byte_seq_hashes_ben):
    """Compare byte sequences between malicious and benign datasets and log findings."""
    logging.info("Starting byte sequence comparison...")
    for header in byte_seq_hashes_mal:
        for seq, mal_hashes in byte_seq_hashes_mal[header].items():
            ben_hashes = byte_seq_hashes_ben.get(header, {}).get(seq, [])
            if ben_hashes:
                logging.info(f"{header} - Byte Sequence: {seq} - Matches found ({len(mal_hashes)} malicious, {len(ben_hashes)} benign)")

if __name__ == "__main__":
    mal_hashes = read_byte_sequences_with_hashes(MALICIOUS_INPUT_CSV)
    ben_hashes = read_byte_sequences_with_hashes(BENIGN_INPUT_CSV)
    if mal_hashes and ben_hashes:
        compare_byte_sequences_and_log(mal_hashes, ben_hashes)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
