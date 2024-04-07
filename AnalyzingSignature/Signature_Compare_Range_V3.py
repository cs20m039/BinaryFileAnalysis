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
    try:
        with open(csv_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)[1:]
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
    logging.info("Starting byte sequence comparison...")
    for header in byte_seq_hashes_mal:
        if "Header" in header:
            footer_key = header.replace("Header", "Footer")
            for seq, mal_hashes in byte_seq_hashes_mal[header].items():
                ben_hashes = byte_seq_hashes_ben.get(header, {}).get(seq, [])
                if not ben_hashes:  # If no benign matches for the header, skip this sequence.
                    continue

                footer_matches = byte_seq_hashes_mal.get(footer_key, {})
                for footer_seq, footer_mal_hashes in footer_matches.items():
                    footer_ben_hashes = byte_seq_hashes_ben.get(footer_key, {}).get(footer_seq, [])
                    if not footer_ben_hashes:  # If no benign matches for the footer, skip this sequence.
                        continue

                    # Check if the number of malicious and benign matches align for both header and footer.
                    if len(mal_hashes) == len(footer_mal_hashes) and len(ben_hashes) == len(footer_ben_hashes):
                        logging.info(
                            f"{header} - Byte Sequence: {seq} - Match ({len(mal_hashes)} malicious, {len(ben_hashes)} benign matches) - "
                            f"{footer_key} - Byte Sequence: {footer_seq} - Match ({len(footer_mal_hashes)} malicious, {len(footer_ben_hashes)} benign matches)")


if __name__ == "__main__":
    mal_hashes = read_byte_sequences_with_hashes(MALICIOUS_INPUT_CSV)
    ben_hashes = read_byte_sequences_with_hashes(BENIGN_INPUT_CSV)
    if mal_hashes and ben_hashes:
        compare_byte_sequences_and_log(mal_hashes, ben_hashes)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
