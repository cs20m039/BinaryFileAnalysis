import csv
import datetime
import logging

# Adjust based on the mode used for generating CSVs
READ_MODE = 'both'  # Can be 'header', 'footer', or 'both'
MALICIOUS_INPUT_CSV = f"../DataExchange/datafile_signature_malicious_{READ_MODE}_1-400.csv"
BENIGN_INPUT_CSV = f"../DataExchange/datafile_signature_benign_{READ_MODE}_1-400.csv"

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE_PATH = f'../Logfiles/log_bytes_compare_{timestamp}.log'

logging.basicConfig(level=logging.DEBUG,  # Changed to DEBUG for verbosity
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE_PATH, mode='w'),
                        logging.StreamHandler()
                    ])


def read_byte_sequences_with_hashes(csv_path):
    logging.debug(f"Attempting to open CSV file: {csv_path}")
    byte_sequences_hashes = {}
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            headers = next(csvreader)[1:]  # Assumes 'FileHash' is the first column
            byte_sequences_hashes = {header: {} for header in headers}
            for row in csvreader:
                file_hash = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:
                        if value not in byte_sequences_hashes[header]:
                            byte_sequences_hashes[header][value] = [file_hash]
                        else:
                            byte_sequences_hashes[header][value].append(file_hash)
        logging.debug(f"Successfully read and processed {csv_path}")
    except Exception as e:
        logging.error(f"Error reading or processing CSV file {csv_path}: {e}")
    return byte_sequences_hashes


def compare_byte_sequences_and_print_hashes(byte_sequences_hashes_malicious, byte_sequences_hashes_benign, read_mode):
    logging.info(f"Starting comparison of byte sequences in {read_mode} mode...")
    for header in byte_sequences_hashes_malicious:
        match_found = False
        for sequence, hashes_malicious in byte_sequences_hashes_malicious[header].items():
            if sequence in byte_sequences_hashes_benign.get(header, {}):
                match_found = True
                hashes_benign = byte_sequences_hashes_benign[header][sequence]
                logging.info(
                    f"{header} - Byte Sequence: {sequence} - Match ({len(hashes_malicious)} malicious, {len(hashes_benign)} benign matches)")
        if not match_found:
            logging.debug(f"No matches found for {header} in {read_mode} mode.")


def compare_header_footer_combined(byte_sequences_hashes_malicious, byte_sequences_hashes_benign):
    logging.info("Starting combined header and footer byte sequence comparison...")

    # Extract header and footer byte sequence information
    headers_malicious = byte_sequences_hashes_malicious.get('ByteHeader', {})
    footers_malicious = byte_sequences_hashes_malicious.get('ByteFooter', {})
    headers_benign = byte_sequences_hashes_benign.get('ByteHeader', {})
    footers_benign = byte_sequences_hashes_benign.get('ByteFooter', {})

    for header_sequence in headers_malicious:
        if header_sequence in headers_benign:
            for footer_sequence in footers_malicious:
                if footer_sequence in footers_benign:
                    # For each matching header sequence, find the intersection of file hashes between malicious and benign
                    matching_header_hashes_malicious = set(headers_malicious[header_sequence])
                    matching_header_hashes_benign = set(headers_benign[header_sequence])
                    # Do the same for footer sequences
                    matching_footer_hashes_malicious = set(footers_malicious[footer_sequence])
                    matching_footer_hashes_benign = set(footers_benign[footer_sequence])

                    # Find common file hashes across both header and footer, for both datasets
                    common_hashes_malicious = matching_header_hashes_malicious.intersection(
                        matching_footer_hashes_malicious)
                    common_hashes_benign = matching_header_hashes_benign.intersection(matching_footer_hashes_benign)

                    if common_hashes_malicious and common_hashes_benign:
                        logging.info(
                            f"1ByteHeader - Byte Sequence: {header_sequence} - Match ({len(common_hashes_malicious)} malicious, {len(common_hashes_benign)} benign matches) "
                            f"and 1ByteFooter - Byte Sequence: {footer_sequence} - Match ({len(common_hashes_malicious)} malicious, {len(common_hashes_benign)} benign matches)")

def report_combined_header_footer_matches(byte_sequences_hashes_malicious, byte_sequences_hashes_benign):
    logging.info("Reporting combined header and footer matches...")

    # Iterate over malicious header byte sequences and their corresponding file hashes
    for header_sequence, hashes_malicious in byte_sequences_hashes_malicious.get('ByteHeader', {}).items():
        # Check if the same byte sequence exists in the benign headers and get the intersection of file hashes
        if header_sequence in byte_sequences_hashes_benign.get('ByteHeader', {}):
            for footer_sequence, hashes_malicious_footer in byte_sequences_hashes_malicious.get('ByteFooter', {}).items():
                # Ensure the same byte sequence exists in the benign footers
                if footer_sequence in byte_sequences_hashes_benign.get('ByteFooter', {}):
                    # Now check for any file hash that has both matching header and footer sequences across datasets
                    matching_hashes_malicious = set(hashes_malicious)
                    matching_hashes_benign_header = set(byte_sequences_hashes_benign['ByteHeader'][header_sequence])
                    matching_hashes_benign_footer = set(byte_sequences_hashes_benign['ByteFooter'][footer_sequence])

                    # Only report if there are matches in both header and footer for the same sequence
                    if matching_hashes_malicious & matching_hashes_benign_header and matching_hashes_malicious & matching_hashes_benign_footer:
                        logging.info(f"1ByteHeader - Byte Sequence: {header_sequence} - Match ({len(matching_hashes_malicious)} malicious, {len(matching_hashes_benign_header)} benign matches) "
                                     f"- 1ByteFooter - Byte Sequence: {footer_sequence} - Match ({len(matching_hashes_malicious)} malicious, {len(matching_hashes_benign_footer)} benign matches)")

# Main execution
if __name__ == "__main__":
    byte_sequences_hashes_malicious = read_byte_sequences_with_hashes(MALICIOUS_INPUT_CSV)
    byte_sequences_hashes_benign = read_byte_sequences_with_hashes(BENIGN_INPUT_CSV)

    if byte_sequences_hashes_malicious and byte_sequences_hashes_benign:
        compare_byte_sequences_and_print_hashes(byte_sequences_hashes_malicious, byte_sequences_hashes_benign, READ_MODE)
        report_combined_header_footer_matches(byte_sequences_hashes_malicious, byte_sequences_hashes_benign)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
