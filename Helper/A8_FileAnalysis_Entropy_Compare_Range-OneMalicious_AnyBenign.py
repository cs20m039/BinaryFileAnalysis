import csv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO,  # Adjust as needed
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('logfiles/comparison_output.log', mode='w'),
                        logging.StreamHandler()
                    ])

def read_entropy_values_with_files(csv_path):
    """Read entropy values and corresponding file paths from a CSV file."""
    logging.debug(f"Opening CSV file: {csv_path}")
    entropy_files = {}  # Initialize to ensure a return value
    try:
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csvreader = csv.reader(csvfile)
            headers = next(csvreader)[1:]  # Assumes first row is headers and skips 'File Path'
            entropy_files = {header: {} for header in headers}
            for row in csvreader:
                file_path = row[0]
                for header, value in zip(headers, row[1:]):
                    if value:  # Ensure the value is not empty
                        value = float(value)
                        if value not in entropy_files[header]:
                            entropy_files[header][value] = [file_path]
                        else:
                            entropy_files[header][value].append(file_path)
    except Exception as e:
        logging.error(f"Error reading CSV file {csv_path}: {e}")
    return entropy_files

def compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign):
    """Compare entropy values from malicious dataset with all values from benign dataset,
    focusing on exact matches. Logs the count of matching benign files and their paths."""
    logging.info("Starting comparison of entropy values...")
    for header in entropy_files_malicious:
        logging.info(f"Processing {header}:")
        for value_malicious, files_malicious in entropy_files_malicious[header].items():
            logging.debug(f"Checking malicious value: {value_malicious}")
            if value_malicious in entropy_files_benign[header]:
                files_benign = entropy_files_benign[header][value_malicious]
                count_benign = len(files_benign)

                logging.info(f"{header} - Entropy Value: {value_malicious} - Match found with {count_benign} benign files.")
                for file_malicious in files_malicious:
                    logging.debug(f"  - Malicious File: {file_malicious}")
                for file_benign in files_benign:
                    logging.debug(f"  - Benign File: {file_benign}")
            else:
                logging.debug(f"Entropy Value: {value_malicious} - No match found in benign files.")
    logging.info("Comparison of entropy values completed.")

# Main execution
if __name__ == "__main__":
    # Adjust these file paths according to your environment
    MALICIOUS_INPUT_CSV = "datashare/entropy_values_malicious_firstBytes.csv"
    BENIGN_INPUT_CSV = "datashare/entropy_values_benign_firstBytes.csv"

    entropy_files_malicious = read_entropy_values_with_files(MALICIOUS_INPUT_CSV)
    entropy_files_benign = read_entropy_values_with_files(BENIGN_INPUT_CSV)

    if entropy_files_malicious is not None and entropy_files_benign is not None:
        compare_entropy_values_and_print_files(entropy_files_malicious, entropy_files_benign)
    else:
        logging.error("Failed to read one or both CSV files. Exiting.")
