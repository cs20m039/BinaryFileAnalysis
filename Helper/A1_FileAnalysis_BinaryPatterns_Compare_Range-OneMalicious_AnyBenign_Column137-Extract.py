#extrahiert die ersten 137 byte aus dem csv file und fügt vorher den hash vom origin file ein boolean hinzu


import csv
import logging
import os

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def extract_sha256(filename):
    """Extracts the SHA256 hash from a filename."""
    return os.path.splitext(os.path.basename(filename))[0]


def read_columns_from_csv(csv_path, column_indices):
    """Reads specific columns from a CSV file."""
    columns_values = []
    try:
        with open(csv_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip the header row
            for row in reader:
                try:
                    values = [extract_sha256(row[i]) for i in column_indices]  # Extract SHA256 from specified columns
                    columns_values.append(values)
                except IndexError:
                    # Log a warning if the row does not have enough columns
                    logging.warning(f"Row with insufficient columns: {row}")
    except FileNotFoundError:
        logging.error(f"File not found: {csv_path}")
    except Exception as e:
        logging.error(f"An error occurred while reading {csv_path}: {e}")

    return columns_values


# Specify the CSV file paths
input_csv_file_path = "datashare/data_headerSignature_benignFiles_varyingLengths.csv"
output_csv_file_path = "output_headerSignature_values_137_benigndata.csv"  # Output file path
column_indices = [0, 134]  # Columns for SHA256 hash and 137Byte

# Read the values from the specified columns
columns_values = read_columns_from_csv(input_csv_file_path, column_indices)

# Write the values to a new CSV file
with open(output_csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    for values in columns_values:
        sha256_value = values[0]
        binary_pattern = values[1]
        writer.writerow([sha256_value, '0', binary_pattern])  # Each set of values is written to a new row with boolean 1

logging.info(f"Column values have been written to {output_csv_file_path}")
