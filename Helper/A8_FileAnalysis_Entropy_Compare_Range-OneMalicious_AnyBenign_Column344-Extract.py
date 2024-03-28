import csv
import logging

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_columns_from_csv(csv_path, column_indexes):
    """Reads specific columns from a CSV file."""
    column_values = {index: [] for index in column_indexes}  # Initialize a dictionary to store the columns' values
    try:
        with open(csv_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip the header row
            for row in reader:
                for index in column_indexes:
                    try:
                        # Extract the value from the specified column index if it exists
                        value = row[index]
                        column_values[index].append(value)
                    except IndexError:
                        # Log a warning if the row does not have enough columns
                        logging.warning(f"Row with insufficient columns: {row}")
    except FileNotFoundError:
        logging.error(f"File not found: {csv_path}")
    except Exception as e:
        logging.error(f"An error occurred while reading {csv_path}: {e}")

    # Return the lists of values for the specified column indexes
    return [column_values[index] for index in column_indexes]

# Specify the CSV file paths
input_csv_file_path = "datashare/entropy_values_malicious_firstBytes.csv"
output_csv_file_path = "BinaryFileScanning/entropy_values.csv"  # Output file path

# Specify the column indexes to read
column_indexes = [0, 344]  # Columns 2 and 345 in 1-indexed terms

# column_index = 134  # For column 137 = 134 for binaryPattern or HeaderSignatures
#column_index = 344 # = 344 for Entropy

# Read the values from the specified columns
column1_values, column344_values = read_columns_from_csv(input_csv_file_path, column_indexes)

# Write the values to a new CSV file
with open(output_csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    for value1, value344 in zip(column1_values, column344_values):
        writer.writerow([value1, value344])  # Write both column values to a new row

logging.info(f"Column values have been written to {output_csv_file_path}")
