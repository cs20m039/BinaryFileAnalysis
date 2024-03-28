import csv
import os

def read_bytes_of_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read up to the first 290 bytes
            bytes_read = file.read(290)
            # Convert the first 290 bytes to hexadecimal representation
            hex_representation = bytes_read.hex()
            return hex_representation
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return ''

def analyze_files_recursive(directory_path, csv_path):
    # Open CSV file to write
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Prepare the header row for 290 bytes only
        headers = ['File Path', '290 Bytes']
        writer.writerow(headers)

        # Walk through all subdirectories
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                if os.path.isfile(full_path):
                    hex_representation = read_bytes_of_file(full_path)
                    # Write the relative path of the file and the hex data for the first 290 bytes to the CSV
                    row = [relative_path := os.path.relpath(full_path, directory_path), hex_representation]
                    writer.writerow(row)

# Example usage
directory_path = '/home/cs20m039/thesis/dataset'  # Change this to your directory's path
csv_path = 'output_290_bytes.csv'  # Adjust the CSV file name as needed
analyze_files_recursive(directory_path, csv_path)
