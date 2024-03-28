import csv
import os


def read_bytes_of_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read the first 5 bytes
            first_5_bytes = file.read(5)
            # Move to the end of the file to read the last 5 bytes
            file.seek(0, os.SEEK_END)  # Go to the end of the file
            file_size = file.tell()
            if file_size >= 10:
                file.seek(-5, os.SEEK_END)
            else:
                # If the file is smaller than 10 bytes, start from the beginning again
                file.seek(0)
            last_5_bytes = file.read(5)

        # Return the hexadecimal representation of the bytes
        return first_5_bytes.hex(), last_5_bytes.hex()
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None, None


def analyze_files_recursive(directory_path, csv_path):
    # Open CSV file to write
    with open(csv_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['File Path', 'First 5 Bytes', 'Last 5 Bytes'])

        # Walk through all subdirectories
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                if os.path.isfile(full_path):
                    first_5_bytes, last_5_bytes = read_bytes_of_file(full_path)
                    if first_5_bytes is not None:
                        # Write the relative path of the file to the CSV
                        relative_path = os.path.relpath(full_path, directory_path)
                        writer.writerow([relative_path, first_5_bytes, last_5_bytes])


# Example usage
directory_path = '/home/cs20m039/thesis/dataset/malicious'  # Change this to your directory's path
csv_path = 'output_bytes_recursive.csv'  # The path where you want to save the CSV
analyze_files_recursive(directory_path, csv_path)
