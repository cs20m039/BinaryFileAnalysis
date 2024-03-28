# Magic Byte Analysis
# All files in a specified folder and its subfolders are analysed according to their file type.
#
# @author Markus Rathkolb
# @version 2024-01-30
# @since 2023-03-05

from tika import parser
import os
import csv


def search_file_types(directory, specific_types_csv_path, other_types_csv_path):
    """
    Searches all folders and subfolders of the given directory for the type of their files using Apache Tika.
    Prints the file path and its MIME type to both the console and writes them to two separate CSV files:
    one for specified MIME types ('application/octet-stream', 'application/x-msdownload', 'application/x-executable')
    and another for all other MIME types.
    """
    if not os.path.isdir(directory):
        print(f"Directory {directory} does not exist.")
        return

    specific_types = ['application/octet-stream', 'application/x-msdownload', 'application/x-executable']

    with open(specific_types_csv_path, mode='w', newline='') as specific_csv_file, \
            open(other_types_csv_path, mode='w', newline='') as other_csv_file:

        specific_writer = csv.writer(specific_csv_file)
        other_writer = csv.writer(other_csv_file)

        # Writing the header of the CSV files
        specific_writer.writerow(['File Path', 'MIME Type'])
        other_writer.writerow(['File Path', 'MIME Type'])

        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    # Use Tika to parse the file
                    parsed = parser.from_file(file_path)
                    mime_type = parsed.get("metadata", {}).get("Content-Type", "Unknown")
                    print(f"File: {file_path}, MIME type: {mime_type}")

                    # Determine which CSV file to write to based on MIME type
                    if mime_type in specific_types:
                        specific_writer.writerow([file_path, mime_type])
                    else:
                        other_writer.writerow([file_path, mime_type])

                except Exception as e:
                    print(f"Error parsing document {file_path}: {str(e)}")
                    # Writing error indication to both CSVs, as it's unclear which category it falls into without MIME type
                    specific_writer.writerow([file_path, "Error parsing document"])
                    other_writer.writerow([file_path, "Error parsing document"])


# Example usage
if __name__ == "__main__":
    directory_path = "/home/cs20m039/thesis/dataset/malicious"  # Change this to your directory path
    specific_types_csv_path = "/home/cs20m039/specific_file_types_2024.csv"  # Path for specific MIME types CSV
    other_types_csv_path = "/home/cs20m039/other_file_types_2024.csv"  # Path for other MIME types CSV
    search_file_types(directory_path, specific_types_csv_path, other_types_csv_path)
