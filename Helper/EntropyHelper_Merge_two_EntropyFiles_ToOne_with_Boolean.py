import csv

def merge_with_boolean_and_column_value_skip_header(input_file_paths, output_file_path, column_index):
    with open(output_file_path, mode='w', newline='') as outfile:
        writer = csv.writer(outfile)
        # Process the first file with boolean 1
        with open(input_file_paths[0], newline='') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip header
            for row in reader:
                if len(row) > column_index:
                    writer.writerow([row[0], 1, row[column_index]])
        # Process the second file with boolean 0
        with open(input_file_paths[1], newline='') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip header
            for row in reader:
                if len(row) > column_index:
                    writer.writerow([row[0], 0, row[column_index]])

# Example usage
input_file_paths = ['../DataExchange/datafile_entropy_malicious_header_1-1000.csv', '../DataExchange/datafile_entropy_benign_header_1-1000.csv']  # Input file paths
output_file_path = '../DataExchange/datafile_entropy_header_500.csv'  # Output file path


# To merge data with the specified column index, skipping headers
column_index = 500  # Adjust based on the column you're interested in (remember it's 0-indexed)
merge_with_boolean_and_column_value_skip_header(input_file_paths, output_file_path, column_index)
