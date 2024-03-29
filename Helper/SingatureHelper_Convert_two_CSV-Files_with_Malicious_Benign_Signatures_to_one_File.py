import csv

# The paths to your input CSV files
csv_file_path1 = '../DataPreparation/extract_signature_malicious_137.csv'
csv_file_path2 = '../DataPreparation/extract_signature_benign_137.csv'

# The path to the output merged CSV file
merged_csv_file_path = '137.csv'

# Initialize a list to hold all the data, excluding headers
data_without_headers = []

# Open the first CSV file and read its contents, skipping the header
with open(csv_file_path1, mode='r', newline='') as file1:
    reader1 = csv.reader(file1)
    next(reader1, None)  # Skip the header row
    data_without_headers.extend(reader1)  # Read the rest

# Open the second CSV file and read its contents, also skipping the header
with open(csv_file_path2, mode='r', newline='') as file2:
    reader2 = csv.reader(file2)
    next(reader2, None)  # Skip the header row
    data_without_headers.extend(reader2)  # Read the rest

# Write the data, excluding headers, to the new merged CSV file
with open(merged_csv_file_path, mode='w', newline='') as merged_file:
    writer = csv.writer(merged_file)
    writer.writerows(data_without_headers)

print(f'Data from {csv_file_path1} and {csv_file_path2}, excluding headers, has been merged into {merged_csv_file_path}')
