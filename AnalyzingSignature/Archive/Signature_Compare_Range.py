import csv


# Function to read CSV content into a dictionary
def read_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


# Load both CSV files
malicious_csv = read_csv('../DataExchange/datafile_signature_malicious_both_1-10.csv')
benign_csv = read_csv('../DataExchange/datafile_signature_benign_both_1-10.csv')

# Since headers are now the same, we directly use them for comparison
header_keys = [f'Header{i}' for i in range(1, 11)]  # Generate header keys
footer_keys = [f'Footer{i}' for i in range(1, 11)]  # Generate footer keys

# Iterate through each header and corresponding footer
for header_key, footer_key in zip(header_keys, footer_keys):
    # Iterate through each row of the malicious CSV
    for row_malicious in malicious_csv:
        # Find matching header value in benign CSV
        matching_rows_benign = [row_benign for row_benign in benign_csv if
                                row_benign[header_key] == row_malicious[header_key]]

        # For each match found, check the footer value
        for match in matching_rows_benign:
            if match[footer_key] == row_malicious[footer_key]:
                #print(f"MATCH for {header_key} and {footer_key}")
                print(f"MATCH for {header_key} and {footer_key}: Header Value = '{row_malicious[header_key]}', Footer Value = '{row_malicious[footer_key]}'")
                break  # Proceed to next column after first match

# Note: Adjust the file names 'malicious-csv-structure.csv' and 'benign-csv-structure.csv' as needed
