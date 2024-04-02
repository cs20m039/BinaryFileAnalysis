import csv


input_malicious = '../DataExchange/datafile_signature_header_malicious_500-500.csv'
input_benign = '../DataExchange/datafile_signature_header_benign_500-500.csv'
output_filename = '../DataExchange/datafile_signature_header_500_output.csv'


with open(output_filename, 'w', newline='') as output_file:
    # Create a CSV writer object for the output file
    csv_writer = csv.writer(output_file)


    with open(input_malicious, newline='') as file1:
        csv_reader1 = csv.reader(file1)
        next(csv_reader1)  # Skip the header
        for row in csv_reader1:
            row.insert(1, '1')
            csv_writer.writerow(row)


    with open(input_benign, newline='') as file2:
        csv_reader2 = csv.reader(file2)
        next(csv_reader2)  # Skip the header
        for row in csv_reader2:
            row.insert(1, '0')
            csv_writer.writerow(row)

print(f"Merged CSV has been created as '{output_filename}'.")
