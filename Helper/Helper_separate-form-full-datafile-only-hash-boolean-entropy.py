import csv

# Define the input and output file names
input_csv_file = 'BinaryFileScanning/full_datafile_signature_entropy_malicious_benign_first137bytes.csv'
output_csv_file = 'output-separator-entropy.csv'

# Open the input CSV file for reading
with open(input_csv_file, mode='r') as infile:
    # Open the output CSV file for writing
    with open(output_csv_file, mode='w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # Process each row in the input file
        for row in reader:
            # Assuming each row is a comma-separated string, extract the first, second, and last values
            first_value = row[0]  # The first hash value
            second_value = row[1]  # The boolean value
            last_value = row[-1]  # The entropy value

            # Write the extracted values to the output file
            writer.writerow([first_value, second_value, last_value])

print("Processing completed. The output has been saved to:", output_csv_file)
