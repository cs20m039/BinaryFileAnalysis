import os
print("Current working directory:", os.getcwd())

# Define the paths to your files
first_file_path = 'BinaryFileScanning/entropy_values.csv'
second_file_path = 'datashare/signatures_only.csv'
output_file_path = 'BinaryFileScanning/combined_pattern.csv'

# Open both files and an output file
with open(first_file_path, 'r') as first_file, \
        open(second_file_path, 'r') as second_file, \
        open(output_file_path, 'w') as output_file:
    # Iterate over each line of both files simultaneously
    for first_line, second_line in zip(first_file, second_file):
        # Strip newline characters and merge with a comma
        merged_line = first_line.strip() + ',' + second_line.strip() + '\n'

        # Write the merged line to the output file
        output_file.write(merged_line)

print('Merging complete.')
