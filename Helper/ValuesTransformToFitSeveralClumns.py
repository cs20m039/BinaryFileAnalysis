import csv

# Open the CSV file and read its contents
with open('entropy_cleared.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    # Iterate over each row in the CSV file
    for row in reader:
        # Check if the row contains at least three elements
        if len(row) >= 3:
            # Extract values from each row
            values = row[:3]  # Extract only the first 3 values from each row
            # Define a function to join values with '&' and add '\\' after every 10 values
            def format_values(values):
                formatted_values = ''
                for i, value in enumerate(values):
                    if (i + 1) % 10 == 0:  # Add '\\' after every 10 values
                        formatted_values += value + '\\\\'
                    else:
                        formatted_values += value + ' & '
                return formatted_values

            # Print the formatted values
            print(format_values(values))
