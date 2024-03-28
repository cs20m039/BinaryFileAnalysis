import csv

# Open the CSV file and read its contents
with open('entropy_cleared.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    # Iterate over each row in the CSV file
    for row in reader:
        # Transform each row and print the formatted output
        formatted_line = " & ".join(row) + '\\\\'
        print(formatted_line)
