import csv
from collections import defaultdict

# Assumes the path to your CSV file is correctly set
file_path = '../DataExchange/datafile_entropy_malicious_header_1-2000.csv'


# Function to read the data from the CSV and find the header with the highest average entropy
def find_header_with_highest_average_entropy(file_path):
    total_entropies = defaultdict(float)
    count_entropies = defaultdict(int)

    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)

        for row in reader:
            for key, value in row.items():
                if key.startswith('Header_Entropy'):
                    entropy = float(value)
                    total_entropies[key] += entropy  # Sum entropy values for each header
                    count_entropies[key] += 1  # Count occurrences of each header

    # Calculate average entropy for each header
    average_entropies = {key: total / count_entropies[key] for key, total in total_entropies.items()}

    # Find the header with the highest average entropy
    header_with_highest_average = max(average_entropies, key=average_entropies.get)
    highest_average_entropy = average_entropies[header_with_highest_average]

    return header_with_highest_average, highest_average_entropy


# Find the header with the highest average entropy and print it
header_result, average_entropy_value = find_header_with_highest_average_entropy(file_path)
print(
    f"The header with the highest average entropy is: {header_result} with an average entropy of {average_entropy_value}")
