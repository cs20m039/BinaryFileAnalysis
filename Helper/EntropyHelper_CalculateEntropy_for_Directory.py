import os
from math import log2

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * log2(p_x)
    return entropy

def get_files_entropy(directory, byte_interval=400):
    entropy_values = []  # Initialize an empty list to store the entropy values here
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(byte_interval)
                    entropy = calculate_entropy(data)
                    entropy_values.append(f"{entropy:.4f}")  # Format for better readability

            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

    # Print all collected entropy values, separated by commas, after processing all files
    print(", ".join(entropy_values))

# Example usage
directory = '/home/cs20m039/thesis/dataset1/benign'  # Replace with your directory path
get_files_entropy(directory)
