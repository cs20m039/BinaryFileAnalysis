import re
import logging

logging.basicConfig(level=logging.INFO)

def extract_info(input_string):
    pattern = r'Entropy(\d+) - Entropy Value: ([\d.]+) - Match found with (\d+) benign files.'
    match = re.search(pattern, input_string)
    if match:
        entropy_group = match.group(1)
        entropy_value = match.group(2)
        num_benign_files = match.group(3)
        return f"{entropy_group}, {entropy_value}, {num_benign_files}"
    else:
        logging.warning("No match found for input string: %s", input_string)
        return None

# Open the CSV file
with open('entropy.csv', 'r') as file:
    for line in file:
        info = extract_info(line.strip())  # Remove leading/trailing whitespace
        if info:
            print(info)
