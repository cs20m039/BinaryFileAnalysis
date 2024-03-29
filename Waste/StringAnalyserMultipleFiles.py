import sys
import json
import re
import os

def find_strings(filename, patterns, min_length=4):
    with open(filename, 'rb') as f:
        content = f.read().decode('ascii', 'ignore')  # decode with ASCII and ignore non-ASCII bytes

        results = []

        # Define a general regex for ASCII strings when "all" is used
        ascii_regex = re.compile(r'[ -~]{' + str(min_length) + r',}')

        for pattern_name, pattern_regex in patterns.items():
            if pattern_name == 'all':  # If the 'all' command is used, look for any ASCII string
                matches = ascii_regex.findall(content)
            else:
                matches = re.findall(pattern_regex, content)
            for match in matches:
                results.append(match)

        return results

def process_directory(directory, patterns):
    # Load regex patterns from the config file
    with open("patterns.json", "r") as f:
        all_patterns = json.load(f)

    # Prepare the pattern dictionary based on chosen_patterns
    if 'all' in patterns:
        patterns = {'all': None}
    else:
        patterns = {k: all_patterns[k] for k in patterns if k in all_patterns}

    for root, dirs, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            print(f"Processing {file_path}...")
            try:
                for s in find_strings(file_path, patterns):
                    print(s)
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")

if __name__ == "__main__":
    # Example directory to search
    directory = "/home/cs20m039/samples/malicious/LockBitRansomware/Windows/"  # Replace with your actual directory path
    chosen_patterns = ['url']  # Or any other specific patterns you're looking for

    process_directory(directory, chosen_patterns)
