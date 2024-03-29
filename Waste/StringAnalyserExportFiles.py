import os
import json
import re

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

def process_directory(directory_path, patterns, output_directory):
    # Load regex patterns from the config file
    with open("patterns.json", "r") as f:
        all_patterns = json.load(f)

    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Prepare the pattern dictionary based on chosen_patterns
    chosen_patterns = patterns
    if 'all' in chosen_patterns:
        patterns = {'all': None}
    else:
        patterns = {k: all_patterns[k] for k in chosen_patterns if k in all_patterns}

    for root, _, files in os.walk(directory_path):
        for name in files:
            file_path = os.path.join(root, name)
            output_file_name = os.path.splitext(name)[0] + '_output.txt'  # Create a unique output file name
            output_file_path = os.path.join(output_directory, output_file_name)
            try:
                matches = find_strings(file_path, patterns)
                if matches:
                    with open(output_file_path, 'w') as output_file:
                        for s in matches:
                            output_file.write(f"{s}\n")
            except Exception as e:
                with open(output_file_path, 'w') as output_file:
                    output_file.write(f"Error processing {file_path}: {str(e)}\n")

# Example usage within PyCharm or any other IDE
if __name__ == "__main__":
    directory_path = ('/home/cs20m039/samples/malicious/')  # Update this to the directory you want to search)
    chosen_patterns = ['all']  # Update this with the patterns you're interested in
    output_directory = 'output_files'  # Directory where output files will be saved
    process_directory(directory_path, chosen_patterns, output_directory)
