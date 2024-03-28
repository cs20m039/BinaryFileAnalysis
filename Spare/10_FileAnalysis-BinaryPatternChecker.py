import os
import re

def find_binary_patterns(directory1, directory2):
    binary_patterns1 = set()
    binary_patterns2 = set()

    def process_folder(directory, binary_patterns_set):
        binary_pattern = re.compile(b'[^\x20-\x7E\r\n\t\f\v]+')
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                with open(filepath, 'rb') as f:
                    data = f.read()
                    matches = binary_pattern.findall(data)
                    for match in matches:
                        binary_patterns_set.add(match)

    process_folder(directory1, binary_patterns1)
    process_folder(directory2, binary_patterns2)

    # Calculate the length of patterns exclusive to each directory
    unique_patterns1 = binary_patterns1 - binary_patterns2
    unique_patterns2 = binary_patterns2 - binary_patterns1

    print(f"Unique patterns in {directory1}:")
    for pattern in unique_patterns1:
        print(f"Pattern: {pattern}, Length: {len(pattern)} bytes")

    print(f"\nUnique patterns in {directory2}:")
    for pattern in unique_patterns2:
        print(f"Pattern: {pattern}, Length: {len(pattern)} bytes")

# Provide paths to the directories you want to analyze
directory_path1 = '/home/cs20m039/thesis/dataset/malicious'
directory_path2 = '/home/cs20m039/thesis/dataset/benign'

find_binary_patterns(directory_path1, directory_path2)
