import os
from collections import defaultdict

def read_files(directory):
    """
    Reads all files in a directory (recursively) and returns a list of byte arrays.
    It now checks if an item is a file before attempting to read it.
    """
    file_contents = []
    for root, dirs, files in os.walk(directory):  # os.walk is used for recursive traversal
        for filename in files:
            path = os.path.join(root, filename)
            if os.path.isfile(path):  # Check if the path is indeed a file
                with open(path, 'rb') as file:
                    file_contents.append(file.read())
    return file_contents

def compare_byte_intervals(malicious_files, benign_files):
    """
    Compares the byte intervals between malicious and benign files.
    Returns a dictionary with byte positions as keys and the number of differences as values.
    """
    byte_differences = defaultdict(int)
    for mal_file in malicious_files:
        for ben_file in benign_files:
            min_len = min(len(mal_file), len(ben_file))
            for i in range(min_len):
                if mal_file[i] != ben_file[i]:
                    byte_differences[i] += 1
    return byte_differences

def find_significant_intervals(byte_differences, threshold):
    """
    Finds intervals with significant differences based on a threshold.
    Returns a list of intervals (start, end) where differences are above the threshold.
    """
    significant_intervals = []
    start = None
    for i in sorted(byte_differences.keys()):
        if byte_differences[i] >= threshold:
            if start is None:
                start = i
            end = i
        else:
            if start is not None:
                significant_intervals.append((start, end + 1))
                start = None
    if start is not None:
        significant_intervals.append((start, end + 1))
    return significant_intervals

# Example usage
malicious_dir = '/home/cs20m039/thesis/dataset1/malicious'
benign_dir = '/home/cs20m039/thesis/dataset1/benign'

malicious_files = read_files(malicious_dir)
benign_files = read_files(benign_dir)

byte_differences = compare_byte_intervals(malicious_files, benign_files)
significant_intervals = find_significant_intervals(byte_differences, threshold=10)  # Adjust the threshold as needed

print("Significant byte intervals where files differ:", significant_intervals)
