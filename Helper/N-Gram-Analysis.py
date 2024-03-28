import os
from collections import defaultdict

def file_to_ngrams(file_path, n):
    """
    Reads a file and extracts n-grams from its binary content.

    :param file_path: Path to the file to process.
    :param n: The length of each n-gram.
    :return: A dictionary of n-grams and their counts.
    """
    ngrams = defaultdict(int)
    with open(file_path, 'rb') as file:
        content = file.read()
        for i in range(len(content) - n + 1):
            ngram = content[i:i+n]
            ngrams[ngram] += 1
    return ngrams

def analyze_directory_ngrams(directory_path, n):
    """
    Analyzes all files in a directory and its subdirectories for n-gram patterns.

    :param directory_path: The root directory to start the analysis from.
    :param n: The length of each n-gram.
    """
    all_ngrams = defaultdict(int)
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if os.path.isfile(full_path):
                file_ngrams = file_to_ngrams(full_path, n)
                for ngram, count in file_ngrams.items():
                    all_ngrams[ngram] += count

    # Example output: Print the 10 most common n-grams
    common_ngrams = sorted(all_ngrams.items(), key=lambda item: item[1], reverse=True)[:10]
    for ngram, count in common_ngrams:
        print(f"N-gram: {ngram.hex()}, Count: {count}")

# Example usage
n = 4  # For 4-grams; adjust as needed
directory_path = '/home/cs20m039/thesis/dataset/benign/System/Windows'  # Replace with your directory path
analyze_directory_ngrams(directory_path, n)
