import os

def count_leading_zeros(file_path):
    """Count the number of leading zero bytes in a file."""
    with open(file_path, 'rb') as file:
        count = 0
        while True:
            byte = file.read(1)
            if not byte or byte != b'\x00':
                break
            count += 1
        return count

def find_max_leading_zeros(root_dir):
    """Find the file with the maximum number of leading zero bytes."""
    max_zeros = 0
    max_zeros_file = None

    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            zeros = count_leading_zeros(file_path)
            if zeros > max_zeros:
                max_zeros = zeros
                max_zeros_file = file_path

    return max_zeros_file, max_zeros


# Specify the root directory to analyze
root_directory = '/home/cs20m039/thesis/dataset/malicious'  # Replace this with the path to your directory
max_zeros_file, max_zeros = find_max_leading_zeros(root_directory)

if max_zeros_file:
    print(f"The file with the maximum number of leading zero bytes is: {max_zeros_file}")
    print(f"Number of leading zero bytes: {max_zeros}")
else:
    print("No files found or no leading zero bytes in any file.")
