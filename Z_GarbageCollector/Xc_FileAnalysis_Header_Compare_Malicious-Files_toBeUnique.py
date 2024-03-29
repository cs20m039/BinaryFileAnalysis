import os

def print_first_byte_of_files(directory):
    """Print the first byte of each file in the specified directory and its subfolders."""
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:  # Open the file in binary mode
                    first_byte = f.read(4)
                    if first_byte:
                        print(f"File: {file_path} - First Byte: {first_byte.hex()}")
                    else:
                        print(f"File: {file_path} - Empty file")
            except Exception as e:
                print(f"Could not read file {file_path}: {e}")

# Example usage
directory = '/home/cs20m039/thesis/dataset/malicious'  # Replace with your directory path
print_first_byte_of_files(directory)
