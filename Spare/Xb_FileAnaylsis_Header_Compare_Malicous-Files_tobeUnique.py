import os

def get_all_file_paths(directory):
    """Recursively get all file paths within a directory."""
    file_paths = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths

def read_file_header(file_path, num_bytes):
    """Read the first num_bytes from a file."""
    with open(file_path, 'rb') as file:
        return file.read(num_bytes)

def find_unique_byte_sequence_and_print_signatures(directory, max_bytes=1024):
    """Find how many bytes are necessary for unique header sequences and print them."""
    all_files = get_all_file_paths(directory)
    file_count = len(all_files)
    for num_bytes in range(1, max_bytes + 1):
        headers = {}
        for file_path in all_files:
            header = read_file_header(file_path, num_bytes)
            if header in headers:
                break  # Found a duplicate, need more bytes
            headers[header] = file_path  # Store file path for printing later
        else:
            # If loop didn't break, all headers are unique with current num_bytes
            print(f"Unique byte sequences found with {num_bytes} bytes among {file_count} files.")
            for header, path in headers.items():
                print(f"Signature: {header.hex()} (File: {path})")
            return num_bytes
    return None  # Couldn't find unique headers within max_bytes

# Example usage
directory = '/home/cs20m039/thesis/dataset/malicious'  # Replace with your directory path
max_bytes_needed = find_unique_byte_sequence_and_print_signatures(directory)
if max_bytes_needed is None:
    print(f"Could not find a unique byte sequence within the given byte limit for {len(get_all_file_paths(directory))} files.")
