import os
import hashlib

def hash_file(file_path):
    """Calculate the hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def rename_files_with_hash(directory):
    """Recursively rename files in a directory and its subdirectories with their hash values."""
    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hash = hash_file(file_path)
            file_extension = os.path.splitext(filename)[1]
            new_filename = file_hash + file_extension
            new_file_path = os.path.join(root, new_filename)
            os.rename(file_path, new_file_path)
            print(f"Renamed: {file_path} -> {new_file_path}")

if __name__ == "__main__":
    directory_path = "/home/cs20m039/thesis/dataset/benign"
    rename_files_with_hash(directory_path)
