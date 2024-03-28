import os

def analyze_file_sizes(directory_path):
    """
    Analyze all files in a directory and its subdirectories to find the smallest
    and largest file sizes, then print out the total count of files analyzed and
    the sizes of the smallest and largest files in bytes.
    """
    smallest_size = float('inf')  # Initialize with infinity
    largest_size = 0  # Initialize with zero
    file_count = 0  # Initialize file count

    for dirpath, _, filenames in os.walk(directory_path):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                file_size = os.path.getsize(full_path)
                file_count += 1  # Increment file count
                if file_size < smallest_size:
                    smallest_size = file_size  # Update smallest size
                if file_size > largest_size:
                    largest_size = file_size  # Update largest size
            except OSError as e:
                print(f"Error reading file {full_path}: {e}")

    # Print results
    if file_count > 0:
        print(f"Total files analyzed: {file_count}")
        print(f"Smallest file size: {smallest_size} bytes")
        print(f"Largest file size: {largest_size} bytes")
    else:
        print("No files found in the directory.")

# Example usage
directory_path = '/home/cs20m039/thesis/dataset/malicious' # Replace with your directory path
analyze_file_sizes(directory_path)
