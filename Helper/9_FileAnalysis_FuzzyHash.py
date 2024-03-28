import os
import ssdeep

def compute_hashes(base_path):
    """Compute fuzzy hashes for all files in the directory and subdirectories."""
    hashes = {}
    for root, dirs, files in os.walk(base_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                    file_hash = ssdeep.hash(file_data)
                    hashes[file_path] = file_hash
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
    return hashes

def compare_hashes(hashes):
    """Compare all hashes with each other to find similarities."""
    keys = list(hashes.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            similarity = ssdeep.compare(hashes[keys[i]], hashes[keys[j]])
            if similarity > 0:  # Adjust this threshold as needed
                print(f"Similarity {similarity}% between {keys[i]} and {keys[j]}")

if __name__ == "__main__":
    base_path = "/home/cs20m039/thesis/dataset/malicious"  # Change this to your directory path
    hashes = compute_hashes(base_path)
    compare_hashes(hashes)
