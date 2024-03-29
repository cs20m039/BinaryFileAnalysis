import hashlib
import os

def calculate_sha256_hash(file_path):
    """Calculate the SHA-256 hash of a given file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def scan_directory_for_sha256_hashes(directory_path):
    """Scan a directory (and subdirectories) for files and collect their SHA-256 hashes."""
    sha256_hashes = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            sha256_hash = calculate_sha256_hash(file_path)
            if sha256_hash:  # Ensure hash was successfully calculated
                sha256_hashes.append(sha256_hash)
    return sha256_hashes

def generate_latex_table(hashes):
    """Generate a LaTeX table from a list of hashes."""
    table = "\\begin{table}[H]\n\\centering\n\\begin{tabular}{|l|}\n\\hline\nSHA-256 Hash \\\\ \\hline\n"
    for hash in hashes:
        table += hash + " \\\\ \\hline\n"
    table += "\\end{tabular}\n\\caption{List of SHA-256 Hashes}\n\\label{table:hashes}\n\\end{table}"
    return table

# Example usage - replace 'your_directory_path_here' with the path to the directory you want to scan
directory_path = "/home/cs20m039/samples/malicious/LockBitRansomware/Windows/"
hashes = scan_directory_for_sha256_hashes(directory_path)

# Generate and output the LaTeX table
latex_table = generate_latex_table(hashes)
print(latex_table)
