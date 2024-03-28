import ssdeep
import os
import logging
from collections import defaultdict

# Setup logging
logging.basicConfig(filename='logfiles/file_similarity.log', level=logging.INFO)

def generate_fuzzy_hashes(directory):
    """Generate fuzzy hashes for all files in the specified directory."""
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    fuzzy_hash = ssdeep.hash(content)
                    hashes[file_path] = fuzzy_hash
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {str(e)}")
    return hashes

def compare_hashes(hashes_a, hashes_b):
    """Compare hashes from folder b against all hashes from folder a."""
    matches = []
    for path_b, hash_b in hashes_b.items():
        for path_a, hash_a in hashes_a.items():
            similarity = ssdeep.compare(hash_a, hash_b)
            if similarity > 0:  # Adjust threshold if needed
                matches.append((path_a, path_b, similarity))
    return matches

def analyze_and_log_results(matches):
    """Analyze matches, cluster by similarity, and identify no-match threshold."""
    if not matches:
        logging.info("No matches found.")
        return

    # Cluster matches by similarity
    clusters = defaultdict(list)
    for path_a, path_b, similarity in matches:
        clusters[similarity].append((path_a, path_b))

    # Log and save results
    with open('datashare/match_results.txt', 'w') as file:
        for similarity, pairs in sorted(clusters.items(), reverse=True):
            file.write(f"Similarity: {similarity}%\n")
            for path_a, path_b in pairs:
                file.write(f"\t{path_a} <--> {path_b}\n")
            file.write("\n")

    # Find and log the lowest similarity where matches still occur
    min_similarity = min(clusters.keys())
    logging.info(f"Lowest similarity with matches: {min_similarity}%")

folder_a = '/home/cs20m039/thesis/dataset/benign/data'
folder_b = '/home/cs20m039/thesis/dataset/benign/'

# Generate hashes
hashes_a = generate_fuzzy_hashes(folder_a)
hashes_b = generate_fuzzy_hashes(folder_b)

# Compare hashes and get matches
matches = compare_hashes(hashes_a, hashes_b)

# Analyze and log results
analyze_and_log_results(matches)

logging.info("Analysis complete. Results are saved in match_results.txt.")
