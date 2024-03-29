import matplotlib.pyplot as plt

def compare_files(file_path_1, file_path_2):
    """Compare two files byte by byte and return differences."""
    with open(file_path_1, 'rb') as f1, open(file_path_2, 'rb') as f2:
        bytes1 = f1.read()
        bytes2 = f2.read()

    min_len = min(len(bytes1), len(bytes2))
    differences = [(i, bytes1[i], bytes2[i]) for i in range(min_len) if bytes1[i] != bytes2[i]]

    if len(bytes1) != len(bytes2):
        differences.append(('length_difference', len(bytes1), len(bytes2)))

    return differences

def plot_differences(differences):
    """Plot the differences between two files graphically."""
    x = [item[0] for item in differences if type(item[0]) == int]
    y1 = [1 for _ in x]  # Just to keep all markers at the same Y level for file 1
    y2 = [2 for _ in x]  # Same for file 2, but at a different Y level

    plt.figure(figsize=(10, 2))
    plt.scatter(x, y1, color='red', label='File 1', alpha=0.5)
    plt.scatter(x, y2, color='blue', label='File 2', alpha=0.5)
    plt.legend()
    plt.xlabel('Byte Position')
    plt.yticks([])
    plt.title('Differences between Files')
    plt.show()

if __name__ == "__main__":
    file_path_1 = '/home/cs20m039/thesis/dataset/malicious/Hive/Windows/6a4ebf513f996bd7198c711bef936a989fea148c235817ea56c1e2afafa927f5.7z'  # Replace with the actual file path
    file_path_2 = '/home/cs20m039/thesis/dataset/benign/data/7ZIP-LZMA2-tiny/0022-7z-lzma2.7z'  # Replace with the actual file path

    differences = compare_files(file_path_1, file_path_2)
    plot_differences(differences)
