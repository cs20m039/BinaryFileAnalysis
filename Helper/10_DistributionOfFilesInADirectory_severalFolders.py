import os
import pandas as pd
import matplotlib.pyplot as plt

def analyze_directory(path):
    file_sizes = []
    file_extensions = []
    for root, dirs, files in os.walk(path):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                size = os.path.getsize(full_path)
                _, ext = os.path.splitext(file)
                ext = ext.lower() if ext else 'no_extension'
                file_sizes.append(size)
                file_extensions.append(ext)
            except Exception as e:
                print(f"Error processing file {file}: {e}")
    return file_sizes, file_extensions

directories = [
    '/home/cs20m039/thesis/dataset/benign/Windows',
    '/home/cs20m039/thesis/dataset/benign/Linux',
    '/home/cs20m039/thesis/dataset/benign/macOS',
    '/home/cs20m039/thesis/dataset/benign/Data'
]

# Dictionary to hold file sizes for each directory
directory_file_sizes = {}

# Collect file sizes for each directory
for directory_path in directories:
    sizes, _ = analyze_directory(directory_path)
    directory_name = os.path.basename(directory_path) or "Root"
    directory_file_sizes[directory_name] = sizes

# Creating the box plot
plt.figure(figsize=(10, 6))

# Prepare data for plotting
data_to_plot = [sizes for sizes in directory_file_sizes.values()]
labels = [name for name in directory_file_sizes.keys()]

#plt.boxplot(data_to_plot, labels=labels, vert=True, patch_artist=True)
# plt.boxplot(data_to_plot, vert=True, patch_artist=True, showfliers=False)  # showfliers=True ensures outliers are shown
plt.boxplot(
    data_to_plot,
    labels=labels,
    vert=True,
    patch_artist=True,
    showfliers=False,  # Ensure outliers are shown
    flierprops=dict(marker='o', color='red', markersize=5)  # Customize outliers
)
plt.yscale('log')  # Optional: Set y-axis to log scale for better visibility
plt.title('File Size Distribution Across Directories')
plt.xlabel('Subsets')
plt.ylabel('File Size (bytes)')

plt.show()
