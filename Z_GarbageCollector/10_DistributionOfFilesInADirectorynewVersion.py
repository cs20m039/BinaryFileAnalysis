import os
import numpy as np
import matplotlib.pyplot as plt

def get_file_sizes(directory):
    file_sizes = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                file_sizes.append(os.path.getsize(file_path))
    return file_sizes

def plot_box_plot(file_sizes_list):
    plt.figure(figsize=(8, 6))
    plt.boxplot(file_sizes_list, labels=['Directory 1', 'Directory 2', 'Directory 3'], showfliers=False)
    plt.title('File Size Distribution')
    plt.ylabel('File Size (bytes)')
    plt.show()

if __name__ == "__main__":
    directories = [
    '/home/cs20m039/thesis/dataset/benign/Windows',
    '/home/cs20m039/thesis/dataset/benign/Linux',
    '/home/cs20m039/thesis/dataset/benign/macOS']
    file_sizes_list = []

    for directory in directories:
        file_sizes = get_file_sizes(directory)
        file_sizes_list.append(file_sizes)

    plot_box_plot(file_sizes_list)
