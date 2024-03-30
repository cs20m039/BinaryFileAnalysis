import matplotlib.pyplot as plt
import numpy as np

# Data
pattern_length = [
    4, 5, 6, 7, 8, 10, 11, 12, 16, 18,
    24, 25, 60, 64, 128, 129, 134, 136, 137
]
malicious_percent = [
    97.14, 96.79, 93.21, 93.21, 88.57, 88.21, 87.14, 87.14, 84.29, 82.14,
    81.07, 77.14, 75.36, 75.36, 74.64, 45.36, 29.29, 28.93, 0.00
]
benign_percent = [
    26.28, 26.27, 26.20, 25.01, 24.72, 24.56, 24.56, 22.66, 22.32, 22.32,
    18.06, 17.38, 16.64, 15.98, 15.67, 0.98, 0.30, 0.03, 0.00
]

# Width of each bar
bar_width = 0.4
index = np.arange(len(pattern_length))

# Create grouped bar plot
plt.figure(figsize=(15, 5))
plt.bar(index - bar_width/2, malicious_percent, bar_width, label='Malicious %', color='red', alpha=0.7, fontsize=13)
plt.bar(index + bar_width/2, benign_percent, bar_width, label='Benign %', color='green', alpha=0.7, fontsize=13)
plt.xlabel('Header Signature Length', fontsize=13)
plt.ylabel('Percentage', fontsize=13)
plt.legend()
plt.xticks(index, pattern_length)
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()
