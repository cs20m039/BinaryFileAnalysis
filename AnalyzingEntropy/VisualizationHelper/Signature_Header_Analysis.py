import matplotlib.pyplot as plt

# Data
pattern_lengths = [4, 5, 6, 7, 8, 10, 11, 12, 16, 18, 24, 25, 60, 64, 128, 129, 134, 136, 137]
ransomware_percentage = [97.14, 96.79, 93.21, 88.57, 88.57, 88.21, 87.14, 84.29, 84.29, 82.14, 81.07, 77.14, 75.36, 74.64, 74.64, 45.36, 29.29, 28.93, 0.00]
benign_percentage = [26.28, 26.27, 26.20, 25.01, 24.72, 24.56, 22.66, 22.66, 22.32, 18.06, 18.06, 17.38, 16.64, 15.98, 15.67, 0.98, 0.30, 0.03, 0.00]

# Plotting
plt.figure(figsize=(14, 8))
plt.plot(pattern_lengths, ransomware_percentage, label='Ransomware %', marker='o', linestyle='-', color='red')
plt.plot(pattern_lengths, benign_percentage, label='Benign %', marker='x', linestyle='--', color='blue')
plt.xlabel('Signature length in bytes', fontsize=16)
plt.ylabel('Number of files in %', fontsize=16)
plt.title('Signature Header Analysis', fontsize=16)
plt.yticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.xticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.legend()
plt.grid(True)
plt.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.1)  # Adjust margins
plt.show()

