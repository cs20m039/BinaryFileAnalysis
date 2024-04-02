import matplotlib.pyplot as plt

# Data
pattern_lengths = [4, 5, 6, 7, 8, 10, 11, 12, 14, 16, 18, 19, 20, 22, 24, 25, 26, 28, 29, 30, 31, 32, 34, 36, 38, 40, 42, 43, 44, 46, 47, 48, 50, 52, 54, 55, 56, 58, 60, 62, 64, 66, 68, 70, 72, 73, 74, 75, 76, 78, 80, 81, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 109, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 129, 134, 136, 137]
ransomware_percentage = [66.07, 65.71, 62.14, 57.14, 56.79, 56.07, 55.71, 54.64, 54.64, 54.64, 53.21, 52.14, 51.79, 51.79, 51.79, 48.21, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 46.79, 42.14, 42.14, 42.14, 41.79, 41.79, 41.43, 41.07, 41.07, 40.71, 40.71, 40.36, 40.00, 39.29, 39.29, 39.29, 38.93, 38.93, 38.93, 38.57, 38.57, 38.21, 38.21, 38.21, 38.21, 37.86, 37.86, 37.86, 37.50, 37.50, 37.50, 37.50, 37.50, 37.14, 37.14, 37.14, 37.14, 36.79, 36.79, 36.43, 36.43, 36.43, 35.00, 35.00, 35.00, 34.64, 34.64, 34.64, 34.64, 16.07, 9.29, 8.93, 0.00]
benign_percentage = [14.08, 13.18, 12.91, 12.54, 12.11, 12.05, 12.00, 12.00, 11.65, 11.63, 10.93, 10.91, 10.76, 10.70, 10.66, 10.12, 9.38, 9.37, 9.35, 9.34, 9.28, 9.27, 9.24, 9.22, 9.17, 9.12, 9.09, 9.08, 9.08, 9.07, 9.04, 9.02, 9.00, 8.97, 8.95, 8.92, 8.91, 8.90, 8.85, 8.27, 8.23, 8.22, 8.20, 8.18, 8.11, 8.09, 8.09, 8.07, 8.07, 8.06, 8.02, 7.97, 7.97, 7.96, 7.91, 7.89, 7.87, 7.86, 7.83, 7.79, 7.77, 7.74, 7.68, 7.67, 7.64, 7.59, 7.59, 7.54, 7.51, 7.47, 7.45, 7.42, 7.36, 7.33, 7.32, 7.25, 0.80, 0.27, 0.01, 0.00]




# Plotting
plt.figure(figsize=(14, 8))
plt.plot(pattern_lengths, ransomware_percentage, label='Ransomware %', marker='o', linestyle='-', color='red')
plt.plot(pattern_lengths, benign_percentage, label='Benign %', marker='x', linestyle='--', color='blue')
plt.xlabel('Signature length in bytes', fontsize=16)
plt.ylabel('Number of files in %', fontsize=16)
plt.title('Signature Header and Footer Analysis', fontsize=16)
plt.yticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.xticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.legend()
plt.grid(True)
plt.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.1)  # Adjust margins
plt.show()

