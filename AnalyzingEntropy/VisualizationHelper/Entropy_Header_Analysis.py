import matplotlib.pyplot as plt

# Data
pattern_lengths = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 188, 190, 191, 194, 195, 196, 197, 198, 200, 201, 202, 210, 219, 226, 230, 231, 232, 233, 238, 239, 240, 243, 246, 247, 251, 253, 254, 255, 256, 343, 344]
ransomware_percentage = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 99.64, 100.0, 100.0, 100.0, 100.0, 98.21, 96.79, 99.64, 98.93, 100.0, 97.14, 97.86, 95.36, 97.86, 97.86, 97.14, 96.07, 96.43, 97.5, 97.14, 94.29, 92.5, 93.21, 92.5, 96.43, 95.0, 95.0, 93.57, 96.07, 93.93, 93.21, 91.79, 92.14, 93.21, 91.43, 92.14, 93.57, 90.36, 88.57, 90.36, 86.07, 90.36, 86.07, 86.07, 87.14, 85.36, 88.57, 87.86, 86.43, 87.14, 86.79, 89.64, 89.29, 86.43, 87.5, 86.79, 84.29, 87.14, 79.29, 88.93, 85.36, 79.29, 81.79, 79.29, 85.36, 84.64, 78.57, 83.93, 85.0, 83.57, 77.86, 78.93, 77.14, 77.14, 77.5, 77.14, 77.5, 77.14, 77.14, 77.5, 76.79, 79.64, 79.64, 76.43, 76.43, 76.79, 77.86, 76.79, 76.79, 77.5, 77.86, 77.5, 77.14, 76.43, 76.07, 76.79, 77.14, 76.79, 76.79, 76.43, 76.43, 75.36, 77.14, 78.21, 75.71, 76.07, 76.43, 75.36, 75.71, 76.07, 76.43, 76.43, 76.43, 76.79, 77.14, 75.71, 73.21, 74.29, 74.64, 74.64, 74.64, 75.36, 75.36, 69.64, 65.71, 59.64, 66.43, 57.86, 61.07, 63.21, 61.43, 60.36, 58.93, 44.29, 60.71, 60.36, 61.07, 71.43, 51.07, 41.43, 31.07, 30.71, 17.86, 37.5, 23.57, 15.36, 25.0, 25.36, 22.14, 12.14, 7.5, 16.07, 12.14, 10.71, 10.0, 17.14, 7.86, 13.57, 6.07, 4.29, 5.0, 7.86, 3.93, 2.86, 2.5, 0.71, 1.43, 3.57, 2.14, 4.64, 1.79, 3.21, 1.43, 0.36, 1.07, 2.86, 0.36, 1.07, 0.36, 1.79, 0.36, 1.79, 2.5, 1.79, 0.36, 0.71, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, 0]
benign_percentage = [88.2, 94.78, 88.99, 89.8, 91.93, 89.26, 65.85, 53.8, 56.69, 49.15, 46.39, 39.55, 44.29, 36.89, 40.25, 35.9, 39.59, 34.76, 30.42, 28.92, 27.61, 23.86, 24.46, 22.08, 25.23, 24.47, 23.14, 20.65, 20.7, 18.64, 20.86, 18.23, 19.02, 21.39, 22.18, 20.07, 22.19, 21.0, 18.05, 18.13, 17.97, 17.62, 17.71, 17.14, 17.16, 17.42, 17.12, 17.22, 17.18, 17.42, 17.53, 17.11, 17.08, 17.16, 16.9, 16.96, 16.89, 16.88, 17.04, 17.04, 17.23, 16.9, 17.04, 16.87, 16.59, 16.7, 16.8, 16.53, 16.95, 17.0, 16.43, 16.67, 16.58, 16.67, 17.36, 16.84, 16.57, 16.83, 16.55, 16.48, 16.46, 16.45, 16.44, 16.43, 16.41, 16.51, 16.47, 16.44, 16.48, 16.41, 16.44, 16.46, 16.41, 16.4, 16.41, 16.44, 16.4, 16.42, 16.5, 16.58, 16.47, 16.36, 16.37, 16.41, 16.38, 16.42, 16.35, 16.38, 16.37, 16.36, 16.33, 16.35, 16.43, 16.37, 16.35, 16.36, 16.33, 16.34, 16.38, 16.42, 16.34, 16.37, 16.38, 16.39, 16.14, 15.88, 10.75, 9.93, 9.85, 13.63, 9.05, 8.06, 11.59, 12.84, 12.48, 10.11, 11.22, 11.59, 5.17, 7.35, 4.82, 6.9, 4.56, 4.59, 3.23, 2.42, 3.77, 3.27, 2.21, 1.48, 1.37, 1.4, 2.15, 0.98, 1.23, 1.14, 0.78, 0.96, 0.56, 0.42, 0.63, 0.41, 0.4, 0.39, 0.34, 0.25, 0.19, 0.22, 0.2, 0.24, 0.18, 0.1, 0.08, 0.05, 0.02, 0.04, 0.07, 0.06, 0.11, 0.04, 0.09, 0.03, 0.01, 0.02, 0.01, 0.01, 0.01, 0.01, 0.02, 0.01, 0.02, 0.04, 0.02, 0.01, 0.02, 0.01, 0.03, 0.01, 0.02, 0.01, 0.03, 0.01, 0.03, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0]

# Plotting
plt.figure(figsize=(14, 8))
plt.plot(pattern_lengths, ransomware_percentage, label='Ransomware %', marker='o', linestyle='-', color='red')
plt.plot(pattern_lengths, benign_percentage, label='Benign %', marker='x', linestyle='--', color='blue')
plt.xlabel('Entropy length in bytes', fontsize=16)
plt.ylabel('Number of files in %', fontsize=16)
plt.title('Entropy Header Analysis', fontsize=16)
#plt.yticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.xticks(range(0, max(pattern_lengths) + 1, 10))  # Setting x-axis ticks to every 10 units
plt.legend()
plt.grid(True)
plt.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.1)  # Adjust margins
plt.show()
