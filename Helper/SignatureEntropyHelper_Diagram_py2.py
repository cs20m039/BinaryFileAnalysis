import matplotlib.pyplot as plt

# Data preparation
patterns = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500]
ransomware_deviation_ds1 = [9.90, 10.50, 10.05, 10.13, 10.57, 11.75, 10.70, 10.34, 9.86, 8.98]
benign_deviation_ds1 = [0.75, 0.73, 0.75, 0.74, 0.73, 0.70, 0.73, 0.74, 0.75, 0.78]
unknown_deviation_ds1 = [0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00]
ransomware_deviation_ds2 = [6.94, 6.60, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00]
benign_deviation_ds2 = [0.83, 0.84, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00]
unknown_deviation_ds2 = [0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00]

# Plotting
plt.figure(figsize=(10, 6))

plt.plot(patterns, ransomware_deviation_ds1, label='Ransomware Deviation DS1', marker='o')
plt.plot(patterns, benign_deviation_ds1, label='Benign Deviation DS1', marker='s')
plt.plot(patterns, ransomware_deviation_ds2, label='Ransomware Deviation DS2', linestyle='--', marker='^')
plt.plot(patterns, benign_deviation_ds2, label='Benign Deviation DS2', linestyle='--', marker='d')

plt.xlabel('Pattern')
plt.ylabel('Deviation')
plt.title('Deviation by Pattern for DS1 and DS2')
plt.legend()
plt.grid(True)
plt.xticks(patterns)

plt.show()
