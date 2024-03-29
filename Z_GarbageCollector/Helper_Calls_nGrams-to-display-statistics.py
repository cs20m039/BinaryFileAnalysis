import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load data from CSV files
malware_df = pd.read_csv('malware_common_patterns.csv')
benign_df = pd.read_csv('benign_common_patterns.csv')

# Box plot visualization
plt.figure(figsize=(10, 6))
sns.boxplot(data=[malware_df['Count'], benign_df['Count']], palette=["red", "blue"])
plt.title('Distribution of Pattern Occurrences')
plt.xlabel('Sample Type')
plt.ylabel('Count')
plt.xticks([0, 1], ['Malware', 'Benign'])
plt.grid(True)
plt.show()
