import pandas as pd

# Read the first input CSV file
df1 = pd.read_csv("datashare/datafile_malicious_and_benign_binarypattern_first137bytes", names=["SHA256", "Boolean", "Binary Pattern"])

# Read the second input CSV file
df2 = pd.read_csv("datashare/entropy_values_benign_malicious_first137Bytes.csv", names=["SHA256", "Entropy"])

# Merge the dataframes based on the common SHA256 hashes
merged_df = pd.merge(df1, df2, on="SHA256")

# Write the merged data to the output CSV file
merged_df.to_csv("output.csv", index=False)
