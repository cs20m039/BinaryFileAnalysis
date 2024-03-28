import pandas as pd

# Define the constant for the column to extract
COLUMN_TO_EXTRACT = '130Byte'

# Path to the input CSV file
input_csv_path = '../DataExchange/data_header_signature_malicious_4-345_Bytes.csv'
# Path to the output CSV file
output_csv_path = '../DataExchange/extracted_column_130.csv'

# Load the CSV file
df = pd.read_csv(input_csv_path)

# Extract the first column and the specified column into a new DataFrame
extracted_columns_df = df.iloc[:, [0]].join(df[[COLUMN_TO_EXTRACT]])

# Output the extracted columns to another CSV
extracted_columns_df.to_csv(output_csv_path, index=False)

print(f"The first column and the column '{COLUMN_TO_EXTRACT}' have been extracted to {output_csv_path}.")
