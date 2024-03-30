import pandas as pd

# Constant values
COLUMN_TO_EXTRACT = '130Byte'
ADDITIONAL_COLUMN_NAME = 'AdditionalColumn'
ADDITIONAL_COLUMN_VALUE = 0

# Paths
input_csv_path = '../DataPreparation/data_header_signature_benign_4-345_Bytes.csv'
# Path to the output CSV file
output_csv_path = '../DataExchange/extract_signature_benign_130.csv'

# Load the CSV
df = pd.read_csv(input_csv_path)

# Create a new DataFrame with the first column, an additional column with a constant value, and the specified column
df[ADDITIONAL_COLUMN_NAME] = ADDITIONAL_COLUMN_VALUE
extracted_columns_df = df.iloc[:, [0]].join(df[[ADDITIONAL_COLUMN_NAME, COLUMN_TO_EXTRACT]])

# Output to CSV
extracted_columns_df.to_csv(output_csv_path, index=False)

print(f"Updated CSV with '{COLUMN_TO_EXTRACT}' and an additional column has been saved to {output_csv_path}.")
