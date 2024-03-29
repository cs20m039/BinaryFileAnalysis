import os
import pandas as pd


def analyze_directory(path):
    file_sizes = []
    file_extensions = []

    # Traverse the directory structure
    for root, dirs, files in os.walk(path):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                size = os.path.getsize(full_path)
                _, ext = os.path.splitext(file)
                ext = ext.lower() if ext else 'no_extension'  # Handle files without extensions
                file_sizes.append(size)
                file_extensions.append(ext)
            except Exception as e:
                print(f"Error processing file {file}: {e}")

    # Create a DataFrame from the collected data
    df = pd.DataFrame({
        'Size': file_sizes,
        'Extension': file_extensions
    })

    return df


import pandas as pd

def print_detailed_analysis(df):
    # Adjust pandas display options for floating-point numbers
    pd.set_option('display.float_format', '{:.2e}'.format)  # Scientific notation
    pd.set_option('display.max_rows', None)  # No limit to the number of rows displayed

    # File size distribution in scientific notation
    print("File Size Distribution (Scientific Notation):")
    print(df['Size'].describe())

    # Switch to decimal format for file size distribution
    pd.set_option('display.float_format', '{:.2f}'.format)  # Decimal notation
    print("\nFile Size Distribution (Decimal):")
    print(df['Size'].describe())

    # Reset display format to default
    pd.reset_option('display.float_format')

    print("\nFile Types Found (unique):")
    file_types = df['Extension'].unique()
    print(f"Total unique file types: {len(file_types)}")
    for file_type in sorted(file_types):
        print(file_type)

    # File type (extension) counts
    print("\nFile Type Counts:")
    print(df['Extension'].value_counts())



# Specify the directory you want to analyze
directory_path = ('/home/cs20m039/thesis/dataset/benign/macOS')

# Perform the analysis
df = analyze_directory(directory_path)

# Print out the detailed analysis
print_detailed_analysis(df)
