import pandas as pd
import matplotlib.pyplot as plt

# Specify the exact names of the CSV files to read
file_names = [
    'datashare/entropy_bianlian.csv',
    'datashare/entropy_kuiper.csv',
    'datashare/entropy_play.csv',
    'datashare/entropy_blackbasta.csv',
    'datashare/entropy_royal.csv',
    'datashare/entropy_blackcat.csv',
    'datashare/entropy_avoslocker.csv',
    'datashare/entropy_conti.csv',
    'datashare/entropy_evilquest.csv',
    'datashare/entropy_lockbit.csv',
    'datashare/entropy_clop.csv',
    'datashare/entropy_keranger.csv'
]

# Custom labels for each file to be used in the plot
file_labels = [
    'Bianlian',
    'Kuiper',
    'Play',
    'Blackbasta',
    'Royal',
    'Blackcat',
    'Avoslocker',
    'Conti',
    'Evilquest',
    'Lockbit',
    'Clop',
    'Keranger'
]

# Read and store entropy values from each file
entropy_values = []

for file_name in file_names:
    try:
        df = pd.read_csv(file_name)
        entropy_values.append(df['Entropy'].values)
    except FileNotFoundError:
        print(f'File not found: {file_name}')
    except Exception as e:
        print(f'An error occurred while processing {file_name}: {e}')

# Check if all files were processed successfully
if len(entropy_values) != len(file_labels):
    print("Mismatch in number of processed files and labels. Check the files and try again.")
else:
    # Generate a box plot
    plt.figure(figsize=(10, 6))  # Adjust figure size here for better fit
    box = plt.boxplot(entropy_values, labels=file_labels, patch_artist=True, widths=0.6)

    # Increase font sizes and adjust styles
#   plt.title('Entropy Distribution by Platform', fontsize=14)  # Adjust title font size
#   plt.ylabel('Entropy Values', fontsize=12)  # Adjust Y-axis label font size
#   plt.xlabel('Platform', fontsize=12)  # Adjust X-axis label font size
    plt.xticks(rotation=45, fontsize=15)  # Adjust X-axis tick font size
    plt.yticks(fontsize=15)  # Adjust Y-axis tick font size
    plt.grid(True, linestyle='--', linewidth=0.5)  # Adjust grid style and linewidth

    # Style adjustments for boxplot elements
    for patch in box['boxes']:
        patch.set_facecolor('lightblue')  # Set the color of the box
    for whisker in box['whiskers']:
        whisker.set(color='blue', linewidth=1.5)  # Set whisker color and linewidth
    for cap in box['caps']:
        cap.set(color='darkblue', linewidth=1.5)  # Set cap color and linewidth

    plt.tight_layout()

    # Save the plot to a file
    plt.savefig('entropy_values_boxplot.png', dpi=300)  # Adjust DPI for higher resolution
    # Optionally, display the plot
    plt.show()