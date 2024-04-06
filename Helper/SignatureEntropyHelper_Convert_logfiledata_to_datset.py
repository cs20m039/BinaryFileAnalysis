# Raw data as a multiline string
raw_data = """
Pattern, Total, Ransomware, Benign, Unknown, Time\
50, 544861, 36, 544678, 147, 359.28
100, 544854, 36, 544671, 147, 4299.27
150, 542015, 0, 541868, 147, 347.82
200, 541857, 0, 541710, 147, 351.03
250, 541859, 0, 541712, 147, 361.10
300, 541861, 0, 541714, 147, 377.96
350, 541863, 0, 541716, 147, 380.04
400, 541865, 0, 541718, 147, 361.40
450, 541865, 0, 541718, 147, 371.62
500, 542635, 0, 542488, 147, 380.93
"""

# Process the raw data
lines = raw_data.strip().split("\n")
columns = [line.split(", ") for line in lines]

# Initialize dictionaries to store processed data
converted_data = {header: [] for header in columns[0]}
for row in columns[1:]:
    for i, value in enumerate(row):
        header = columns[0][i]
        if header not in ["Pattern", "Total", "Ransomware", "Benign", "Unknown"]:  # Convert to float for 'Time'
            converted_data[header].append(float(value))
        else:  # Convert to int for the rest
            converted_data[header].append(int(value))

# Prepare the new format
new_format = {
    "Pattern": converted_data["Pattern"],
    "Sig_RW": converted_data["Ransomware"],
    "Sig_BG": converted_data["Benign"],
    "Sig_UK": converted_data["Unknown"]
}
"""
new_format = {
    "Pattern": converted_data["Pattern"],
    "Entr_RW": converted_data["Ransomware"],
    "Entr_BG": converted_data["Benign"],
    "Entr_UK": converted_data["Unknown"]
}
"""
print(new_format)
