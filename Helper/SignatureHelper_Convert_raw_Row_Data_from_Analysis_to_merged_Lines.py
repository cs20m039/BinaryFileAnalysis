
# Original data
pattern_length_benign = 4, 5, 6, 7, 8, 10, 12, 16, 24, 25, 60, 64, 128, 129, 134, 136
different_patterns_benign = 7, 9, 7, 7, 8, 7, 5, 5, 4, 3, 1, 13, 13, 25, 2, 3
file_count_benign = 2628, 2627, 2620, 2501, 2472, 2456, 2266, 2232, 1806, 1738, 1664, 1598, 1567, 98, 30, 3
percentage_benign = "26.28%", "26.27%", "26.20%", "25.01%", "24.72%", "24.56%", "22.66%", "22.32%", "18.06%", "17.38%", "16.64%", "15.98%", "15.67%", "0.98%", "0.30%", "0.03%"

pattern_length_malicious = 4, 5, 6, 8, 10, 11, 16, 18, 24, 25, 60, 128, 129, 134, 136
different_patterns_malicious = 7, 9, 7, 8, 7, 5, 5, 4, 4, 3, 1, 13, 25, 2, 3
file_count_malicious = 272, 271, 261, 248, 247, 244, 236, 230, 227, 216, 211, 209, 127, 82, 81
percentage_malicious = "97.14%", "96.79%", "93.21%", "88.57%", "88.21%", "87.14%", "84.29%", "82.14%", "81.07%", "77.14%", "75.36%", "74.64%", "45.36%", "29.29%", "28.93%"

# Merging pattern lengths and initializing new lists
# Merging pattern lengths and initializing new lists for all attributes
merged_pattern_length = sorted(set(pattern_length_benign + pattern_length_malicious))
new_file_count_benign = []
new_file_count_malicious = []
new_different_patterns_benign = []
new_percentage_benign = []
new_different_patterns_malicious = []
new_percentage_malicious = []

# Populating new lists based on merged_pattern_length
for pattern_length in merged_pattern_length:
    if pattern_length in pattern_length_benign:
        index = pattern_length_benign.index(pattern_length)
        new_file_count_benign.append(file_count_benign[index])
        new_different_patterns_benign.append(different_patterns_benign[index])
        new_percentage_benign.append(percentage_benign[index])
    else:
        new_file_count_benign.append(0)
        new_different_patterns_benign.append(0)
        new_percentage_benign.append("0%")

    if pattern_length in pattern_length_malicious:
        index = pattern_length_malicious.index(pattern_length)
        new_file_count_malicious.append(file_count_malicious[index])
        new_different_patterns_malicious.append(different_patterns_malicious[index])
        new_percentage_malicious.append(percentage_malicious[index])
    else:
        new_file_count_malicious.append(0)
        new_different_patterns_malicious.append(0)
        new_percentage_malicious.append("0%")

# Displaying the updated data
print("Merged Pattern Lengths:", merged_pattern_length)
print("New File Count Benign:", new_file_count_benign)
print("New Different Patterns Benign:", new_different_patterns_benign)
print("New Percentage Benign:", new_percentage_benign)
print("New File Count Malicious:", new_file_count_malicious)
print("New Different Patterns Malicious:", new_different_patterns_malicious)
print("New Percentage Malicious:", new_percentage_malicious)




