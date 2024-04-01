# Original pattern lengths for benign data
pattern_length_benign = [4, 5, 6, 7, 8, 10, 11, 12, 16, 18, 24, 25, 60, 64, 128, 129, 134, 136]

# Function to replace 0s with the first non-zero value from the right in a list
def fill_zeros_from_right_v2(data_list):
    filled_list = []
    last_non_zero = '0'  # Using '0' as placeholder for string-based percentage; will work for counts too.
    for item in reversed(data_list):
        if item != 0 and item != "0%":
            last_non_zero = item
        filled_list.append(last_non_zero)
    return list(reversed(filled_list))

# Original lists with '0' values (redefined for completeness)
new_file_count_benign = [2628, 2627, 2620, 2501, 2472, 2456, 0, 2266, 2232, 0, 1806, 1738, 1664, 1598, 1567, 98, 30, 3]
new_different_patterns_benign = [7, 9, 7, 7, 8, 7, 0, 5, 5, 0, 4, 3, 1, 13, 13, 25, 2, 3]
new_percentage_benign = ["26.28%", "26.27%", "26.20%", "25.01%", "24.72%", "24.56%", "0%", "22.66%", "22.32%", "0%", "18.06%", "17.38%", "16.64%", "15.98%", "15.67%", "0.98%", "0.30%", "0.03%"]
new_file_count_malicious = [272, 271, 261, 0, 248, 247, 244, 0, 236, 230, 227, 216, 211, 0, 209, 127, 82, 81]
new_different_patterns_malicious = [7, 9, 7, 0, 8, 7, 5, 0, 5, 4, 4, 3, 1, 0, 13, 25, 2, 3]
new_percentage_malicious = ["97.14%", "96.79%", "93.21%", "0%", "88.57%", "88.21%", "87.14%", "0%", "84.29%", "82.14%", "81.07%", "77.14%", "75.36%", "0%", "74.64%", "45.36%", "29.29%", "28.93%"]

# Applying the function to all new lists
new_file_count_benign_filled = fill_zeros_from_right_v2(new_file_count_benign)
new_different_patterns_benign_filled = fill_zeros_from_right_v2(new_different_patterns_benign)
new_percentage_benign_filled = fill_zeros_from_right_v2(new_percentage_benign)
new_file_count_malicious_filled = fill_zeros_from_right_v2(new_file_count_malicious)
new_different_patterns_malicious_filled = fill_zeros_from_right_v2(new_different_patterns_malicious)
new_percentage_malicious_filled = fill_zeros_from_right_v2(new_percentage_malicious)

# Printing the pattern lengths and filled lists
print("Pattern Length Benign:", pattern_length_benign)
print("New File Count Malicious Filled:", new_file_count_malicious_filled)
print("New Different Patterns Malicious Filled:", new_different_patterns_malicious_filled)
print("New Percentage Malicious Filled:", new_percentage_malicious_filled)
print("New File Count Benign Filled:", new_file_count_benign_filled)
print("New Different Patterns Benign Filled:", new_different_patterns_benign_filled)
print("New Percentage Benign Filled:", new_percentage_benign_filled)

