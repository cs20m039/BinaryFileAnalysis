# Original pattern lengths for benign data
pattern_length_benign = [ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 188, 190, 191, 194, 195, 196, 197, 198, 200, 201, 202, 210, 219, 226, 230, 231, 232, 233, 238, 239, 240, 243, 246, 247, 251, 253, 254, 255, 256, 343, 344]

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
new_file_count_benign = [2, 3, 4, 4, 6, 7, 8, 10, 13, 13, 12, 13, 12, 15, 13, 14, 16, 17, 20, 19, 18, 18, 20, 22, 20, 21, 20, 20, 20, 22, 19, 20, 19, 23, 21, 20, 19, 23, 22, 25, 21, 19, 22, 18, 19, 21, 18, 15, 16, 13, 19, 13, 14, 16, 11, 18, 13, 14, 0, 13, 17, 12, 10, 14, 13, 10, 11, 11, 15, 13, 9, 14, 10, 12, 14, 10, 11, 10, 10, 10, 10, 8, 8, 9, 8, 9, 8, 8, 9, 8, 10, 11, 7, 7, 7, 10, 7, 7, 9, 10, 9, 8, 7, 7, 8, 8, 8, 7, 6, 8, 5, 6, 9, 7, 7, 8, 5, 6, 8, 8, 6, 6, 7, 8, 10, 10, 14, 16, 16, 20, 24, 26, 26, 27, 35, 35, 21, 28, 37, 23, 35, 33, 34, 31, 37, 35, 43, 32, 34, 34, 28, 29, 34, 27, 24, 24, 24, 23, 21, 15, 26, 18, 19, 18, 14, 14, 10, 11, 10, 11, 11, 6, 6, 5, 2, 2, 6, 5, 9, 4, 8, 3, 1, 2, 0, 0, 0, 1, 2, 1, 2, 4, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 0]
new_different_patterns_benign = [8820, 9478, 8899, 8980, 9193, 8926, 6585, 5380, 5669, 4915, 4639, 3955, 4429, 3689, 4025, 3590, 3959, 3476, 3042, 2892, 2761, 2386, 2446, 2208, 2523, 2447, 2314, 2065, 2070, 1864, 2086, 1823, 1902, 2139, 2218, 2007, 2219, 2100, 1805, 1813, 1797, 1762, 1771, 1714, 1716, 1742, 1712, 1722, 1718, 1742, 1753, 1711, 1708, 1716, 1690, 1696, 1689, 1688, 0, 1704, 1723, 1690, 1704, 1687, 1659, 1670, 1680, 1653, 1695, 1700, 1643, 1667, 1658, 1667, 1736, 1684, 1657, 1683, 1655, 1648, 1646, 1645, 1644, 1643, 1641, 1651, 1647, 1644, 1648, 1641, 1644, 1646, 1641, 1640, 1641, 1644, 1640, 1642, 1650, 1658, 1647, 1636, 1637, 1641, 1638, 1642, 1635, 1638, 1637, 1636, 1633, 1635, 1643, 1637, 1635, 1636, 1633, 1634, 1638, 1642, 1634, 1637, 1638, 1639, 1614, 1588, 1075, 993, 985, 1363, 905, 806, 1159, 1284, 1248, 1011, 1122, 1159, 517, 735, 482, 690, 456, 459, 323, 242, 377, 327, 221, 148, 137, 140, 215, 98, 123, 114, 78, 96, 56, 42, 63, 41, 40, 39, 34, 25, 19, 22, 20, 24, 18, 10, 8, 5, 2, 4, 7, 6, 11, 4, 9, 3, 1, 2, 0, 0, 0, 1, 2, 1, 2, 4, 2, 1, 2, 1, 3, 1, 2, 1, 3, 1, 3, 1, 2, 1, 2, 1, 2, 1, 2, 1, 0]
new_percentage_benign = [88.2, 94.78, 88.99, 89.8, 91.93, 89.26, 65.85, 53.8, 56.69, 49.15, 46.39, 39.55, 44.29, 36.89, 40.25, 35.9, 39.59, 34.76, 30.42, 28.92, 27.61, 23.86, 24.46, 22.08, 25.23, 24.47, 23.14, 20.65, 20.7, 18.64, 20.86, 18.23, 19.02, 21.39, 22.18, 20.07, 22.19, 21.0, 18.05, 18.13, 17.97, 17.62, 17.71, 17.14, 17.16, 17.42, 17.12, 17.22, 17.18, 17.42, 17.53, 17.11, 17.08, 17.16, 16.9, 16.96, 16.89, 16.88, 0, 17.04, 17.23, 16.9, 17.04, 16.87, 16.59, 16.7, 16.8, 16.53, 16.95, 17.0, 16.43, 16.67, 16.58, 16.67, 17.36, 16.84, 16.57, 16.83, 16.55, 16.48, 16.46, 16.45, 16.44, 16.43, 16.41, 16.51, 16.47, 16.44, 16.48, 16.41, 16.44, 16.46, 16.41, 16.4, 16.41, 16.44, 16.4, 16.42, 16.5, 16.58, 16.47, 16.36, 16.37, 16.41, 16.38, 16.42, 16.35, 16.38, 16.37, 16.36, 16.33, 16.35, 16.43, 16.37, 16.35, 16.36, 16.33, 16.34, 16.38, 16.42, 16.34, 16.37, 16.38, 16.39, 16.14, 15.88, 10.75, 9.93, 9.85, 13.63, 9.05, 8.06, 11.59, 12.84, 12.48, 10.11, 11.22, 11.59, 5.17, 7.35, 4.82, 6.9, 4.56, 4.59, 3.23, 2.42, 3.77, 3.27, 2.21, 1.48, 1.37, 1.4, 2.15, 0.98, 1.23, 1.14, 0.78, 0.96, 0.56, 0.42, 0.63, 0.41, 0.4, 0.39, 0.34, 0.25, 0.19, 0.22, 0.2, 0.24, 0.18, 0.1, 0.08, 0.05, 0.02, 0.04, 0.07, 0.06, 0.11, 0.04, 0.09, 0.03, 0.01, 0.02, 0, 0, 0, 0.01, 0.02, 0.01, 0.02, 0.04, 0.02, 0.01, 0.02, 0.01, 0.03, 0.01, 0.02, 0.01, 0.03, 0.01, 0.03, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.0]
new_file_count_malicious = [13, 0, 0, 0, 0, 0, 0, 0, 13, 13, 0, 0, 0, 15, 13, 14, 16, 17, 20, 19, 18, 18, 0, 22, 20, 21, 20, 20, 20, 22, 19, 20, 19, 23, 0, 20, 19, 23, 22, 25, 21, 19, 22, 18, 19, 21, 18, 15, 16, 13, 19, 0, 14, 16, 11, 18, 13, 14, 15, 13, 17, 12, 10, 14, 13, 10, 11, 11, 15, 13, 9, 14, 10, 12, 14, 10, 11, 10, 10, 10, 10, 0, 8, 9, 8, 9, 0, 8, 9, 8, 0, 11, 0, 7, 7, 10, 0, 7, 9, 10, 9, 8, 7, 7, 8, 8, 0, 7, 0, 8, 5, 6, 9, 7, 7, 8, 5, 6, 8, 0, 0, 6, 7, 8, 10, 10, 14, 0, 0, 20, 0, 26, 26, 27, 35, 35, 21, 28, 37, 23, 35, 33, 34, 31, 37, 35, 43, 32, 34, 34, 28, 29, 34, 27, 24, 24, 24, 23, 21, 15, 26, 18, 19, 18, 14, 14, 10, 11, 10, 11, 11, 6, 6, 5, 2, 2, 6, 5, 9, 4, 8, 3, 1, 2, 1, 1, 1, 1, 2, 1, 2, 4, 2, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 0]
new_different_patterns_malicious = [280, 0, 0, 0, 0, 0, 0, 0, 280, 279, 0, 0, 0, 280, 275, 271, 279, 277, 280, 272, 274, 267, 0, 274, 272, 269, 270, 273, 272, 264, 259, 261, 259, 270, 0, 266, 262, 269, 263, 261, 257, 258, 261, 256, 258, 262, 253, 248, 253, 241, 253, 0, 241, 244, 239, 248, 246, 242, 244, 243, 251, 250, 242, 245, 243, 236, 244, 222, 249, 239, 222, 229, 222, 239, 237, 220, 235, 238, 234, 218, 221, 0, 216, 217, 216, 217, 0, 216, 217, 215, 0, 223, 0, 214, 215, 218, 0, 215, 217, 218, 217, 216, 214, 213, 215, 216, 0, 215, 0, 214, 211, 216, 219, 212, 213, 214, 211, 212, 213, 0, 0, 214, 215, 216, 212, 205, 208, 0, 0, 209, 0, 211, 195, 184, 167, 186, 162, 171, 177, 172, 169, 165, 124, 170, 169, 171, 200, 143, 116, 87, 86, 50, 105, 66, 43, 70, 71, 62, 34, 21, 45, 34, 30, 28, 48, 22, 38, 17, 12, 14, 22, 11, 8, 7, 2, 4, 10, 6, 13, 5, 9, 4, 1, 3, 8, 1, 3, 1, 5, 1, 5, 7, 5, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 0]
new_percentage_malicious = [100.0, 0, 0, 0, 0, 0, 0, 0, 100.0, 99.64, 0, 0, 0, 100.0, 98.21, 96.79, 99.64, 98.93, 100.0, 97.14, 97.86, 95.36, 0, 97.86, 97.14, 96.07, 96.43, 97.5, 97.14, 94.29, 92.5, 93.21, 92.5, 96.43, 0, 95.0, 93.57, 96.07, 93.93, 93.21, 91.79, 92.14, 93.21, 91.43, 92.14, 93.57, 90.36, 88.57, 90.36, 86.07, 90.36, 0, 86.07, 87.14, 85.36, 88.57, 87.86, 86.43, 87.14, 86.79, 89.64, 89.29, 86.43, 87.5, 86.79, 84.29, 87.14, 79.29, 88.93, 85.36, 79.29, 81.79, 79.29, 85.36, 84.64, 78.57, 83.93, 85.0, 83.57, 77.86, 78.93, 0, 77.14, 77.5, 77.14, 77.5, 0, 77.14, 77.5, 76.79, 0, 79.64, 0, 76.43, 76.79, 77.86, 0, 76.79, 77.5, 77.86, 77.5, 77.14, 76.43, 76.07, 76.79, 77.14, 0, 76.79, 0, 76.43, 75.36, 77.14, 78.21, 75.71, 76.07, 76.43, 75.36, 75.71, 76.07, 0, 0, 76.43, 76.79, 77.14, 75.71, 73.21, 74.29, 0, 0, 74.64, 0, 75.36, 69.64, 65.71, 59.64, 66.43, 57.86, 61.07, 63.21, 61.43, 60.36, 58.93, 44.29, 60.71, 60.36, 61.07, 71.43, 51.07, 41.43, 31.07, 30.71, 17.86, 37.5, 23.57, 15.36, 25.0, 25.36, 22.14, 12.14, 7.5, 16.07, 12.14, 10.71, 10.0, 17.14, 7.86, 13.57, 6.07, 4.29, 5.0, 7.86, 3.93, 2.86, 2.5, 0.71, 1.43, 3.57, 2.14, 4.64, 1.79, 3.21, 1.43, 0.36, 1.07, 2.86, 0.36, 1.07, 0.36, 1.79, 0.36, 1.79, 2.5, 1.79, 0.36, 0.71, 0, 0, 0, 0, 0, 0, 0, 0, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, 0.0]

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

