def transform_data_to_latex_rows(pattern_lengths, ransomware_files, ransomware_percents, benign_files, benign_percents):
    """
    Transforms lists of data into a formatted LaTeX row string.

    Parameters:
    - pattern_lengths: List of pattern lengths.
    - ransomware_files: List of ransomware file counts.
    - ransomware_percents: List of ransomware percentage values.
    - benign_files: List of benign file counts.
    - benign_percents: List of benign percentage values.

    Returns:
    - A string of LaTeX formatted rows.
    """
    latex_rows = []
    for pl, rf, rp, bf, bp in zip(pattern_lengths, ransomware_files, ransomware_percents, benign_files, benign_percents):
        row = f"{pl} & {rf} & {rp} & {bf} & {bp} \\\\"
        latex_rows.append(row)
    return "\n".join(latex_rows)


#header

pattern_lengths = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 188, 190, 191, 194, 195, 196, 197, 198, 200, 201, 202, 210, 219, 226, 230, 231, 232, 233, 238, 239, 240, 243, 246, 247, 251, 253, 254, 255, 256, 343, 344]
ransomware_files = [280, 280, 280, 280, 280, 280, 280, 280, 280, 279, 280, 280, 280, 280, 275, 271, 279, 277, 280, 272, 274, 267, 274, 274, 272, 269, 270, 273, 272, 264, 259, 261, 259, 270, 266, 266, 262, 269, 263, 261, 257, 258, 261, 256, 258, 262, 253, 248, 253, 241, 253, 241, 241, 244, 239, 248, 246, 242, 244, 243, 251, 250, 242, 245, 243, 236, 244, 222, 249, 239, 222, 229, 222, 239, 237, 220, 235, 238, 234, 218, 221, 216, 216, 217, 216, 217, 216, 216, 217, 215, 223, 223, 214, 214, 215, 218, 215, 215, 217, 218, 217, 216, 214, 213, 215, 216, 215, 215, 214, 214, 211, 216, 219, 212, 213, 214, 211, 212, 213, 214, 214, 214, 215, 216, 212, 205, 208, 209, 209, 209, 211, 211, 195, 184, 167, 186, 162, 171, 177, 172, 169, 165, 124, 170, 169, 171, 200, 143, 116, 87, 86, 50, 105, 66, 43, 70, 71, 62, 34, 21, 45, 34, 30, 28, 48, 22, 38, 17, 12, 14, 22, 11, 8, 7, 2, 4, 10, 6, 13, 5, 9, 4, 1, 3, 8, 1, 3, 1, 5, 1, 5, 7, 5, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, '0']
ransomware_percents = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 99.64, 100.0, 100.0, 100.0, 100.0, 98.21, 96.79, 99.64, 98.93, 100.0, 97.14, 97.86, 95.36, 97.86, 97.86, 97.14, 96.07, 96.43, 97.5, 97.14, 94.29, 92.5, 93.21, 92.5, 96.43, 95.0, 95.0, 93.57, 96.07, 93.93, 93.21, 91.79, 92.14, 93.21, 91.43, 92.14, 93.57, 90.36, 88.57, 90.36, 86.07, 90.36, 86.07, 86.07, 87.14, 85.36, 88.57, 87.86, 86.43, 87.14, 86.79, 89.64, 89.29, 86.43, 87.5, 86.79, 84.29, 87.14, 79.29, 88.93, 85.36, 79.29, 81.79, 79.29, 85.36, 84.64, 78.57, 83.93, 85.0, 83.57, 77.86, 78.93, 77.14, 77.14, 77.5, 77.14, 77.5, 77.14, 77.14, 77.5, 76.79, 79.64, 79.64, 76.43, 76.43, 76.79, 77.86, 76.79, 76.79, 77.5, 77.86, 77.5, 77.14, 76.43, 76.07, 76.79, 77.14, 76.79, 76.79, 76.43, 76.43, 75.36, 77.14, 78.21, 75.71, 76.07, 76.43, 75.36, 75.71, 76.07, 76.43, 76.43, 76.43, 76.79, 77.14, 75.71, 73.21, 74.29, 74.64, 74.64, 74.64, 75.36, 75.36, 69.64, 65.71, 59.64, 66.43, 57.86, 61.07, 63.21, 61.43, 60.36, 58.93, 44.29, 60.71, 60.36, 61.07, 71.43, 51.07, 41.43, 31.07, 30.71, 17.86, 37.5, 23.57, 15.36, 25.0, 25.36, 22.14, 12.14, 7.5, 16.07, 12.14, 10.71, 10.0, 17.14, 7.86, 13.57, 6.07, 4.29, 5.0, 7.86, 3.93, 2.86, 2.5, 0.71, 1.43, 3.57, 2.14, 4.64, 1.79, 3.21, 1.43, 0.36, 1.07, 2.86, 0.36, 1.07, 0.36, 1.79, 0.36, 1.79, 2.5, 1.79, 0.36, 0.71, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, 0.71, 0.36, '0']
benign_files = [8820, 9478, 8899, 8980, 9193, 8926, 6585, 5380, 5669, 4915, 4639, 3955, 4429, 3689, 4025, 3590, 3959, 3476, 3042, 2892, 2761, 2386, 2446, 2208, 2523, 2447, 2314, 2065, 2070, 1864, 2086, 1823, 1902, 2139, 2218, 2007, 2219, 2100, 1805, 1813, 1797, 1762, 1771, 1714, 1716, 1742, 1712, 1722, 1718, 1742, 1753, 1711, 1708, 1716, 1690, 1696, 1689, 1688, 1704, 1704, 1723, 1690, 1704, 1687, 1659, 1670, 1680, 1653, 1695, 1700, 1643, 1667, 1658, 1667, 1736, 1684, 1657, 1683, 1655, 1648, 1646, 1645, 1644, 1643, 1641, 1651, 1647, 1644, 1648, 1641, 1644, 1646, 1641, 1640, 1641, 1644, 1640, 1642, 1650, 1658, 1647, 1636, 1637, 1641, 1638, 1642, 1635, 1638, 1637, 1636, 1633, 1635, 1643, 1637, 1635, 1636, 1633, 1634, 1638, 1642, 1634, 1637, 1638, 1639, 1614, 1588, 1075, 993, 985, 1363, 905, 806, 1159, 1284, 1248, 1011, 1122, 1159, 517, 735, 482, 690, 456, 459, 323, 242, 377, 327, 221, 148, 137, 140, 215, 98, 123, 114, 78, 96, 56, 42, 63, 41, 40, 39, 34, 25, 19, 22, 20, 24, 18, 10, 8, 5, 2, 4, 7, 6, 11, 4, 9, 3, 1, 2, 1, 1, 1, 1, 2, 1, 2, 4, 2, 1, 2, 1, 3, 1, 2, 1, 3, 1, 3, 1, 2, 1, 2, 1, 2, 1, 2, 1, '0']
benign_percents = [88.2, 94.78, 88.99, 89.8, 91.93, 89.26, 65.85, 53.8, 56.69, 49.15, 46.39, 39.55, 44.29, 36.89, 40.25, 35.9, 39.59, 34.76, 30.42, 28.92, 27.61, 23.86, 24.46, 22.08, 25.23, 24.47, 23.14, 20.65, 20.7, 18.64, 20.86, 18.23, 19.02, 21.39, 22.18, 20.07, 22.19, 21.0, 18.05, 18.13, 17.97, 17.62, 17.71, 17.14, 17.16, 17.42, 17.12, 17.22, 17.18, 17.42, 17.53, 17.11, 17.08, 17.16, 16.9, 16.96, 16.89, 16.88, 17.04, 17.04, 17.23, 16.9, 17.04, 16.87, 16.59, 16.7, 16.8, 16.53, 16.95, 17.0, 16.43, 16.67, 16.58, 16.67, 17.36, 16.84, 16.57, 16.83, 16.55, 16.48, 16.46, 16.45, 16.44, 16.43, 16.41, 16.51, 16.47, 16.44, 16.48, 16.41, 16.44, 16.46, 16.41, 16.4, 16.41, 16.44, 16.4, 16.42, 16.5, 16.58, 16.47, 16.36, 16.37, 16.41, 16.38, 16.42, 16.35, 16.38, 16.37, 16.36, 16.33, 16.35, 16.43, 16.37, 16.35, 16.36, 16.33, 16.34, 16.38, 16.42, 16.34, 16.37, 16.38, 16.39, 16.14, 15.88, 10.75, 9.93, 9.85, 13.63, 9.05, 8.06, 11.59, 12.84, 12.48, 10.11, 11.22, 11.59, 5.17, 7.35, 4.82, 6.9, 4.56, 4.59, 3.23, 2.42, 3.77, 3.27, 2.21, 1.48, 1.37, 1.4, 2.15, 0.98, 1.23, 1.14, 0.78, 0.96, 0.56, 0.42, 0.63, 0.41, 0.4, 0.39, 0.34, 0.25, 0.19, 0.22, 0.2, 0.24, 0.18, 0.1, 0.08, 0.05, 0.02, 0.04, 0.07, 0.06, 0.11, 0.04, 0.09, 0.03, 0.01, 0.02, 0.01, 0.01, 0.01, 0.01, 0.02, 0.01, 0.02, 0.04, 0.02, 0.01, 0.02, 0.01, 0.03, 0.01, 0.02, 0.01, 0.03, 0.01, 0.03, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, 0.02, 0.01, '0']

"""
#Header and Footer Combi
pattern_lengths = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 181, 182, 183, 184, 185, 321, 322]
ransomware_files = [280, 280, 280, 280, 280, 280, 279, 276, 270, 272, 260, 254, 251, 252, 252, 239, 242, 237, 234, 232, 239, 230, 230, 227, 228, 224, 227, 221, 222, 214, 215, 213, 214, 216, 215, 222, 214, 214, 210, 214, 205, 198, 217, 195, 191, 211, 210, 200, 193, 196, 195, 200, 200, 199, 195, 200, 194, 181, 171, 180, 189, 179, 181, 183, 174, 179, 185, 160, 164, 186, 157, 158, 161, 179, 160, 164, 172, 163, 146, 155, 154, 161, 158, 148, 141, 149, 147, 138, 148, 126, 123, 128, 149, 138, 139, 141, 145, 128, 148, 137, 141, 139, 116, 138, 115, 131, 111, 123, 134, 125, 121, 121, 120, 119, 134, 138, 116, 123, 120, 119, 125, 127, 126, 114, 143, 111, 126, 104, 103, 99, 101, 100, 101, 95, 96, 92, 78, 76, 82, 79, 80, 79, 78, 73, 78, 72, 71, 58, 74, 58, 54, 42, 11, 32, 18, 17, 24, 16, 19, 19, 7, 19, 10, 9, 9, 30, 6, 4, 2, 3, 3, 3, 1, 2, 3, 6, 2, 3, 1, '0']
ransomware_percents = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 99.64, 98.57, 96.43, 97.14, 92.86, 90.71, 89.64, 90.0, 90.0, 85.36, 86.43, 84.64, 83.57, 82.86, 85.36, 82.14, 82.14, 81.07, 81.43, 80.0, 81.07, 78.93, 79.29, 76.43, 76.79, 76.07, 76.43, 77.14, 76.79, 79.29, 76.43, 76.43, 75.0, 76.43, 73.21, 70.71, 77.5, 69.64, 68.21, 75.36, 75.0, 71.43, 68.93, 70.0, 69.64, 71.43, 71.43, 71.07, 69.64, 71.43, 69.29, 64.64, 61.07, 64.29, 67.5, 63.93, 64.64, 65.36, 62.14, 63.93, 66.07, 57.14, 58.57, 66.43, 56.07, 56.43, 57.5, 63.93, 57.14, 58.57, 61.43, 58.21, 52.14, 55.36, 55.0, 57.5, 56.43, 52.86, 50.36, 53.21, 52.5, 49.29, 52.86, 45.0, 43.93, 45.71, 53.21, 49.29, 49.64, 50.36, 51.79, 45.71, 52.86, 48.93, 50.36, 49.64, 41.43, 49.29, 41.07, 46.79, 39.64, 43.93, 47.86, 44.64, 43.21, 43.21, 42.86, 42.5, 47.86, 49.29, 41.43, 43.93, 42.86, 42.5, 44.64, 45.36, 45.0, 40.71, 51.07, 39.64, 45.0, 37.14, 36.79, 35.36, 36.07, 35.71, 36.07, 33.93, 34.29, 32.86, 27.86, 27.14, 29.29, 28.21, 28.57, 28.21, 27.86, 26.07, 27.86, 25.71, 25.36, 20.71, 26.43, 20.71, 19.29, 15.0, 3.93, 11.43, 6.43, 6.07, 8.57, 5.71, 6.79, 6.79, 2.5, 6.79, 3.57, 3.21, 3.21, 10.71, 2.14, 1.43, 0.71, 1.07, 1.07, 1.07, 0.36, 0.71, 1.07, 2.14, 0.71, 1.07, 0.36, '0']
benign_files = [8528, 8095, 7370, 3708, 4684, 3161, 2856, 2221, 2022, 1856, 1806, 1583, 1552, 1536, 1540, 1526, 1494, 1339, 1357, 1279, 1360, 1223, 1147, 1144, 1200, 1167, 1183, 1180, 1117, 1105, 1096, 1073, 1073, 1059, 1086, 1074, 1073, 1061, 1070, 1083, 1057, 1035, 1058, 1027, 1011, 1050, 1042, 1023, 1020, 1030, 1030, 1039, 1033, 1042, 1039, 1041, 1020, 984, 966, 985, 1012, 981, 989, 978, 953, 980, 964, 938, 940, 960, 942, 933, 942, 957, 958, 963, 927, 898, 903, 915, 940, 933, 929, 892, 891, 906, 897, 878, 908, 863, 855, 862, 884, 864, 867, 868, 887, 854, 887, 855, 864, 873, 829, 858, 822, 852, 820, 830, 837, 831, 830, 827, 827, 812, 846, 843, 811, 813, 816, 810, 818, 819, 813, 796, 847, 760, 775, 640, 569, 586, 575, 524, 446, 282, 451, 385, 314, 384, 423, 239, 393, 222, 358, 175, 214, 143, 118, 189, 140, 68, 37, 41, 45, 99, 34, 42, 50, 33, 21, 27, 14, 12, 13, 12, 14, 9, 8, 6, 4, 8, 4, 2, 1, 2, 3, 3, 1, 3, 1, '0']
benign_percents = [85.28, 80.95, 73.7, 37.08, 46.84, 31.61, 28.56, 22.21, 20.22, 18.56, 18.06, 15.83, 15.52, 15.36, 15.4, 15.26, 14.94, 13.39, 13.57, 12.79, 13.6, 12.23, 11.47, 11.44, 12.0, 11.67, 11.83, 11.8, 11.17, 11.05, 10.96, 10.73, 10.73, 10.59, 10.86, 10.74, 10.73, 10.61, 10.7, 10.83, 10.57, 10.35, 10.58, 10.27, 10.11, 10.5, 10.42, 10.23, 10.2, 10.3, 10.3, 10.39, 10.33, 10.42, 10.39, 10.41, 10.2, 9.84, 9.66, 9.85, 10.12, 9.81, 9.89, 9.78, 9.53, 9.8, 9.64, 9.38, 9.4, 9.6, 9.42, 9.33, 9.42, 9.57, 9.58, 9.63, 9.27, 8.98, 9.03, 9.15, 9.4, 9.33, 9.29, 8.92, 8.91, 9.06, 8.97, 8.78, 9.08, 8.63, 8.55, 8.62, 8.84, 8.64, 8.67, 8.68, 8.87, 8.54, 8.87, 8.55, 8.64, 8.73, 8.29, 8.58, 8.22, 8.52, 8.2, 8.3, 8.37, 8.31, 8.3, 8.27, 8.27, 8.12, 8.46, 8.43, 8.11, 8.13, 8.16, 8.1, 8.18, 8.19, 8.13, 7.96, 8.47, 7.6, 7.75, 6.4, 5.69, 5.86, 5.75, 5.24, 4.46, 2.82, 4.51, 3.85, 3.14, 3.84, 4.23, 2.39, 3.93, 2.22, 3.58, 1.75, 2.14, 1.43, 1.18, 1.89, 1.4, 0.68, 0.37, 0.41, 0.45, 0.99, 0.34, 0.42, 0.5, 0.33, 0.21, 0.27, 0.14, 0.12, 0.13, 0.12, 0.14, 0.09, 0.08, 0.06, 0.04, 0.08, 0.04, 0.02, 0.01, 0.02, 0.03, 0.03, 0.01, 0.03, 0.01, '0']
"""

"""
Header
pattern_lengths = [4, 5, 6, 7, 8, 10, 11, 12, 16, 18, 24, 25, 60, 64, 128, 129, 134, 136, 137]
benign_patterns = [7, 9, 7, 8, 8, 7, 5, 5, 5, 4, 4, 3, 1, 13, 13, 25, 2, 3, 0]
ransomware_files = [272, 271, 261, 248, 248, 247, 244, 236, 236, 230, 227, 216, 211, 209, 209, 127, 82, 81, 0]
ransomware_percents = [97.14, 96.79, 93.21, 88.57, 88.57, 88.21, 87.14, 84.29, 84.29, 82.14, 81.07, 77.14, 75.36, 74.64, 74.64, 45.36, 29.29, 28.93, 0.00]
ransomware_patterns = [7, 9, 7, 7, 8, 7, 5, 5, 5, 4, 4, 3, 1, 13, 13, 25, 2, 3, 0]
benign_files = [2628, 2627, 2620, 2501, 2472, 2456, 2266, 2266, 2232, 1806, 1806, 1738, 1664, 1598, 1567, 98, 30, 3, 0]
benign_percents = [26.28, 26.27, 26.20, 25.01, 24.72, 24.56, 22.66, 22.66, 22.32, 18.06, 18.06, 17.38, 16.64, 15.98, 15.67, 0.98, 0.30, 0.03, 0.00]
"""

"""
Footer Entropy
pattern_lengths = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 551, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 565, 566, 567, 568, 569, 570, 571, 578, 583, 585, 586, 587, 589, 593, 594, 595, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 610, 613, 614, 615, 616, 617, 618, 619, 621, 622, 623, 624, 626, 629, 633, 634, 636, 638, 640, 642, 643, 644, 647, 649, 650, 651, 654, 655, 656, 658, 659, 661, 662, 663, 664, 665, 668, 669, 672, 675, 677, 678, 679, 684, 686, 687, 688, 690, 694, 695, 697, 699, 701, 703, 705, 706, 707, 709, 712, 713, 716, 717, 719, 720, 721, 722, 723, 724, 725, 726, 729, 730, 731, 732, 734, 736, 737, 738, 739, 741, 742, 743, 745, 746, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 764, 765, 766, 767, 769, 770, 771, 773, 774, 775, 777, 778, 780, 782, 783, 784, 785, 786, 788, 789, 790, 792, 794, 795, 796, 797, 803, 804, 808, 809, 810, 812, 813, 815, 816, 817, 818, 819, 820, 821, 822, 823, 825, 826, 827, 828, 830, 831, 832, 833, 834, 835, 839, 840, 841, 842, 843, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 868, 869, 871, 872, 873, 875, 876, 878, 879, 880, 881, 883, 885, 886, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899, 900, 902, 903, 904, 905, 906, 910, 912, 914, 915, 917, 919, 921, 923, 924, 925, 927, 928, 929, 930, 931, 933, 934, 936, 938, 939, 940, 941, 984, 987, 989, 996, 1000, 1004, 1016, 1020, 1024, 1027, 1029, 1130, 1131, 1186, 1187, 1188, 1192, 1196, 1232, 1233, 1234, 1238, 1244, 1245, 1246, 1250, 1251, 1264, 1344, 1345, 1346, 1490, 1626, 1627, 1628, 1661, 1662, 1663, 1667, 1668, 1711, 1712, 1713, 1792, 1887, 2252, 2253, 2254, 2262, 2263, 2267, 2271, 2273, 2338, 2355, 2356, 2428, 2429, 2430, 2511, 2512, 2513, 2689, 2690, 2691, 2695, 2696, 2700, 2952, 2953, 2954, 3011, 3012, 3013, 3259, 3263, 3271, 3275, 3328, 3329, 3330, 3637, 3638, 3639, 3640, 3644, 3646, 3650, 3651, 3812, 3813, 3814, 3909, 4072, 4073, 4074, 4086, 4087, 4090, 4091, 4095, 4300, 4301, 4302, 4464, 4465, 4466, 4643, 4644, 4645, 4647, 4648, 4685, 4686, 4687, 4689, 4690, 5005, 5006, 5007, 5242, 5243, 5244, 5260, 5262, 5263, 5296, 5859, 5865, 5866, 5893, 5899, 6110, 6126, 6139, 6140, 6142, 6143, 6192, 6512, 6518, 6519, 6580, 7125, 7126, 7521, 7704, 7734, 7740, 7741, 7828, 7859, 7939, 8195, 8476, 9059, 9227, 9363, 9904, 9905, 9906]
ransomware_files = [280, 280, 280, 280, 280, 280, 280, 280, 279, 279, 279, 278, 280, 280, 279, 278, 278, 272, 273, 273, 276, 276, 274, 271, 275, 274, 270, 275, 270, 270, 271, 266, 265, 271, 267, 265, 261, 266, 258, 263, 265, 255, 254, 257, 254, 260, 256, 242, 251, 251, 237, 239, 243, 240, 240, 242, 255, 240, 233, 229, 241, 235, 233, 235, 251, 230, 231, 230, 231, 231, 225, 226, 218, 218, 215, 217, 225, 216, 215, 214, 215, 218, 216, 212, 214, 217, 215, 210, 217, 211, 210, 219, 213, 207, 211, 202, 208, 210, 203, 199, 205, 207, 202, 200, 207, 200, 205, 202, 198, 190, 200, 187, 193, 191, 205, 198, 196, 192, 184, 191, 194, 191, 185, 185, 205, 183, 199, 192, 192, 190, 193, 179, 172, 188, 193, 174, 194, 176, 180, 184, 194, 187, 181, 187, 191, 182, 178, 185, 185, 176, 173, 178, 186, 183, 180, 178, 187, 178, 172, 165, 166, 173, 170, 157, 163, 172, 157, 162, 165, 163, 168, 159, 153, 156, 158, 179, 171, 152, 160, 164, 169, 176, 162, 150, 159, 163, 159, 151, 166, 158, 148, 154, 151, 153, 151, 158, 164, 160, 157, 162, 167, 153, 155, 152, 154, 157, 156, 146, 152, 146, 151, 146, 143, 140, 143, 147, 148, 146, 138, 137, 148, 137, 132, 148, 157, 144, 138, 140, 137, 138, 146, 135, 139, 126, 131, 128, 137, 127, 139, 139, 126, 125, 134, 130, 133, 145, 150, 141, 138, 125, 126, 140, 148, 130, 127, 101, 105, 94, 114, 101, 100, 102, 95, 94, 97, 99, 103, 98, 98, 92, 91, 96, 96, 93, 93, 101, 95, 97, 91, 96, 103, 107, 93, 98, 95, 97, 96, 103, 94, 91, 85, 88, 89, 97, 87, 91, 90, 89, 82, 93, 94, 86, 83, 86, 88, 83, 82, 82, 81, 82, 85, 84, 96, 80, 82, 82, 85, 85, 79, 85, 81, 79, 81, 85, 85, 84, 82, 79, 82, 82, 84, 81, 77, 82, 82, 80, 81, 82, 81, 81, 79, 77, 84, 78, 80, 79, 78, 81, 79, 81, 81, 76, 78, 73, 76, 71, 72, 76, 75, 73, 77, 76, 75, 73, 72, 76, 73, 71, 70, 77, 70, 73, 73, 75, 78, 75, 78, 71, 73, 72, 72, 72, 69, 71, 69, 72, 69, 70, 70, 72, 68, 69, 69, 73, 69, 71, 67, 69, 68, 68, 67, 66, 69, 68, 68, 67, 69, 69, 67, 66, 68, 71, 66, 66, 66, 71, 68, 66, 66, 68, 68, 71, 65, 68, 67, 66, 67, 66, 67, 65, 62, 67, 70, 66, 61, 62, 61, 63, 60, 63, 63, 59, 57, 59, 59, 61, 61, 59, 59, 60, 60, 59, 58, 61, 58, 60, 59, 60, 59, 63, 58, 58, 58, 54, 53, 56, 50, 58, 53, 50, 53, 57, 56, 57, 53, 54, 53, 54, 54, 54, 53, 55, 51, 51, 51, 51, 53, 50, 49, 50, 53, 50, 47, 50, 43, 45, 49, 36, 40, 36, 45, 47, 39, 43, 40, 40, 43, 41, 41, 35, 36, 40, 40, 36, 38, 39, 36, 33, 42, 30, 35, 30, 29, 32, 31, 28, 33, 33, 29, 33, 39, 30, 32, 29, 33, 27, 28, 29, 28, 29, 31, 28, 32, 31, 28, 31, 26, 28, 29, 24, 26, 35, 29, 26, 29, 26, 27, 26, 29, 30, 24, 26, 29, 26, 29, 27, 27, 29, 26, 29, 30, 29, 26, 29, 26, 24, 29, 27, 30, 27, 24, 26, 29, 29, 27, 26, 24, 26, 29, 26, 29, 30, 29, 27, 26, 29, 26, 30, 29, 26, 29, 26, 24, 29, 26, 27, 27, 26, 29, 26, 24, 26, 29, 29, 25, 29, 26, 25, 26, 24, 29, 26, 29, 26, 27, 29, 26, 27, 26, 27, 28, 25, 28, 23, 25, 25, 22, 23, 22, 25, 22, 25, 22, 20, 22, 23, 25, 20, 25, 23, 25, 20, 25, 20, 22, 23, 20, 22, 25, 20, 20, 25, 23, 20, 22, 25, 22, 25, 20, 23, 24, 21, 19, 21, 19, 20, 25, 22, 19, 24, 21, 19, 22, 24, 21, 24, 22, 19, 24, 19, 21, 19, 24, 19, 24, 21, 19, 24, 19, 24, 25, 24, 21, 19, 21, 24, 21, 24, 22, 24, 21, 22, 24, 21, 24, 21, 24, 21, 21, 24, 19, 22, 21, 24, 19, 22, 24, 22, 21, 22, 24, 21, 22, 24, 21, 24, 22, 21, 24, 21, 24, 19, 22, 21, 24, 21, 22, 19, 24, 19, 22, 24, 22, 24, 19, 24, 22, 24, 19, 22, 24, 22, 21, 24, 21, 24, 21, 19, 21, 22, 21, 24, 24, 19, 24, 22, 24, 22, 19, 21, 24, 21, 24, 22, 21, 19, 24, 21, 24, 21, 24, 21, 22, 21, 21, 24, 21, 26, 27, 24, 19, 21, 30, 25, 24, 21, 24, 22, 21, 19, 21, 19, 17, 17, 17, 17, 19, 17, 17, 19, 17, 17, 17, 18, 17, 17, 18, 17, 18, 17, 17, 18, 17, 17, 17, 18, 17, 17, 17, 17, 17, 18, 17, 17, 17, 18, 17, 17, 18, 17, 17, 17, 17, 18, 17, 17, 17, 17, 18, 17, 17, 18, 17, 17, 17, 15, 15, 14, 14, 15, 14, 14, 15, 14, 14, 15, 14, 16, 14, 14, 14, 15, 14, 14, 15, 14, 14, 13, 13, 12, 12, 13, 12, 12, 13, 12, 7, 12, 7, 7, 6, 6, 7, 6, 6, 6, 7, 6, 6, 7, 7, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 7, 6, 6, 6, 4, 6, 4, 4, 4, 4, 4, 4, 4, 3, 4, 3, 3, 3, 5, 3, 3, 3, 3, 3, 3, 2, 3, 2, 2, 2, 4, 2, 2, 4, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0]
ransomware_percents = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 99.64, 99.64, 99.64, 99.29, 100.0, 100.0, 99.64, 99.29, 99.29, 97.14, 97.5, 97.5, 98.57, 98.57, 97.86, 96.79, 98.21, 97.86, 96.43, 98.21, 96.43, 96.43, 96.79, 95.0, 94.64, 96.79, 95.36, 94.64, 93.21, 95.0, 92.14, 93.93, 94.64, 91.07, 90.71, 91.79, 90.71, 92.86, 91.43, 86.43, 89.64, 89.64, 84.64, 85.36, 86.79, 85.71, 85.71, 86.43, 91.07, 85.71, 83.21, 81.79, 86.07, 83.93, 83.21, 83.93, 89.64, 82.14, 82.5, 82.14, 82.5, 82.5, 80.36, 80.71, 77.86, 77.86, 76.79, 77.5, 80.36, 77.14, 76.79, 76.43, 76.79, 77.86, 77.14, 75.71, 76.43, 77.5, 76.79, 75.0, 77.5, 75.36, 75.0, 78.21, 76.07, 73.93, 75.36, 72.14, 74.29, 75.0, 72.5, 71.07, 73.21, 73.93, 72.14, 71.43, 73.93, 71.43, 73.21, 72.14, 70.71, 67.86, 71.43, 66.79, 68.93, 68.21, 73.21, 70.71, 70.0, 68.57, 65.71, 68.21, 69.29, 68.21, 66.07, 66.07, 73.21, 65.36, 71.07, 68.57, 68.57, 67.86, 68.93, 63.93, 61.43, 67.14, 68.93, 62.14, 69.29, 62.86, 64.29, 65.71, 69.29, 66.79, 64.64, 66.79, 68.21, 65.0, 63.57, 66.07, 66.07, 62.86, 61.79, 63.57, 66.43, 65.36, 64.29, 63.57, 66.79, 63.57, 61.43, 58.93, 59.29, 61.79, 60.71, 56.07, 58.21, 61.43, 56.07, 57.86, 58.93, 58.21, 60.0, 56.79, 54.64, 55.71, 56.43, 63.93, 61.07, 54.29, 57.14, 58.57, 60.36, 62.86, 57.86, 53.57, 56.79, 58.21, 56.79, 53.93, 59.29, 56.43, 52.86, 55.0, 53.93, 54.64, 53.93, 56.43, 58.57, 57.14, 56.07, 57.86, 59.64, 54.64, 55.36, 54.29, 55.0, 56.07, 55.71, 52.14, 54.29, 52.14, 53.93, 52.14, 51.07, 50.0, 51.07, 52.5, 52.86, 52.14, 49.29, 48.93, 52.86, 48.93, 47.14, 52.86, 56.07, 51.43, 49.29, 50.0, 48.93, 49.29, 52.14, 48.21, 49.64, 45.0, 46.79, 45.71, 48.93, 45.36, 49.64, 49.64, 45.0, 44.64, 47.86, 46.43, 47.5, 51.79, 53.57, 50.36, 49.29, 44.64, 45.0, 50.0, 52.86, 46.43, 45.36, 36.07, 37.5, 33.57, 40.71, 36.07, 35.71, 36.43, 33.93, 33.57, 34.64, 35.36, 36.79, 35.0, 35.0, 32.86, 32.5, 34.29, 34.29, 33.21, 33.21, 36.07, 33.93, 34.64, 32.5, 34.29, 36.79, 38.21, 33.21, 35.0, 33.93, 34.64, 34.29, 36.79, 33.57, 32.5, 30.36, 31.43, 31.79, 34.64, 31.07, 32.5, 32.14, 31.79, 29.29, 33.21, 33.57, 30.71, 29.64, 30.71, 31.43, 29.64, 29.29, 29.29, 28.93, 29.29, 30.36, 30.0, 34.29, 28.57, 29.29, 29.29, 30.36, 30.36, 28.21, 30.36, 28.93, 28.21, 28.93, 30.36, 30.36, 30.0, 29.29, 28.21, 29.29, 29.29, 30.0, 28.93, 27.5, 29.29, 29.29, 28.57, 28.93, 29.29, 28.93, 28.93, 28.21, 27.5, 30.0, 27.86, 28.57, 28.21, 27.86, 28.93, 28.21, 28.93, 28.93, 27.14, 27.86, 26.07, 27.14, 25.36, 25.71, 27.14, 26.79, 26.07, 27.5, 27.14, 26.79, 26.07, 25.71, 27.14, 26.07, 25.36, 25.0, 27.5, 25.0, 26.07, 26.07, 26.79, 27.86, 26.79, 27.86, 25.36, 26.07, 25.71, 25.71, 25.71, 24.64, 25.36, 24.64, 25.71, 24.64, 25.0, 25.0, 25.71, 24.29, 24.64, 24.64, 26.07, 24.64, 25.36, 23.93, 24.64, 24.29, 24.29, 23.93, 23.57, 24.64, 24.29, 24.29, 23.93, 24.64, 24.64, 23.93, 23.57, 24.29, 25.36, 23.57, 23.57, 23.57, 25.36, 24.29, 23.57, 23.57, 24.29, 24.29, 25.36, 23.21, 24.29, 23.93, 23.57, 23.93, 23.57, 23.93, 23.21, 22.14, 23.93, 25.0, 23.57, 21.79, 22.14, 21.79, 22.5, 21.43, 22.5, 22.5, 21.07, 20.36, 21.07, 21.07, 21.79, 21.79, 21.07, 21.07, 21.43, 21.43, 21.07, 20.71, 21.79, 20.71, 21.43, 21.07, 21.43, 21.07, 22.5, 20.71, 20.71, 20.71, 19.29, 18.93, 20.0, 17.86, 20.71, 18.93, 17.86, 18.93, 20.36, 20.0, 20.36, 18.93, 19.29, 18.93, 19.29, 19.29, 19.29, 18.93, 19.64, 18.21, 18.21, 18.21, 18.21, 18.93, 17.86, 17.5, 17.86, 18.93, 17.86, 16.79, 17.86, 15.36, 16.07, 17.5, 12.86, 14.29, 12.86, 16.07, 16.79, 13.93, 15.36, 14.29, 14.29, 15.36, 14.64, 14.64, 12.5, 12.86, 14.29, 14.29, 12.86, 13.57, 13.93, 12.86, 11.79, 15.0, 10.71, 12.5, 10.71, 10.36, 11.43, 11.07, 10.0, 11.79, 11.79, 10.36, 11.79, 13.93, 10.71, 11.43, 10.36, 11.79, 9.64, 10.0, 10.36, 10.0, 10.36, 11.07, 10.0, 11.43, 11.07, 10.0, 11.07, 9.29, 10.0, 10.36, 8.57, 9.29, 12.5, 10.36, 9.29, 10.36, 9.29, 9.64, 9.29, 10.36, 10.71, 8.57, 9.29, 10.36, 9.29, 10.36, 9.64, 9.64, 10.36, 9.29, 10.36, 10.71, 10.36, 9.29, 10.36, 9.29, 8.57, 10.36, 9.64, 10.71, 9.64, 8.57, 9.29, 10.36, 10.36, 9.64, 9.29, 8.57, 9.29, 10.36, 9.29, 10.36, 10.71, 10.36, 9.64, 9.29, 10.36, 9.29, 10.71, 10.36, 9.29, 10.36, 9.29, 8.57, 10.36, 9.29, 9.64, 9.64, 9.29, 10.36, 9.29, 8.57, 9.29, 10.36, 10.36, 8.93, 10.36, 9.29, 8.93, 9.29, 8.57, 10.36, 9.29, 10.36, 9.29, 9.64, 10.36, 9.29, 9.64, 9.29, 9.64, 10.0, 8.93, 10.0, 8.21, 8.93, 8.93, 7.86, 8.21, 7.86, 8.93, 7.86, 8.93, 7.86, 7.14, 7.86, 8.21, 8.93, 7.14, 8.93, 8.21, 8.93, 7.14, 8.93, 7.14, 7.86, 8.21, 7.14, 7.86, 8.93, 7.14, 7.14, 8.93, 8.21, 7.14, 7.86, 8.93, 7.86, 8.93, 7.14, 8.21, 8.57, 7.5, 6.79, 7.5, 6.79, 7.14, 8.93, 7.86, 6.79, 8.57, 7.5, 6.79, 7.86, 8.57, 7.5, 8.57, 7.86, 6.79, 8.57, 6.79, 7.5, 6.79, 8.57, 6.79, 8.57, 7.5, 6.79, 8.57, 6.79, 8.57, 8.93, 8.57, 7.5, 6.79, 7.5, 8.57, 7.5, 8.57, 7.86, 8.57, 7.5, 7.86, 8.57, 7.5, 8.57, 7.5, 8.57, 7.5, 7.5, 8.57, 6.79, 7.86, 7.5, 8.57, 6.79, 7.86, 8.57, 7.86, 7.5, 7.86, 8.57, 7.5, 7.86, 8.57, 7.5, 8.57, 7.86, 7.5, 8.57, 7.5, 8.57, 6.79, 7.86, 7.5, 8.57, 7.5, 7.86, 6.79, 8.57, 6.79, 7.86, 8.57, 7.86, 8.57, 6.79, 8.57, 7.86, 8.57, 6.79, 7.86, 8.57, 7.86, 7.5, 8.57, 7.5, 8.57, 7.5, 6.79, 7.5, 7.86, 7.5, 8.57, 8.57, 6.79, 8.57, 7.86, 8.57, 7.86, 6.79, 7.5, 8.57, 7.5, 8.57, 7.86, 7.5, 6.79, 8.57, 7.5, 8.57, 7.5, 8.57, 7.5, 7.86, 7.5, 7.5, 8.57, 7.5, 9.29, 9.64, 8.57, 6.79, 7.5, 10.71, 8.93, 8.57, 7.5, 8.57, 7.86, 7.5, 6.79, 7.5, 6.79, 6.07, 6.07, 6.07, 6.07, 6.79, 6.07, 6.07, 6.79, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.43, 6.07, 6.43, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 6.07, 6.43, 6.07, 6.07, 6.43, 6.07, 6.07, 6.07, 5.36, 5.36, 5.0, 5.0, 5.36, 5.0, 5.0, 5.36, 5.0, 5.0, 5.36, 5.0, 5.71, 5.0, 5.0, 5.0, 5.36, 5.0, 5.0, 5.36, 5.0, 5.0, 4.64, 4.64, 4.29, 4.29, 4.64, 4.29, 4.29, 4.64, 4.29, 2.5, 4.29, 2.5, 2.5, 2.14, 2.14, 2.5, 2.14, 2.14, 2.14, 2.5, 2.14, 2.14, 2.5, 2.5, 2.14, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.14, 2.5, 2.14, 2.14, 2.14, 1.43, 2.14, 1.43, 1.43, 1.43, 1.43, 1.43, 1.43, 1.43, 1.07, 1.43, 1.07, 1.07, 1.07, 1.79, 1.07, 1.07, 1.07, 1.07, 1.07, 1.07, 0.71, 1.07, 0.71, 0.71, 0.71, 1.43, 0.71, 0.71, 1.43, 0.71, 0.71, 0.71, 0.71, 1.43, 0.71, 0.71, 0.71, 0.71, 0.71, 0.71, 0.71, 0.71, 0.71, 0.71, 0]
benign_files = [9818, 9902, 9854, 9840, 9785, 8391, 8908, 7565, 7501, 8497, 7982, 6465, 7855, 5511, 5565, 5024, 4102, 4418, 4276, 4329, 4333, 4095, 3243, 3268, 3457, 3297, 3335, 3383, 3312, 3732, 3272, 2852, 2875, 2916, 2966, 2571, 2577, 2630, 2627, 2699, 2568, 2422, 2554, 2427, 2316, 2527, 2345, 2266, 2276, 2303, 2273, 2416, 2325, 2325, 2363, 2380, 2242, 2041, 1972, 2134, 2393, 2165, 2073, 2149, 1956, 2075, 1880, 1805, 1761, 1845, 1998, 1768, 1974, 1929, 1713, 1882, 1855, 1736, 1676, 1833, 1963, 1863, 1855, 1645, 1698, 1778, 1684, 1569, 1773, 1524, 1508, 1801, 1661, 1448, 1490, 1486, 1625, 1430, 1669, 1388, 1487, 1672, 1355, 1462, 1478, 1439, 1529, 1377, 1391, 1395, 1362, 1321, 1345, 1280, 1550, 1596, 1251, 1301, 1297, 1282, 1316, 1393, 1319, 1237, 1676, 1211, 1504, 1367, 1285, 1239, 1290, 1152, 1151, 1333, 1457, 1207, 1262, 1136, 1227, 1259, 1258, 1196, 1185, 1202, 1220, 1176, 1138, 1156, 1178, 1157, 1167, 1137, 1181, 1164, 1150, 1144, 1185, 1201, 1163, 1086, 1083, 1121, 1088, 1050, 1060, 1094, 1044, 1058, 1061, 1061, 1085, 1033, 1040, 1044, 1037, 1113, 1133, 1009, 1063, 1041, 1043, 1146, 992, 1007, 980, 978, 1025, 970, 1038, 1031, 948, 963, 943, 951, 947, 974, 979, 967, 952, 974, 978, 938, 947, 916, 923, 944, 949, 909, 918, 912, 921, 918, 906, 892, 903, 894, 917, 899, 889, 887, 905, 872, 882, 895, 908, 883, 873, 862, 864, 861, 875, 853, 864, 842, 849, 837, 848, 826, 843, 844, 828, 820, 830, 819, 828, 839, 866, 830, 827, 815, 816, 850, 858, 818, 815, 798, 805, 791, 815, 796, 797, 800, 801, 781, 791, 789, 793, 798, 788, 780, 777, 786, 787, 775, 776, 785, 780, 777, 772, 764, 785, 781, 766, 780, 756, 761, 766, 777, 755, 750, 745, 740, 754, 747, 739, 736, 738, 721, 723, 732, 729, 714, 713, 716, 723, 707, 710, 717, 705, 700, 706, 697, 714, 697, 700, 691, 697, 689, 688, 685, 683, 673, 679, 673, 680, 665, 670, 650, 662, 633, 657, 611, 635, 604, 613, 603, 604, 598, 599, 591, 596, 585, 593, 581, 585, 580, 589, 575, 581, 577, 579, 571, 573, 561, 570, 556, 559, 553, 558, 547, 552, 547, 551, 544, 541, 541, 540, 535, 537, 533, 535, 529, 533, 539, 532, 538, 533, 527, 530, 522, 523, 527, 518, 515, 515, 513, 506, 508, 507, 508, 499, 502, 498, 505, 494, 500, 488, 492, 498, 487, 487, 486, 483, 486, 484, 484, 435, 469, 428, 468, 470, 431, 408, 458, 415, 411, 408, 398, 393, 395, 449, 411, 388, 391, 385, 395, 396, 393, 392, 383, 372, 381, 375, 379, 363, 365, 358, 367, 348, 353, 342, 330, 321, 340, 330, 320, 314, 330, 323, 307, 302, 305, 310, 319, 309, 299, 302, 295, 296, 295, 295, 286, 293, 277, 283, 280, 272, 276, 275, 268, 257, 267, 251, 258, 245, 253, 245, 251, 217, 239, 210, 218, 192, 205, 188, 193, 183, 184, 179, 189, 179, 182, 182, 178, 177, 179, 172, 171, 149, 168, 169, 169, 160, 147, 143, 148, 150, 155, 154, 150, 148, 145, 144, 144, 142, 142, 141, 140, 143, 138, 141, 138, 134, 135, 134, 133, 135, 136, 133, 133, 134, 132, 132, 131, 133, 130, 132, 131, 131, 142, 131, 130, 132, 131, 130, 131, 130, 142, 131, 129, 130, 132, 130, 129, 130, 129, 130, 129, 130, 131, 128, 129, 130, 128, 129, 129, 128, 129, 127, 128, 129, 128, 127, 128, 127, 126, 128, 128, 129, 128, 126, 127, 128, 129, 128, 128, 126, 127, 128, 127, 128, 129, 128, 127, 127, 128, 127, 129, 128, 127, 128, 127, 126, 128, 127, 127, 128, 127, 128, 127, 126, 127, 130, 128, 127, 128, 127, 127, 127, 126, 128, 127, 128, 127, 128, 128, 127, 127, 127, 127, 128, 127, 128, 126, 127, 128, 127, 127, 127, 128, 127, 128, 127, 126, 127, 127, 128, 126, 128, 127, 128, 126, 128, 126, 127, 127, 126, 127, 128, 126, 125, 127, 127, 125, 126, 127, 126, 127, 125, 125, 126, 125, 124, 125, 124, 125, 127, 125, 124, 126, 125, 124, 125, 126, 125, 126, 125, 124, 126, 124, 125, 124, 126, 124, 126, 125, 124, 126, 124, 126, 127, 126, 125, 124, 125, 126, 125, 126, 125, 126, 125, 125, 126, 125, 126, 125, 126, 124, 125, 125, 123, 124, 124, 125, 123, 124, 125, 124, 124, 124, 125, 124, 124, 125, 124, 125, 124, 124, 125, 124, 125, 123, 124, 124, 125, 124, 124, 123, 125, 123, 124, 125, 124, 125, 123, 125, 124, 125, 123, 124, 125, 124, 124, 125, 124, 125, 124, 123, 124, 124, 124, 125, 126, 123, 125, 124, 125, 124, 123, 123, 124, 123, 125, 123, 123, 122, 124, 123, 124, 123, 124, 123, 123, 124, 123, 124, 123, 124, 124, 124, 122, 123, 125, 124, 124, 123, 124, 123, 123, 122, 123, 122, 121, 122, 121, 120, 121, 120, 119, 120, 119, 120, 119, 119, 119, 118, 119, 117, 118, 117, 116, 117, 116, 117, 115, 117, 115, 117, 115, 114, 112, 113, 112, 111, 110, 111, 110, 109, 110, 109, 110, 109, 108, 109, 108, 107, 106, 105, 106, 105, 104, 105, 104, 105, 104, 103, 105, 103, 102, 103, 102, 101, 102, 101, 100, 101, 100, 101, 100, 99, 98, 99, 98, 97, 98, 97, 99, 97, 99, 97, 96, 97, 96, 98, 98, 97, 95, 96, 95, 97, 95, 94, 95, 94, 93, 92, 93, 92, 91, 92, 91, 90, 91, 90, 91, 90, 89, 90, 89, 91, 89, 89, 90, 89, 91, 89, 89, 90, 89, 88, 89, 88, 87, 88, 87, 86, 87, 86, 85, 84, 85, 84, 83, 82, 84, 83, 82, 81, 82, 81, 80, 79, 80, 79, 78, 79, 78, 77, 76, 75, 76, 75, 74, 73, 72, 71, 70, 69, 68, 67, 2, 0]
benign_percents = [98.18, 99.02, 98.54, 98.4, 97.85, 83.91, 89.08, 75.65, 75.01, 84.97, 79.82, 64.65, 78.55, 55.11, 55.65, 50.24, 41.02, 44.18, 42.76, 43.29, 43.33, 40.95, 32.43, 32.68, 34.57, 32.97, 33.35, 33.83, 33.12, 37.32, 32.72, 28.52, 28.75, 29.16, 29.66, 25.71, 25.77, 26.3, 26.27, 26.99, 25.68, 24.22, 25.54, 24.27, 23.16, 25.27, 23.45, 22.66, 22.76, 23.03, 22.73, 24.16, 23.25, 23.25, 23.63, 23.8, 22.42, 20.41, 19.72, 21.34, 23.93, 21.65, 20.73, 21.49, 19.56, 20.75, 18.8, 18.05, 17.61, 18.45, 19.98, 17.68, 19.74, 19.29, 17.13, 18.82, 18.55, 17.36, 16.76, 18.33, 19.63, 18.63, 18.55, 16.45, 16.98, 17.78, 16.84, 15.69, 17.73, 15.24, 15.08, 18.01, 16.61, 14.48, 14.9, 14.86, 16.25, 14.3, 16.69, 13.88, 14.87, 16.72, 13.55, 14.62, 14.78, 14.39, 15.29, 13.77, 13.91, 13.95, 13.62, 13.21, 13.45, 12.8, 15.5, 15.96, 12.51, 13.01, 12.97, 12.82, 13.16, 13.93, 13.19, 12.37, 16.76, 12.11, 15.04, 13.67, 12.85, 12.39, 12.9, 11.52, 11.51, 13.33, 14.57, 12.07, 12.62, 11.36, 12.27, 12.59, 12.58, 11.96, 11.85, 12.02, 12.2, 11.76, 11.38, 11.56, 11.78, 11.57, 11.67, 11.37, 11.81, 11.64, 11.5, 11.44, 11.85, 12.01, 11.63, 10.86, 10.83, 11.21, 10.88, 10.5, 10.6, 10.94, 10.44, 10.58, 10.61, 10.61, 10.85, 10.33, 10.4, 10.44, 10.37, 11.13, 11.33, 10.09, 10.63, 10.41, 10.43, 11.46, 9.92, 10.07, 9.8, 9.78, 10.25, 9.7, 10.38, 10.31, 9.48, 9.63, 9.43, 9.51, 9.47, 9.74, 9.79, 9.67, 9.52, 9.74, 9.78, 9.38, 9.47, 9.16, 9.23, 9.44, 9.49, 9.09, 9.18, 9.12, 9.21, 9.18, 9.06, 8.92, 9.03, 8.94, 9.17, 8.99, 8.89, 8.87, 9.05, 8.72, 8.82, 8.95, 9.08, 8.83, 8.73, 8.62, 8.64, 8.61, 8.75, 8.53, 8.64, 8.42, 8.49, 8.37, 8.48, 8.26, 8.43, 8.44, 8.28, 8.2, 8.3, 8.19, 8.28, 8.39, 8.66, 8.3, 8.27, 8.15, 8.16, 8.5, 8.58, 8.18, 8.15, 7.98, 8.05, 7.91, 8.15, 7.96, 7.97, 8.0, 8.01, 7.81, 7.91, 7.89, 7.93, 7.98, 7.88, 7.8, 7.77, 7.86, 7.87, 7.75, 7.76, 7.85, 7.8, 7.77, 7.72, 7.64, 7.85, 7.81, 7.66, 7.8, 7.56, 7.61, 7.66, 7.77, 7.55, 7.5, 7.45, 7.4, 7.54, 7.47, 7.39, 7.36, 7.38, 7.21, 7.23, 7.32, 7.29, 7.14, 7.13, 7.16, 7.23, 7.07, 7.1, 7.17, 7.05, 7.0, 7.06, 6.97, 7.14, 6.97, 7.0, 6.91, 6.97, 6.89, 6.88, 6.85, 6.83, 6.73, 6.79, 6.73, 6.8, 6.65, 6.7, 6.5, 6.62, 6.33, 6.57, 6.11, 6.35, 6.04, 6.13, 6.03, 6.04, 5.98, 5.99, 5.91, 5.96, 5.85, 5.93, 5.81, 5.85, 5.8, 5.89, 5.75, 5.81, 5.77, 5.79, 5.71, 5.73, 5.61, 5.7, 5.56, 5.59, 5.53, 5.58, 5.47, 5.52, 5.47, 5.51, 5.44, 5.41, 5.41, 5.4, 5.35, 5.37, 5.33, 5.35, 5.29, 5.33, 5.39, 5.32, 5.38, 5.33, 5.27, 5.3, 5.22, 5.23, 5.27, 5.18, 5.15, 5.15, 5.13, 5.06, 5.08, 5.07, 5.08, 4.99, 5.02, 4.98, 5.05, 4.94, 5.0, 4.88, 4.92, 4.98, 4.87, 4.87, 4.86, 4.83, 4.86, 4.84, 4.84, 4.35, 4.69, 4.28, 4.68, 4.7, 4.31, 4.08, 4.58, 4.15, 4.11, 4.08, 3.98, 3.93, 3.95, 4.49, 4.11, 3.88, 3.91, 3.85, 3.95, 3.96, 3.93, 3.92, 3.83, 3.72, 3.81, 3.75, 3.79, 3.63, 3.65, 3.58, 3.67, 3.48, 3.53, 3.42, 3.3, 3.21, 3.4, 3.3, 3.2, 3.14, 3.3, 3.23, 3.07, 3.02, 3.05, 3.1, 3.19, 3.09, 2.99, 3.02, 2.95, 2.96, 2.95, 2.95, 2.86, 2.93, 2.77, 2.83, 2.8, 2.72, 2.76, 2.75, 2.68, 2.57, 2.67, 2.51, 2.58, 2.45, 2.53, 2.45, 2.51, 2.17, 2.39, 2.1, 2.18, 1.92, 2.05, 1.88, 1.93, 1.83, 1.84, 1.79, 1.89, 1.79, 1.82, 1.82, 1.78, 1.77, 1.79, 1.72, 1.71, 1.49, 1.68, 1.69, 1.69, 1.6, 1.47, 1.43, 1.48, 1.5, 1.55, 1.54, 1.5, 1.48, 1.45, 1.44, 1.44, 1.42, 1.42, 1.41, 1.4, 1.43, 1.38, 1.41, 1.38, 1.34, 1.35, 1.34, 1.33, 1.35, 1.36, 1.33, 1.33, 1.34, 1.32, 1.32, 1.31, 1.33, 1.3, 1.32, 1.31, 1.31, 1.42, 1.31, 1.3, 1.32, 1.31, 1.3, 1.31, 1.3, 1.42, 1.31, 1.29, 1.3, 1.32, 1.3, 1.29, 1.3, 1.29, 1.3, 1.29, 1.3, 1.31, 1.28, 1.29, 1.3, 1.28, 1.29, 1.29, 1.28, 1.29, 1.27, 1.28, 1.29, 1.28, 1.27, 1.28, 1.27, 1.26, 1.28, 1.28, 1.29, 1.28, 1.26, 1.27, 1.28, 1.29, 1.28, 1.28, 1.26, 1.27, 1.28, 1.27, 1.28, 1.29, 1.28, 1.27, 1.27, 1.28, 1.27, 1.29, 1.28, 1.27, 1.28, 1.27, 1.26, 1.28, 1.27, 1.27, 1.28, 1.27, 1.28, 1.27, 1.26, 1.27, 1.3, 1.28, 1.27, 1.28, 1.27, 1.27, 1.27, 1.26, 1.28, 1.27, 1.28, 1.27, 1.28, 1.28, 1.27, 1.27, 1.27, 1.27, 1.28, 1.27, 1.28, 1.26, 1.27, 1.28, 1.27, 1.27, 1.27, 1.28, 1.27, 1.28, 1.27, 1.26, 1.27, 1.27, 1.28, 1.26, 1.28, 1.27, 1.28, 1.26, 1.28, 1.26, 1.27, 1.27, 1.26, 1.27, 1.28, 1.26, 1.25, 1.27, 1.27, 1.25, 1.26, 1.27, 1.26, 1.27, 1.25, 1.25, 1.26, 1.25, 1.24, 1.25, 1.24, 1.25, 1.27, 1.25, 1.24, 1.26, 1.25, 1.24, 1.25, 1.26, 1.25, 1.26, 1.25, 1.24, 1.26, 1.24, 1.25, 1.24, 1.26, 1.24, 1.26, 1.25, 1.24, 1.26, 1.24, 1.26, 1.27, 1.26, 1.25, 1.24, 1.25, 1.26, 1.25, 1.26, 1.25, 1.26, 1.25, 1.25, 1.26, 1.25, 1.26, 1.25, 1.26, 1.24, 1.25, 1.25, 1.23, 1.24, 1.24, 1.25, 1.23, 1.24, 1.25, 1.24, 1.24, 1.24, 1.25, 1.24, 1.24, 1.25, 1.24, 1.25, 1.24, 1.24, 1.25, 1.24, 1.25, 1.23, 1.24, 1.24, 1.25, 1.24, 1.24, 1.23, 1.25, 1.23, 1.24, 1.25, 1.24, 1.25, 1.23, 1.25, 1.24, 1.25, 1.23, 1.24, 1.25, 1.24, 1.24, 1.25, 1.24, 1.25, 1.24, 1.23, 1.24, 1.24, 1.24, 1.25, 1.26, 1.23, 1.25, 1.24, 1.25, 1.24, 1.23, 1.23, 1.24, 1.23, 1.25, 1.23, 1.23, 1.22, 1.24, 1.23, 1.24, 1.23, 1.24, 1.23, 1.23, 1.24, 1.23, 1.24, 1.23, 1.24, 1.24, 1.24, 1.22, 1.23, 1.25, 1.24, 1.24, 1.23, 1.24, 1.23, 1.23, 1.22, 1.23, 1.22, 1.21, 1.22, 1.21, 1.2, 1.21, 1.2, 1.19, 1.2, 1.19, 1.2, 1.19, 1.19, 1.19, 1.18, 1.19, 1.17, 1.18, 1.17, 1.16, 1.17, 1.16, 1.17, 1.15, 1.17, 1.15, 1.17, 1.15, 1.14, 1.12, 1.13, 1.12, 1.11, 1.1, 1.11, 1.1, 1.09, 1.1, 1.09, 1.1, 1.09, 1.08, 1.09, 1.08, 1.07, 1.06, 1.05, 1.06, 1.05, 1.04, 1.05, 1.04, 1.05, 1.04, 1.03, 1.05, 1.03, 1.02, 1.03, 1.02, 1.01, 1.02, 1.01, 1.0, 1.01, 1.0, 1.01, 1.0, 0.99, 0.98, 0.99, 0.98, 0.97, 0.98, 0.97, 0.99, 0.97, 0.99, 0.97, 0.96, 0.97, 0.96, 0.98, 0.98, 0.97, 0.95, 0.96, 0.95, 0.97, 0.95, 0.94, 0.95, 0.94, 0.93, 0.92, 0.93, 0.92, 0.91, 0.92, 0.91, 0.9, 0.91, 0.9, 0.91, 0.9, 0.89, 0.9, 0.89, 0.91, 0.89, 0.89, 0.9, 0.89, 0.91, 0.89, 0.89, 0.9, 0.89, 0.88, 0.89, 0.88, 0.87, 0.88, 0.87, 0.86, 0.87, 0.86, 0.85, 0.84, 0.85, 0.84, 0.83, 0.82, 0.84, 0.83, 0.82, 0.81, 0.82, 0.81, 0.8, 0.79, 0.8, 0.79, 0.78, 0.79, 0.78, 0.77, 0.76, 0.75, 0.76, 0.75, 0.74, 0.73, 0.72, 0.71, 0.7, 0.69, 0.68, 0.67, 0.02, 0]
"""


# Transforming data to LaTeX rows
latex_rows = transform_data_to_latex_rows(pattern_lengths, ransomware_files, ransomware_percents, benign_files, benign_percents)
print(latex_rows)
