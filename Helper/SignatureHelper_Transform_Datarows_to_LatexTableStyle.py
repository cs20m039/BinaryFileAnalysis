def transform_data_to_latex_rows(pattern_lengths, benign_patterns, ransomware_files, ransomware_percents, ransomware_patterns, benign_files, benign_percents):
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
    for pl, bpc, rf, rp, rpc, bf, bp in zip(pattern_lengths, benign_patterns, ransomware_files, ransomware_percents, ransomware_patterns, benign_files,
                                  benign_percents):
        row = f"{pl} & {bpc} & {rf} & {rp} {rpc}& {bf} & {bp} \\\\"
        latex_rows.append(row)
    return "\n".join(latex_rows)

pattern_lengths = [4, 5, 6, 7, 8, 10, 11, 12, 16, 18, 24, 25, 60, 64, 128, 129, 134, 136, 137]
benign_patterns = [7, 9, 7, 8, 8, 7, 5, 5, 5, 4, 4, 3, 1, 13, 13, 25, 2, 3, 0]
ransomware_files = [272, 271, 261, 248, 248, 247, 244, 236, 236, 230, 227, 216, 211, 209, 209, 127, 82, 81, 0]
ransomware_percents = [97.14, 96.79, 93.21, 88.57, 88.57, 88.21, 87.14, 84.29, 84.29, 82.14, 81.07, 77.14, 75.36, 74.64, 74.64, 45.36, 29.29, 28.93, 0.00]
ransomware_patterns = [7, 9, 7, 7, 8, 7, 5, 5, 5, 4, 4, 3, 1, 13, 13, 25, 2, 3, 0]
benign_files = [2628, 2627, 2620, 2501, 2472, 2456, 2266, 2266, 2232, 1806, 1806, 1738, 1664, 1598, 1567, 98, 30, 3, 0]
benign_percents = [26.28, 26.27, 26.20, 25.01, 24.72, 24.56, 22.66, 22.66, 22.32, 18.06, 18.06, 17.38, 16.64, 15.98, 15.67, 0.98, 0.30, 0.03, 0.00]




# Transforming data to LaTeX rows
latex_rows = transform_data_to_latex_rows(pattern_lengths, benign_patterns, ransomware_files, ransomware_percents, ransomware_patterns, benign_files,
                                          benign_percents)
print(latex_rows)
