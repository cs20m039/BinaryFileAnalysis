import os

def generate_hex_substrings(hex_data, pattern_length):
    substrings = set()
    for i in range(len(hex_data) - pattern_length + 1):
        substring = hex_data[i:i+pattern_length]
        substrings.add(substring)
    return substrings

def find_common_matching_pattern(directory):
    file_patterns = {}
    max_common_pattern = ""
    max_common_pattern_count = 0

    # Traverse the directory and its subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                hex_data = f.read().hex()
                max_pattern_length = len(hex_data)
                for pattern_length in range(2, max_pattern_length + 1):
                    patterns = generate_hex_substrings(hex_data, pattern_length)
                    for pattern in patterns:
                        if pattern not in file_patterns:
                            file_patterns[pattern] = 1
                        else:
                            file_patterns[pattern] += 1

    for pattern, count in file_patterns.items():
        if count > max_common_pattern_count:
            max_common_pattern = pattern
            max_common_pattern_count = count

    return max_common_pattern, max_common_pattern_count

# Specify the directory containing your files
directory_path = "/home/cs20m039/samples/malicious/LockBitRansomware/Windows/"

max_common_pattern, max_common_pattern_count = find_common_matching_pattern(directory_path)

if max_common_pattern_count > 1:
    print(f"The most common matching pattern across files is: {max_common_pattern}")
    print(f"Number of files with this pattern: {max_common_pattern_count}")
else:
    print("No common matching pattern found across files.")




# import os
#
# def generate_hex_substrings(hex_data, pattern_length):
#     substrings = set()
#     for i in range(len(hex_data) - pattern_length + 1):
#         substring = hex_data[i:i+pattern_length]
#         substrings.add(substring)
#     return substrings
#
# def find_similar_hex_patterns(directory):
#     file_patterns = {}
#
#     # Traverse the directory and its subdirectories
#     for root, _, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             with open(file_path, 'rb') as f:
#                 hex_data = f.read().hex()
#                 patterns = generate_hex_substrings(hex_data, pattern_length)
#                 for pattern in patterns:
#                     if pattern not in file_patterns:
#                         file_patterns[pattern] = [file_path]
#                     else:
#                         file_patterns[pattern].append(file_path)
#
#     if not file_patterns:
#         print("No hex patterns found in the specified directory.")
#         return
#
#     common_hex_patterns = {pattern: files for pattern, files in file_patterns.items() if len(files) > 1}
#
#     if not common_hex_patterns:
#         print("No common hex patterns found in the specified directory.")
#         return
#
#     print(f"Common Hex Patterns:")
#     for pattern, files in common_hex_patterns.items():
#         print(f"Pattern: {pattern}")
#         print("Matching files:")
#         for file in files:
#             print(f"- {file}")
#         print()
#
# # Specify the directory containing your files
# directory_path = "/home/cs20m039/sample-files"
#
# # Specify the desired hex pattern length
# pattern_length = 2
#
# find_similar_hex_patterns(directory_path)





# import os
#
#
# def extract_hex_patterns(file_path, pattern_length):
#     with open(file_path, 'rb') as file:
#         hex_data = file.read().hex()
#     # Extract hex patterns of the specified length
#     return [hex_data[i:i + pattern_length] for i in range(0, len(hex_data), pattern_length)]
#
#
# def find_common_hex_patterns(directory):
#     common_hex_patterns = set()
#
#     # Start with pattern length of 2
#     pattern_length = 2
#     while True:
#         # Flag to check if any common patterns are found
#         found_common = False
#         # Dictionary to store hex patterns and their counts
#         hex_patterns_count = {}
#
#         # Traverse the directory and its subdirectories
#         for root, _, files in os.walk(directory):
#             for file in files:
#                 file_path = os.path.join(root, file)
#                 # Extract hex patterns of the current length from each file
#                 hex_patterns = extract_hex_patterns(file_path, pattern_length)
#                 for pattern in hex_patterns:
#                     if pattern not in hex_patterns_count:
#                         hex_patterns_count[pattern] = 1
#                     else:
#                         hex_patterns_count[pattern] += 1
#
#         # Filter out patterns that occur in all files
#         common_patterns = {pattern for pattern, count in hex_patterns_count.items() if count == len(files)}
#         if common_patterns:
#             found_common = True
#             print(f"Common Hex Patterns of Length {pattern_length}:")
#             print(common_patterns)
#             # Update the set of common hex patterns
#             common_hex_patterns.update(common_patterns)
#
#         # If no common patterns are found, break the loop
#         if not found_common:
#             break
#
#         # Increase pattern length for the next iteration
#         pattern_length += 1
#
#     if not common_hex_patterns:
#         print("No common hex patterns found in the specified directory.")
#
#
# # Specify the directory containing your files
# directory_path = "/home/cs20m039/sample-files"
#
# find_common_hex_patterns(directory_path)

# import os
#
# def extract_hex_patterns(file_path, pattern_length):
#     with open(file_path, 'rb') as file:
#         hex_data = file.read().hex()
#     # Extract hex patterns of the specified length
#     return [hex_data[i:i+pattern_length] for i in range(0, len(hex_data), pattern_length)]
#
# def find_common_hex_patterns(directory, pattern_length):
#     common_hex_patterns = set()
#
#     # Traverse the directory and its subdirectories
#     for root, _, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             # Extract hex patterns of the specified length from each file
#             hex_patterns = set(extract_hex_patterns(file_path, pattern_length))
#             if not common_hex_patterns:
#                 common_hex_patterns = hex_patterns
#             else:
#                 # Update common hex patterns with the intersection of current file's hex patterns
#                 common_hex_patterns = common_hex_patterns.intersection(hex_patterns)
#
#     if not common_hex_patterns:
#         print("No common hex patterns found in the specified directory.")
#         return
#
#     print(f"Common Hex Patterns of Length {pattern_length}:")
#     print(common_hex_patterns)
#
# # Specify the directory containing your files
# directory_path = "/home/cs20m039/sample-files"
# # Specify the desired hex pattern length
# desired_pattern_length = 5
#
# find_common_hex_patterns(directory_path, desired_pattern_length)
