import csv


def read_csv(filename):
    malware_patterns = []

    with open(filename, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            hash_value, label, pattern = row
            if int(label) == 0:
                pattern_bytes = bytes.fromhex(
                    pattern[:274])  # Considering only the first 137 bytes (274 characters in hex)
                pattern_length = min(len(pattern_bytes), 137)  # Ensure pattern length doesn't exceed 137 bytes
                malware_patterns.append(pattern_bytes[:pattern_length])

    return malware_patterns


def find_common_patterns(patterns):
    common_patterns = {}

    for pattern in patterns:
        for i in range(len(pattern)):
            for length in range(len(pattern) - i, 0, -1):  # Iterate from longest to shortest patterns
                current_pattern = pattern[i:i + length]
                current_pattern_hex = current_pattern.hex()
                if all(current_pattern in p for p in patterns):  # Check if the pattern appears in all files
                    common_patterns[current_pattern_hex] = len(current_pattern)
                    break  # Move to the next pattern once the maximum length for this position is found

    return common_patterns


def main():
    filename = 'datafile_malicious_and_benign'
    malware_patterns = read_csv(filename)

    common_patterns = find_common_patterns(malware_patterns)

    if common_patterns:  # Check if there are common patterns
        max_length = max(common_patterns.values())
        common_max_length_patterns = {pattern: length for pattern, length in common_patterns.items() if
                                      length == max_length}

        print("Common Patterns Appearing in All 280 Malware Files:")
        for pattern, length in common_max_length_patterns.items():
            print(f"Pattern: {pattern}, Length: {length}")
    else:
        print("No common patterns found among malware samples.")


if __name__ == "__main__":
    main()
