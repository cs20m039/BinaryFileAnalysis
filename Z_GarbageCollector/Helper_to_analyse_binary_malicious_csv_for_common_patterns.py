import csv


def read_csv(filename):
    malware_patterns = []
    benign_patterns = []

    with open(filename, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            hash_value, label, pattern = row
            pattern_bytes = bytes.fromhex(pattern)
            if int(label) == 1:
                malware_patterns.append(pattern_bytes)
            else:
                benign_patterns.append(pattern_bytes)

    return malware_patterns, benign_patterns


def find_common_patterns(patterns, max_length):
    common_patterns = {}
    for pattern in patterns:
        for i in range(len(pattern)):
            for length in range(1, min(max_length, len(pattern) - i) + 1):
                current_pattern = pattern[i:i + length]
                current_pattern_hex = current_pattern.hex()
                if current_pattern_hex not in common_patterns:
                    common_patterns[current_pattern_hex] = 0
                common_patterns[current_pattern_hex] += 1

    return common_patterns


def write_common_patterns_to_csv(common_patterns, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Pattern', 'Count'])
        for pattern, count in sorted(common_patterns.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([pattern, count])


def main():
    filename = 'datafile_malicious_and_benign'
    max_pattern_length = 137
    malware_patterns, benign_patterns = read_csv(filename)

    malware_common = find_common_patterns(malware_patterns, max_pattern_length)
    benign_common = find_common_patterns(benign_patterns, max_pattern_length)

    write_common_patterns_to_csv(malware_common, 'malware_common_patterns.csv')
    write_common_patterns_to_csv(benign_common, 'benign_common_patterns.csv')


if __name__ == "__main__":
    main()
