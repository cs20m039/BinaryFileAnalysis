import os
from collections import Counter

def find_most_common_strings(output_directory):
    strings_counter = Counter()  # Counter object to store and count strings

    # Iterate over each file in the output directory
    for filename in os.listdir(output_directory):
        file_path = os.path.join(output_directory, filename)
        with open(file_path, 'r') as file:
            # Update the counter with strings from this file
            file_strings = [line.strip() for line in file if line.strip()]
            strings_counter.update(file_strings)

    # Get the most common strings; adjust the number as needed
    most_common_strings = strings_counter.most_common(10)  # Adjust the number for desired count

    return most_common_strings

# Example usage
if __name__ == "__main__":
    output_directory = '/home/cs20m039/PycharmProjects/pythonProject/output_files/' # Directory containing the output files
    most_common_strings = find_most_common_strings(output_directory)

    # Print or save the most common strings
    print("Most common strings across all files:")
    for string, count in most_common_strings:
        print(f"{string}: {count} times")

    # Optionally, save the most common strings to a file
    with open('most_common_strings.txt', 'w') as output_file:
        for string, count in most_common_strings:
            output_file.write(f"{string}: {count} times\n")
