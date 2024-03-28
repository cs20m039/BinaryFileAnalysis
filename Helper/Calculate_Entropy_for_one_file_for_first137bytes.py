import math


def calculate_entropy(data):
    # Count the frequency of each byte value
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1

    # Calculate probability of each byte value
    total_bytes = len(data)
    probabilities = [freq / total_bytes for freq in frequency if freq > 0]

    # Calculate entropy
    entropy = -sum(prob * math.log2(prob) for prob in probabilities)

    return entropy


# Read the first 137 bytes of the file
file_path = "/home/cs20m039/thesis/dataset/malicious/Evilquest/macOS/d43291684d6412f537d7f2001c21ad58313643a3556b730c287aed2015624a31.macho"
with open(file_path, "rb") as file:
    data = file.read(137)

# Calculate entropy
entropy = calculate_entropy(data)
print("Entropy:", entropy)
