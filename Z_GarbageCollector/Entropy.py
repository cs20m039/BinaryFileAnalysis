import os
import math

class EntropyAnalysis:

    def check_entropy_values(self, directory):
        print("----------\n\033[1mOutput of Entropy-Analysis:\033[0m")

        # Uniform distribution as reference for Cross-Entropy
        reference_distribution = [1/256] * 256

        total_shannon_entropy = 0
        total_conditional_entropy = 0
        total_cross_entropy = 0
        total_renyi_entropy = 0
        total_tsallis_entropy = 0
        total_files = 0

        # Traverse directory and subdirectories
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'rb') as file:
                    buffer = file.read(1024)
                    total_bits = 0
                    freq = [0] * 256

                    while buffer:
                        for byte in buffer:
                            freq[byte] += 1
                            total_bits += 8
                        buffer = file.read(1024)

                    # Calculate Shannon Entropy
                    shannon_entropy = self.calculate_shannon_entropy(freq, total_bits)

                    # Calculate Conditional Entropy (here, identical to Shannon for demonstration)
                    conditional_entropy = shannon_entropy

                    # Calculate Cross-Entropy
                    cross_entropy = self.calculate_cross_entropy(freq, total_bits, reference_distribution)

                    # Calculate Renyi Entropy
                    renyi_entropy = self.calculate_renyi_entropy(freq, alpha=2)

                    # Calculate Tsallis Entropy
                    tsallis_entropy = self.calculate_tsallis_entropy(freq, q=2)

                    print(f"File: {file_name}, Shannon Entropy: {shannon_entropy}, Conditional Entropy: {conditional_entropy}, Cross-Entropy: {cross_entropy}, Renyi Entropy: {renyi_entropy}, Tsallis Entropy: {tsallis_entropy}")

                    total_shannon_entropy += shannon_entropy
                    total_conditional_entropy += conditional_entropy
                    total_cross_entropy += cross_entropy
                    total_renyi_entropy += renyi_entropy
                    total_tsallis_entropy += tsallis_entropy
                    total_files += 1

        self.print_average_entropies(total_shannon_entropy, total_conditional_entropy, total_cross_entropy, total_renyi_entropy, total_tsallis_entropy, total_files)

    def calculate_shannon_entropy(self, freq, total_bits):
        shannon_entropy = 0
        for i in freq:
            if i > 0:
                p = i / total_bits
                shannon_entropy -= p * math.log(p, 2)
        return shannon_entropy

    def calculate_cross_entropy(self, freq, total_bits, reference_distribution):
        cross_entropy = 0
        for i in range(len(freq)):
            if freq[i] > 0:
                p = freq[i] / total_bits
                cross_entropy -= p * math.log(reference_distribution[i], 2)
        return cross_entropy

    def calculate_renyi_entropy(self, freq, alpha):
        if alpha == 1:  # Reduce to Shannon Entropy
            return self.calculate_shannon_entropy(freq, sum(freq))
        else:
            return 1 / (1 - alpha) * math.log(sum([p ** alpha for p in freq if p > 0]), 2)

    def calculate_tsallis_entropy(self, freq, q):
        return 1 / (q - 1) * (1 - sum([p ** q for p in freq if p > 0]))

    def print_average_entropies(self, total_shannon_entropy, total_conditional_entropy, total_cross_entropy, total_renyi_entropy, total_tsallis_entropy, total_files):
        avg_shannon_entropy = total_shannon_entropy / total_files
        avg_conditional_entropy = total_conditional_entropy / total_files
        avg_cross_entropy = total_cross_entropy / total_files
        avg_renyi_entropy = total_renyi_entropy / total_files
        avg_tsallis_entropy = total_tsallis_entropy / total_files

        print(f"Average Shannon Entropy: {avg_shannon_entropy}")
        print(f"Average Conditional Entropy: {avg_conditional_entropy}")
        print(f"Average Cross-Entropy: {avg_cross_entropy}")
        print(f"Average Renyi Entropy: {avg_renyi_entropy}")
        print(f"Average Tsallis Entropy: {avg_tsallis_entropy}")

# Example usage:
if __name__ == "__main__":
    analyzer = EntropyAnalysis()
    analyzer.check_entropy_values("/home/cs20m039/samples/benign")
