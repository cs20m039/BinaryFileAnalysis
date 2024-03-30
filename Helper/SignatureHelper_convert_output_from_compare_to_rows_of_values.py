data = """
2024-03-29 23:03:01,424 - INFO - Length 400 bytes: 0 files found with a pattern at the beginning.
2024-03-29 23:15:03,852 - INFO - Length 136 bytes: 81 files found with a pattern at the beginning.
2024-03-29 23:15:06,418 - INFO - Length 134 bytes: 82 files found with a pattern at the beginning.
2024-03-29 23:15:12,391 - INFO - Length 129 bytes: 127 files found with a pattern at the beginning.
2024-03-29 23:15:13,381 - INFO - Length 128 bytes: 209 files found with a pattern at the beginning.
2024-03-29 23:15:57,492 - INFO - Length 60 bytes: 211 files found with a pattern at the beginning.
2024-03-29 23:16:10,875 - INFO - Length 25 bytes: 216 files found with a pattern at the beginning.
2024-03-29 23:16:11,587 - INFO - Length 24 bytes: 227 files found with a pattern at the beginning.
2024-03-29 23:16:12,622 - INFO - Length 18 bytes: 230 files found with a pattern at the beginning.
2024-03-29 23:16:12,854 - INFO - Length 16 bytes: 236 files found with a pattern at the beginning.
2024-03-29 23:16:13,539 - INFO - Length 11 bytes: 244 files found with a pattern at the beginning.
2024-03-29 23:16:13,633 - INFO - Length 10 bytes: 247 files found with a pattern at the beginning.
2024-03-29 23:16:13,926 - INFO - Length 8 bytes: 248 files found with a pattern at the beginning.
2024-03-29 23:16:14,271 - INFO - Length 6 bytes: 261 files found with a pattern at the beginning.
2024-03-29 23:16:14,291 - INFO - Length 5 bytes: 271 files found with a pattern at the beginning.
2024-03-29 23:16:14,383 - INFO - Length 4 bytes: 272 files found with a pattern at the beginning.

"""

length_list = []
files_list = []

lines = data.strip().split("\n")
for line in lines:
    parts = line.split()
    length_index = parts.index("Length")
    bytes_index = parts.index("bytes:")
    length_list.append(int(parts[length_index + 1]))
    files_list.append(int(parts[bytes_index + 1]))

# Reverse the lists
length_list = length_list[::-1]
files_list = files_list[::-1]

print("Length:", length_list)
print("Files:", files_list)