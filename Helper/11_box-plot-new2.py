import matplotlib.pyplot as plt

# Summary statistics for each operating system
data = {
    'General': {'min': 24, 'q1': 50048, 'median': 434129, 'q3': 1641552, 'max': 160489900},
    'Linux': {'min': 1, 'q1': 895.75, 'median': 2893, 'q3': 13638.5, 'max': 3940022},
    'Windows': {'min': 21, 'q1': 6656, 'median': 18890, 'q3': 124763, 'max': 23448580},
    'macOS': {'min': 1025, 'q1': 2894.75, 'median': 6302.5, 'q3': 16755.5, 'max': 11380800}
}

fig, ax = plt.subplots()
positions = range(len(data), 0, -1)  # Reverse position for vertical orientation

for pos, (label, stats) in zip(positions, data.items()):
    # Draw the box
    ax.add_patch(plt.Rectangle((stats['q1'], pos - 0.4), stats['q3'] - stats['q1'], 0.8, color='skyblue'))
    # Draw the median line
    ax.plot([stats['median'], stats['median']], [pos - 0.4, pos + 0.4], color='red')
    # Draw whiskers
    ax.plot([stats['min'], stats['q1']], [pos, pos], color='black')
    ax.plot([stats['q3'], stats['max']], [pos, pos], color='black')
    # Draw caps
    ax.plot([stats['min'], stats['min']], [pos - 0.2, pos + 0.2], color='black')
    ax.plot([stats['max'], stats['max']], [pos - 0.2, pos + 0.2], color='black')

ax.set_yticks(range(1, len(data) + 1))
ax.set_yticklabels(data.keys())
ax.set_xscale('log')
ax.set_xlabel('File Size (bytes)')
ax.set_ylabel('Operating System')
ax.set_title('File Size Distribution Across Operating Systems')

plt.show()
