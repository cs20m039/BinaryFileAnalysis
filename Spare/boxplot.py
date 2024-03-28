# Define a function to group pattern lengths into intervals and calculate summary statistics
def group_and_summarize(pattern_lengths, file_counts):
    # Determine interval ranges (for simplicity, we use fixed intervals based on the data range)
    intervals = [(0, 25), (26, 128), (129, 290)]
    interval_labels = ['1-25', '26-128', '129-290']
    summaries = []

    for start, end in intervals:
        interval_counts = [file_counts[i] for i, pl in enumerate(pattern_lengths) if start <= pl <= end]
        if interval_counts:  # Ensure there are counts in this interval
            median = np.median(interval_counts)
            min_val = np.min(interval_counts)
            max_val = np.max(interval_counts)
            summaries.append((median, min_val, max_val))
        else:
            summaries.append((0, 0, 0))  # Placeholder if no data in interval

    return interval_labels, summaries


# Apply the function to both data sets
labels, summary_1 = group_and_summarize(pattern_lengths_1, file_counts_1)
_, summary_2 = group_and_summarize(pattern_lengths_2, file_counts_2)

labels, summary_1, summary_2
