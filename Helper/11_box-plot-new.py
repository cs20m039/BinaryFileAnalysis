import matplotlib.pyplot as plt
import numpy as np

# Updating the data with the new dataset statistics
data = [
    {
        "label": "Data",
        "whislo": 24,  # Bottom whisker position
        "q1": 50048,   # First quartile (25th percentile)
        "med": 434129,  # Median         (50th percentile)
        "q3": 1641552,   # Third quartile (75th percentile)
        "whishi": 160489900,  # Top whisker position
        "fliers": []        # Outliers
    },
    {
        "label": "macOS",
        "whislo": 1025,
        "q1": 2872,
        "med": 6266,
        "q3": 16685,
        "whishi": 11380800,
        "fliers": []
    },
    {
        "label": "Linux",
        "whislo": 1,
        "q1": 895.75,
        "med": 2893,
        "q3": 13638.5,
        "whishi": 3940022,
        "fliers": []
    },
    {
        "label": "Windows",
        "whislo": 12,
        "q1": 7168,
        "med": 20474,
        "q3": 130816,
        "whishi": 190470100,
        "fliers": []
    }
]

fig, ax = plt.subplots(figsize=(10, 6))
ax.bxp(data, vert=False, showfliers=False)
ax.set_xscale('log')
ax.set_title('Distribution of file sizes for all individual subsets of benign files')
ax.set_xlabel('File size (bytes)')
ax.set_ylabel('')

plt.show()
