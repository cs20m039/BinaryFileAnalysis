import matplotlib.pyplot as plt
import numpy as np

# Preparing the data for a more direct approach
data = [
    {
        "label": "Windows",
        "whislo": 33,  # Bottom whisker position
        "q1": 14336,   # First quartile (25th percentile)
        "med": 34304,  # Median         (50th percentile)
        "q3": 61440,   # Third quartile (75th percentile)
        "whishi": 3159650,  # Top whisker position
        "fliers": []        # Outliers
    },
    {
        "label": "Linux",
        "whislo": 0,
        "q1": 9424.5,
        "med": 27008,
        "q3": 64084,
        "whishi": 263800800,
        "fliers": []
    },
    {
        "label": "macOS",
        "whislo": 0,
        "q1": 345,
        "med": 433,
        "q3": 468,
        "whishi": 286984400,
        "fliers": []
    },
    {
        "label": "OwnData",
        "whislo": 1429,
        "q1": 163525.5,
        "med": 932744,
        "q3": 5923266,
        "whishi": 3099764000,
        "fliers": []
    },
    {
        "label": "NapierOne",
        "whislo": 24,
        "q1": 51712,
        "med": 434359.5,
        "q3": 1718313,
        "whishi": 3099764000,
        "fliers": []
    }
]

fig, ax = plt.subplots(figsize=(10, 6))
ax.bxp(data, vert=False, showfliers=False)
ax.set_xscale('log')
ax.set_title('Distribution of file sizes across the benign data sets used')
ax.set_xlabel('File size (bytes)')
ax.set_ylabel('Data subsets')

plt.show()
