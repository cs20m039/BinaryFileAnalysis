import pandas as pd

# Data for Result Set 1 (DS1) and Result Set 2 (DS2)
data_signature = {
    'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500],
    'Sig_RW': [1944, 1847, 280, 280, 280, 280, 280, 280, 280, 280],
    'Sig_BG': [8336, 8433, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000],
    'Sig_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
}

data_entropy = {
    'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500],
    'Entr_RW': [2771, 2940, 2813, 2837, 2959, 3291, 2997, 2895, 2761, 2514],
    'Entr_BG': [7509, 7340, 7467, 7443, 7321, 6989, 7283, 7385, 7519, 7766],
    'Entr_UN': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
}

df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

# Merging datasets on Pattern
combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

# Adjusting deviation calculations with a condition
combined_df['Sig_RW'] = combined_df.apply(lambda row: 0 if row['Sig_RW'] == 280 else row['Sig_RW'] / 280, axis=1)
combined_df['Sig_BG'] = combined_df.apply(lambda row: 0 if row['Sig_BG'] == 10000 else row['Sig_BG'] / 10000, axis=1)
combined_df['Sig_UK'] = combined_df['Sig_UK'] / 1  # No change needed as it's always 0

combined_df['Entr_RW'] = combined_df.apply(lambda row: 0 if row['Entr_RW'] == 280 else row['Entr_RW'] / 280, axis=1)
combined_df['Entr_BG'] = combined_df.apply(lambda row: 0 if row['Entr_BG'] == 10000 else row['Entr_BG'] / 10000, axis=1)
combined_df['Entr_UK'] = combined_df['Entr_UK'] / 1  # No change needed as it's always 0


# Ensuring all columns are displayed in the output
pd.set_option('display.max_columns', None)
for index, row in combined_df.iterrows():
    print(f"{int(row['Pattern'])} {row['Sig_RW']:.2f} {row['Sig_BG']:.2f} {row['Sig_UK']:.2f} {row['Entr_RW']:.2f} {row['Entr_BG']:.2f} {row['Entr_UK']:.2f}")


