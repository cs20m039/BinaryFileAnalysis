import pandas as pd

# 40 Ransomware, 4000 Benign

data_signature = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [78, 75, 29, 29, 22, 19, 18, 18, 17, 17], 'Sig_BG': [3962, 3965, 4011, 4011, 4018, 4021, 4022, 4022, 4023, 4023], 'Sig_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}
data_entropy = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [721, 565, 512, 853, 608, 645, 469, 505, 535, 477], 'Entr_BG': [3312, 3473, 3523, 3168, 3417, 3386, 3561, 3522, 3495, 3551], 'Entr_UK': [7, 2, 5, 19, 15, 9, 10, 13, 10, 12]}



df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

combined_df['Sig_RW'] = (combined_df['Sig_RW'] - 40) / 40 * 100
combined_df['Sig_BG'] = (combined_df['Sig_BG'] - 4000) / 4000 * 100
combined_df['Entr_RW'] = (combined_df['Entr_RW'] - 40) / 40 * 100
combined_df['Entr_BG'] = (combined_df['Entr_BG'] - 4000) / 4000 * 100

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)
print(combined_df)
