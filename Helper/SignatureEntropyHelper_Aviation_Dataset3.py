import pandas as pd

# 40 Ransomware, 4000 Benign

data_signature = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [20, 17, 0, 0, 0, 0, 0, 0, 0, 0], 'Sig_BG': [0, 3, 20, 20, 20, 20, 20, 20, 20, 20], 'Sig_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}
data_entropy = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [20, 20, 17, 15, 14, 11, 11, 13, 17, 12], 'Entr_BG': [0, 0, 3, 5, 6, 9, 9, 7, 3, 8], 'Entr_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}



df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

combined_df['Sig_RW'] = (combined_df['Sig_RW'] - 20) / 20 * 100
#combined_df['Sig_BG'] = (combined_df['Sig_BG'] - 4000) / 4000 * 100
combined_df['Entr_RW'] = (combined_df['Entr_RW'] - 20) / 20 * 100
#combined_df['Entr_BG'] = (combined_df['Entr_BG'] - 4000) / 4000 * 100

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)
print(combined_df)
