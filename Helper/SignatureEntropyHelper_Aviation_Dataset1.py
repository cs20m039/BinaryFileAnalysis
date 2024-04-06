import pandas as pd

data_signature = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [1944, 1847, 280, 280, 280, 280, 280, 280, 280, 280], 'Sig_BG': [8336, 8433, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000], 'Sig_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}


data_entropy = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [2771, 2940, 2813, 2837, 2959, 3291, 2997, 2895, 2761, 2514], 'Entr_BG': [7509, 7340, 7467, 7443, 7321, 6989, 7283, 7385, 7519, 7766], 'Entr_UK': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}


df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

combined_df['Sig_RW'] = (combined_df['Sig_RW'] - 280) / 280
combined_df['Sig_BG'] = (combined_df['Sig_BG'] - 10000) / 10000
combined_df['Entr_RW'] = (combined_df['Entr_RW'] - 280) / 280
combined_df['Entr_BG'] = (combined_df['Entr_BG'] - 10000) / 10000

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)
print(combined_df)
