import pandas as pd

# 40 Ransomware, 4000 Benign

data_signature = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [41537, 38790, 0, 0, 0, 0, 0, 0, 0, 0], 'Sig_BG': [308859, 311596, 350389, 350392, 350396, 350403, 350404, 350406, 350407, 350406], 'Sig_UK': [329, 329, 329, 326, 329, 329, 329, 326, 326, 330]}
data_entropy = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [48783, 102764, 48907, 38971, 51268, 50740, 57871, 50872, 55473, 51768], 'Entr_BG': [300947, 245990, 300094, 310217, 297792, 298504, 291307, 298365, 293809, 297505], 'Entr_UK': [1339, 2322, 2069, 1887, 2016, 1835, 1905, 1846, 1802, 1815]}


df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

#combined_df['Sig_RW'] = (combined_df['Sig_RW'] - 350715) / 350715 * 100
combined_df['Sig_BG'] = (combined_df['Sig_BG'] - 350715) / 350715 * 100
#combined_df['Sig_UK'] = (combined_df['Sig_UK'] - 350715) / 350715 * 100

#combined_df['Entr_RW'] = (combined_df['Entr_RW'] - 350715) / 350715 * 100
combined_df['Entr_BG'] = (combined_df['Entr_BG'] - 350715) / 350715 * 100
#combined_df['Entr_UK'] = (combined_df['Entr_UK'] - 350715) / 350715 * 100

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)
print(combined_df)
