import pandas as pd

# 40 Ransomware, 4000 Benign

data_signature = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [49, 49, 0, 0, 0, 0, 0, 0, 0, 0], 'Sig_BG': [431370, 432078, 431355, 431220, 430280, 431401, 433466, 431352, 429759, 433219], 'Sig_UK': [26647, 26679, 26695, 26488, 26506, 26518, 26706, 26454, 26400, 26763]}

data_entropy = {'Pattern': [150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [58658, 106266, 150269, 196870, 156439, 106045, 97808, 72476], 'Entr_BG': [493593, 445610, 400237, 353631, 395981, 447288, 455763, 481197], 'Entr_UK': [4042, 4427, 5797, 5804, 3885, 2976, 2738, 2636]}


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
