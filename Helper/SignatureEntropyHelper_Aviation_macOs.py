import pandas as pd

# 40 Ransomware, 4000 Benign

data_signature = {'Pattern': [100, 150, 200, 250, 300, 350, 400, 450, 500], 'Sig_RW': [36, 0, 0, 0, 0, 0, 0, 0, 0], 'Sig_BG': [544671, 541868, 541710, 541712, 541714, 541716, 541718, 541718, 542488], 'Sig_UK': [147, 147, 147, 147, 147, 147, 147, 147, 147]}

data_entropy = {'Pattern': [50, 100, 150, 200, 250, 300, 350, 400, 450, 500], 'Entr_RW': [51123, 57640, 65588, 79706, 106631, 133679, 125848, 111374, 108185, 102819], 'Entr_BG': [459448, 417034, 404345, 395021, 365499, 341587, 350314, 362571, 369805, 376330], 'Entr_UK': [94469, 129532, 129205, 128703, 130295, 130013, 131245, 129797, 128494, 130148]}


df_ds1 = pd.DataFrame(data_signature)
df_ds2 = pd.DataFrame(data_entropy)

combined_df = pd.merge(df_ds1, df_ds2, on='Pattern')

#combined_df['Sig_RW'] = (combined_df['Sig_RW'] - 350715) / 350715 * 100
combined_df['Sig_BG'] = (combined_df['Sig_BG'] - 541857) / 541857 * 100
#combined_df['Sig_UK'] = (combined_df['Sig_UK'] - 350715) / 350715 * 100

#combined_df['Entr_RW'] = (combined_df['Entr_RW'] - 350715) / 350715 * 100
combined_df['Entr_BG'] = (combined_df['Entr_BG'] - 541857) / 541857 * 100
#combined_df['Entr_UK'] = (combined_df['Entr_UK'] - 350715) / 350715 * 100

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)
print(combined_df)
