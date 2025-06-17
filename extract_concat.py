import pandas as pd

df1 = pd.read_csv("cve_ansi_enriched_local.csv")
df2 = pd.read_csv("cve_ansi_enriched_save.csv")

df_concat = pd.concat([df1, df2], ignore_index=True)
df_concat_unique = df_concat.drop_duplicates(subset="cve")
df_concat_unique = df_concat_unique.drop_duplicates()

print("Nombre de lignes après suppression des doublons :", len(df_concat_unique))
df_concat_unique.to_csv("cve_ansi_enriched_local_save.csv", index=False)