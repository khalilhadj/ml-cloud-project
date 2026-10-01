import pandas as pd

COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty",
]

for name in ["KDDTrain+.txt", "KDDTest+.txt"]:
    df = pd.read_csv(f"data/raw/{name}", header=None, names=COLS)
    n_normal = (df["label"] == "normal").sum()
    print(f"\n=== {name} ===")
    print("Lignes, colonnes :", df.shape)
    print("Valeurs manquantes :", int(df.isna().sum().sum()))
    print(f"Normal : {n_normal} ({n_normal/len(df):.1%})")
    print(f"Attaques : {len(df)-n_normal} ({1-n_normal/len(df):.1%})")
    print("Types d'attaques distincts :", df.loc[df.label != 'normal', 'label'].nunique())
    print("Top 5 labels :")
    print(df["label"].value_counts().head(5).to_string())
