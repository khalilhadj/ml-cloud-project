"""Diagnostic : rappel par famille d'attaque sur le test, au seuil figé dans config.yaml."""
import numpy as np
import pandas as pd

from ingestion import load_nsl_kdd
from score import ROOT, load_config, load_version, score_matrix

FAMILIES = {
    "DoS": ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
            "udpstorm", "processtable", "worm", "mailbomb"],
    "Probe": ["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"],
    "R2L": ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
            "warezclient", "warezmaster", "xlock", "xsnoop", "snmpguess",
            "snmpgetattack", "httptunnel", "sendmail", "named"],
    "U2R": ["buffer_overflow", "loadmodule", "perl", "rootkit", "ps",
            "sqlattack", "xterm"],
}
LABEL_TO_FAMILY = {lab: fam for fam, labs in FAMILIES.items() for lab in labs}


def main():
    cfg = load_config()
    thr = cfg["detection"]["threshold"]
    model, _, meta, _ = load_version(cfg)

    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    train = load_nsl_kdd(str(ROOT / "data/raw/KDDTrain+.txt"))
    test = load_nsl_kdd(str(ROOT / "data/raw/KDDTest+.txt"))

    assert ((test.label != "normal").astype(int).values == data["y_test"]).all(), \
        "Ordre de X_test différent de KDDTest+ : diagnostic impossible"

    scores = score_matrix(model, data["X_test"])
    df = pd.DataFrame({"label": test.label.values, "detected": scores >= thr})
    att = df[df.label != "normal"].copy()
    att["family"] = att.label.map(LABEL_TO_FAMILY).fillna("autre")
    att["known"] = att.label.isin(set(train.label))

    print(f"Modèle {meta['version']}, seuil {thr}")
    print("\nRappel par famille :")
    print(att.groupby("family").detected.agg(["mean", "sum", "count"]).round(3))
    print("\nRappel attaques connues / inconnues :")
    print(att.groupby("known").detected.agg(["mean", "sum", "count"]).round(3))
    print("\nLes 10 attaques les plus nombreuses et leur rappel :")
    top = att.groupby("label").detected.agg(["mean", "sum", "count"])
    print(top.sort_values("count", ascending=False).head(10).round(3))


if __name__ == "__main__":
    main()
