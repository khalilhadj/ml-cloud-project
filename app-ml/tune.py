"""Comparaison de configurations sur la VALIDATION uniquement (le test n'est jamais lu)."""
import itertools
import time

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

import features as F
from diagnose import LABEL_TO_FAMILY
from ingestion import load_nsl_kdd

FEATURE_SETS = {
    "toutes(77)": (F.NUM_COLS, ["protocol_type", "service", "flag"]),
    "sans_service": (F.NUM_COLS, ["protocol_type", "flag"]),
    "numeriques": (F.NUM_COLS, []),
}
MAX_SAMPLES = [256, 1024]
MAX_FEATURES = [1.0, 0.5]


def best_f1(y, s):
    p, r, _ = precision_recall_curve(y, s)
    f1 = 2 * p[:-1] * r[:-1] / np.clip(p[:-1] + r[:-1], 1e-12, None)
    return float(f1.max())


def f1_at_best(y, s):
    p, r, t = precision_recall_curve(y, s)
    f1 = 2 * p[:-1] * r[:-1] / np.clip(p[:-1] + r[:-1], 1e-12, None)
    return float(t[int(np.argmax(f1))])


def main():
    cfg = F.load_config()
    seed = cfg["random_seed"]
    full = load_nsl_kdd(F.ROOT / cfg["paths"]["raw"] / "KDDTrain+.txt")
    y_all = (full.label != "normal").astype(int)
    train_part, val = train_test_split(full, test_size=0.2, stratify=y_all, random_state=seed)
    assert len(val) == 25195, "Découpage différent de features.py"
    train_normal = train_part[train_part.label == "normal"]

    y_val = (val.label != "normal").astype(int).to_numpy()
    no_nep = (val.label != "neptune").to_numpy()
    fam = val.label.map(LABEL_TO_FAMILY).fillna("normal").to_numpy()
    r2l = fam == "R2L"

    rows = []
    for (fs_name, (num, cat)), ms, mf in itertools.product(FEATURE_SETS.items(), MAX_SAMPLES, MAX_FEATURES):
        t0 = time.time()
        parts = [("num", StandardScaler(), num)]
        if cat:
            parts.append(("cat", OneHotEncoder(handle_unknown="ignore"), cat))
        pre = ColumnTransformer(parts, sparse_threshold=0)
        pre.fit(F._log(train_normal))
        Xtr = pre.transform(F._log(train_normal)).astype(np.float32)
        Xv = pre.transform(F._log(val)).astype(np.float32)

        model = IsolationForest(n_estimators=cfg["model"]["n_estimators"], max_samples=ms,
                                max_features=mf, random_state=seed, n_jobs=-1).fit(Xtr)
        s = -model.score_samples(Xv)

        thr = f1_at_best(y_val, s)
        rows.append({
            "variables": fs_name, "n_col": Xtr.shape[1], "max_samples": ms, "max_features": mf,
            "F1_val": round(best_f1(y_val, s), 4),
            "F1_val_sans_neptune": round(best_f1(y_val[no_nep], s[no_nep]), 4),
            "AUC_val": round(roc_auc_score(y_val, s), 4),
            "rappel_R2L": round(float((s[r2l] >= thr).mean()), 3),
            "sec": round(time.time() - t0, 1),
        })
        print(rows[-1], flush=True)

    res = pd.DataFrame(rows).sort_values("F1_val_sans_neptune", ascending=False)
    out = F.ROOT / cfg["paths"]["processed"] / "tune_results.csv"
    res.to_csv(out, index=False)
    print("\n=== Classement (validation uniquement) ===")
    print(res.to_string(index=False))
    print("\nRésultats sauvegardés dans", out)


if __name__ == "__main__":
    main()
