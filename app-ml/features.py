"""Features : encodage, normalisation, découpage train / validation / test."""
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

sys.path.append(str(Path(__file__).resolve().parent))
from ingestion import NUMERIC, load_nsl_kdd  # noqa: E402

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
CAT_COLS = ["protocol_type", "service", "flag"]
NUM_COLS = [c for c in NUMERIC if c != "difficulty"]   # 38 variables
LOG_COLS = ["duration", "src_bytes", "dst_bytes"]      # très asymétriques


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _log(df):
    """Réduit l'écart d'échelle des variables très étalées."""
    df = df.copy()
    for c in LOG_COLS:
        df[c] = np.log1p(df[c].clip(lower=0))
    return df


def fit_preprocessor(df):
    """Ajuste encodeur + scaler (à appeler sur le trafic normal d'entraînement uniquement)."""
    pre = ColumnTransformer(
        [("num", StandardScaler(), NUM_COLS),
         ("cat", OneHotEncoder(handle_unknown="ignore"), CAT_COLS)],
        sparse_threshold=0,   # sortie dense
    )
    pre.fit(_log(df))
    return pre


def transform(df, pre):
    """Applique exactement la même transformation (entraînement et scoring)."""
    return pre.transform(_log(df)).astype(np.float32)


def feature_names(pre):
    return list(pre.get_feature_names_out())


def build_datasets(cfg=None):
    cfg = cfg or load_config()
    seed = cfg["random_seed"]
    raw = ROOT / cfg["paths"]["raw"]

    full = load_nsl_kdd(raw / "KDDTrain+.txt")
    test = load_nsl_kdd(raw / "KDDTest+.txt")

    full_attack = (full["label"] != "normal").astype(int)
    train_part, val = train_test_split(
        full, test_size=0.2, stratify=full_attack, random_state=seed
    )
    train_normal = train_part[train_part["label"] == "normal"]

    pre = fit_preprocessor(train_normal)

    return {
        "pre": pre,
        "X_train": transform(train_normal, pre),                       # normal seulement
        "X_val": transform(val, pre),
        "y_val": (val["label"] != "normal").astype(int).to_numpy(),    # 1 = attaque
        "X_test": transform(test, pre),
        "y_test": (test["label"] != "normal").astype(int).to_numpy(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = load_config()
    d = build_datasets(cfg)

    out = ROOT / cfg["paths"]["processed"]
    out.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out / "datasets.npz",
        X_train=d["X_train"], X_val=d["X_val"], y_val=d["y_val"],
        X_test=d["X_test"], y_test=d["y_test"],
    )
    joblib.dump(d["pre"], out / "preprocessor.joblib")
    joblib.dump(feature_names(d["pre"]), out / "feature_names.joblib")

    print("X_train :", d["X_train"].shape, "(normal uniquement)")
    print("X_val   :", d["X_val"].shape, "| attaques :", int(d["y_val"].sum()))
    print("X_test  :", d["X_test"].shape, "| attaques :", int(d["y_test"].sum()))
    print("Variables après encodage :", len(feature_names(d["pre"])))
