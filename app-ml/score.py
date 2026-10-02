"""Chargement du dernier modèle versionné et calcul des scores d'anomalie."""
import json
import re
from pathlib import Path

import joblib
import yaml

from train import anomaly_score

ROOT = Path(__file__).resolve().parents[1]


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def latest_version_dir(models_dir):
    nums = [int(m.group(1)) for p in models_dir.iterdir()
            if p.is_dir() and (m := re.fullmatch(r"v(\d+)", p.name))
            and (p / "model.joblib").exists()]
    if not nums:
        raise FileNotFoundError(f"Aucun modèle versionné dans {models_dir}")
    return models_dir / f"v{max(nums):03d}"


def load_version(cfg=None, version=None):
    """Retourne (model, preprocessor, metadata, dossier). version=None -> la plus récente."""
    cfg = cfg or load_config()
    models_dir = ROOT / cfg["paths"]["models"]
    vdir = models_dir / version if version else latest_version_dir(models_dir)
    model = joblib.load(vdir / "model.joblib")
    pre = joblib.load(vdir / "preprocessor.joblib")
    with open(vdir / "metadata.json", encoding="utf-8") as f:
        meta = json.load(f)
    return model, pre, meta, vdir


def score_matrix(model, X):
    """Score d'anomalie pour chaque ligne d'une matrice déjà transformée."""
    return anomaly_score(model, X)


if __name__ == "__main__":
    import numpy as np
    cfg = load_config()
    model, pre, meta, vdir = load_version(cfg)
    X_test = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")["X_test"]
    s = score_matrix(model, X_test)
    print(f"Modèle {meta['version']} : {len(s)} scores, min={s.min():.3f} max={s.max():.3f}")
