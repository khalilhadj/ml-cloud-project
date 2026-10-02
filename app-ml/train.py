"""Entraînement de l'Isolation Forest (non supervisé) et versionnement du modèle."""
import json
import logging
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
import yaml
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def next_version_dir(models_dir):
    """Retourne models/vNNN avec NNN = dernière version + 1."""
    models_dir.mkdir(parents=True, exist_ok=True)
    nums = [int(m.group(1)) for p in models_dir.iterdir()
            if (m := re.fullmatch(r"v(\d+)", p.name))]
    return models_dir / f"v{(max(nums) + 1 if nums else 1):03d}"


def train_model(X_train, cfg):
    mcfg = cfg["model"]
    model = IsolationForest(
        n_estimators=mcfg["n_estimators"],
        contamination=mcfg["contamination"],
        max_samples=mcfg.get("max_samples", 256),
        random_state=cfg["random_seed"],
        n_jobs=-1,
    )
    model.fit(X_train)
    return model


def anomaly_score(model, X):
    """Plus le score est élevé, plus l'événement est anormal."""
    return -model.score_samples(X)


def save_version(model, pre, cfg, X_train, extra=None):
    out = next_version_dir(ROOT / cfg["paths"]["models"])
    out.mkdir(parents=True)
    joblib.dump(model, out / "model.joblib")
    joblib.dump(pre, out / "preprocessor.joblib")
    meta = {
        "version": out.name,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "IsolationForest",
        "hyperparameters": {
            "n_estimators": cfg["model"]["n_estimators"],
            "contamination": cfg["model"]["contamination"],
            "max_samples": cfg["model"].get("max_samples", 256),
            "random_state": cfg["random_seed"],
        },
        "train_samples": int(X_train.shape[0]),
        "n_features": int(X_train.shape[1]),
        "sklearn_version": sklearn.__version__,
        "score_convention": "score = -score_samples ; plus élevé = plus anormal",
        "metrics": {},
    }
    if extra:
        meta.update(extra)
    with open(out / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = load_config()
    proc = ROOT / cfg["paths"]["processed"]

    data = np.load(proc / "datasets.npz")
    pre = joblib.load(proc / "preprocessor.joblib")
    X_train = data["X_train"]

    logger.info("Entraînement sur %d événements normaux (%d variables)", *X_train.shape)
    model = train_model(X_train, cfg)

    out = save_version(model, pre, cfg, X_train)
    s_train = anomaly_score(model, X_train)
    s_val = anomaly_score(model, data["X_val"])
    print("Modèle sauvegardé dans :", out)
    print(f"Score moyen train (normal)      : {s_train.mean():.4f}")
    print(f"Score moyen validation (mélange): {s_val.mean():.4f}")
