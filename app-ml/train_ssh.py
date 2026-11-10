"""Entraîne le détecteur SSH (Isolation Forest) sur du trafic normal UNIQUEMENT.
Usage : python app-ml/train_ssh.py <log_normal>"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.append(str(Path(__file__).resolve().parent))
from features_logs import FEATURE_NAMES, SSH_WINDOW, build_features  # noqa: E402
from ingestion import load_auth_log  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "models" / "ssh" / "v001"
SEED = 42

path = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "data/raw/auth_normal.log")
events = load_auth_log(path)
if (events["failed"] == 1).any():
    sys.exit(f"ARRÊT : {int(events['failed'].sum())} échecs dans {path}. "
             "Le jeu d'entraînement doit être normal (aucune attaque).")
keys, X = build_features(events)
if len(X) < 30:
    sys.exit(f"Trop peu de fenêtres ({len(X)}). Laisse tourner le trafic normal plus longtemps.")

model = IsolationForest(n_estimators=200, contamination="auto", random_state=SEED).fit(X)
scores = -model.score_samples(X)
threshold = float(np.percentile(scores, 99.5))   # fixé sur le normal, sans voir d'attaque

OUT.mkdir(parents=True, exist_ok=True)
joblib.dump(model, OUT / "model.joblib")
meta = {"version": "ssh-v001", "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "IsolationForest", "window_seconds": SSH_WINDOW, "features": FEATURE_NAMES,
        "train_windows": int(len(X)), "train_events": int(len(events)), "random_state": SEED,
        "threshold": round(threshold, 6),
        "threshold_rule": "percentile 99,5 des scores d'entraînement (normal uniquement)",
        "score_convention": "score = -score_samples ; plus élevé = plus anormal"}
(OUT / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Modèle SSH entraîné sur {len(X)} fenêtres normales ; seuil = {threshold:.4f}")
print(f"Sauvegardé dans {OUT}")
