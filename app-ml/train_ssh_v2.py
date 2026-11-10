"""Entraîne le détecteur SSH (Isolation Forest) sur du trafic normal UNIQUEMENT.
Variante v2 : seuil = médiane + 3 x MAD (robuste à un point isolé), au lieu du
percentile 99,5 utilisé dans train_ssh.py. Sur un petit échantillon (~100-150
fenêtres), le percentile 99,5 coïncide quasiment avec le score maximum observé,
donc un seul point limite de l'entraînement fixe tout le seuil sans marge réelle.
La médiane + k x MAD est moins sensible à ce point unique.
Usage : python app-ml/train_ssh_v2.py <log_normal>"""
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
OUT = ROOT / "models" / "ssh" / "v002"
SEED = 42
K = 3   # nombre de MAD au-dessus de la médiane

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

# Ancien calcul, conservé uniquement pour comparaison documentée dans metadata.json
threshold_percentile = float(np.percentile(scores, 99.5))

# Nouveau calcul : médiane + k x MAD (constante 1,4826 = équivalent écart-type
# pour une distribution normale, convention statistique standard pour le MAD).
median_score = float(np.median(scores))
mad = float(np.median(np.abs(scores - median_score)))
robust_std = 1.4826 * mad
threshold = median_score + K * robust_std

OUT.mkdir(parents=True, exist_ok=True)
joblib.dump(model, OUT / "model.joblib")
meta = {"version": "ssh-v002", "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "IsolationForest", "window_seconds": SSH_WINDOW, "features": FEATURE_NAMES,
        "train_windows": int(len(X)), "train_events": int(len(events)), "random_state": SEED,
        "threshold": round(threshold, 6),
        "threshold_rule": f"médiane + {K} x MAD (robuste à un point isolé, cf. percentile 99,5 instable sur petit échantillon)",
        "threshold_percentile_995_pour_comparaison": round(threshold_percentile, 6),
        "median_score": round(median_score, 6), "mad": round(mad, 6),
        "score_convention": "score = -score_samples ; plus élevé = plus anormal"}
(OUT / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Modèle SSH v002 entraîné sur {len(X)} fenêtres normales ; seuil (médiane+{K}MAD) = {threshold:.4f} "
      f"(pour référence, percentile 99,5 aurait donné {threshold_percentile:.4f})")
print(f"Sauvegardé dans {OUT}")
