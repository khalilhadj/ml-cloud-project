"""ACC-4 : génère des alertes depuis X_test, les qualifie avec le label NSL-KDD
(analyste = 'oracle-nslkdd'), puis affiche l'état avant réentraînement.
Usage : docker compose exec -T scheduler python - < attacks/acc4_cycle.py"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path("/app")
sys.path.insert(0, str(ROOT / "app-ml"))

import db  # noqa: E402
from alerts import generate_alerts  # noqa: E402
from score import load_config, load_version, score_matrix  # noqa: E402

N_NORMAL, N_ATTACK, SEED = 1500, 500, 42
ANALYST = "oracle-nslkdd"

cfg = load_config()
model, pre, meta, _ = load_version(cfg)
names = list(pre.get_feature_names_out())
data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
X, y = data["X_test"], data["y_test"]

rng = np.random.default_rng(SEED)
idx = np.concatenate([
    rng.choice(np.where(y == 0)[0], N_NORMAL, replace=False),
    rng.choice(np.where(y == 1)[0], N_ATTACK, replace=False)])
Xs = X[idx]

print("AVANT :", db.stats())
alerts = generate_alerts(Xs, score_matrix(model, Xs), cfg, names)
ids = db.insert_alerts(alerts, Xs, meta["version"])
assert len(ids) == len(alerts), "ids et alertes désalignés"

n_fp = n_tp = 0
for alert_id, a in zip(ids, alerts):
    is_attack = int(y[idx[a["index"]]]) == 1
    verdict = "vrai_positif" if is_attack else "faux_positif"
    db.add_feedback(alert_id, verdict, ANALYST, "label NSL-KDD (vérité terrain)")
    n_tp += is_attack
    n_fp += not is_attack

out = ROOT / cfg["paths"]["processed"] / "acc4_test_indices.json"
out.write_text(json.dumps({"seed": SEED, "test_indices": idx.tolist()}))
print(f"{len(alerts)} alertes sur {len(idx)} événements : {n_tp} vrais positifs, {n_fp} faux positifs")
print("APRÈS :", db.stats())
print("prêts pour le réentraînement :", len(db.false_positives_for_retraining()), "/", cfg["retrain"]["min_feedback"])
