"""ACC-4 cycle 2 : génère des alertes depuis X_test SANS les qualifier (qualification humaine au dashboard).
Graine différente de acc4_cycle.py, événements déjà utilisés exclus. Les labels vont dans un fichier
séparé (jamais en base) pour mesurer ensuite l'accord entre l'analyste et la vérité terrain.
Usage : docker compose exec -T scheduler python - < attacks/acc4_human_batch.py"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path("/app")
sys.path.insert(0, str(ROOT / "app-ml"))

import db  # noqa: E402
from alerts import generate_alerts  # noqa: E402
from score import load_config, load_version, score_matrix  # noqa: E402

N_NORMAL, N_ATTACK, SEED = 450, 50, 7

cfg = load_config()
model, pre, meta, _ = load_version(cfg)
names = list(pre.get_feature_names_out())
proc = ROOT / cfg["paths"]["processed"]
data = np.load(proc / "datasets.npz")
X, y = data["X_test"], data["y_test"]

used = set()
prev = proc / "acc4_test_indices.json"
if prev.exists():
    used = set(json.loads(prev.read_text())["test_indices"])
free = np.array([i for i in range(len(y)) if i not in used])
rng = np.random.default_rng(SEED)
idx = np.concatenate([
    rng.choice(free[y[free] == 0], N_NORMAL, replace=False),
    rng.choice(free[y[free] == 1], N_ATTACK, replace=False)])
Xs = X[idx]

print("AVANT :", db.stats())
alerts = generate_alerts(Xs, score_matrix(model, Xs), cfg, names)
ids = db.insert_alerts(alerts, Xs, meta["version"])
assert len(ids) == len(alerts)
truth = {int(i): int(y[idx[a["index"]]]) for i, a in zip(ids, alerts)}
(proc / "acc4_human_batch.json").write_text(json.dumps(
    {"seed": SEED, "model": meta["version"], "test_indices": idx.tolist(), "truth_by_alert_id": truth}))
print(f"{len(alerts)} alertes créées, AUCUNE qualifiée. Modèle {meta['version']}")
print("APRÈS :", db.stats())
