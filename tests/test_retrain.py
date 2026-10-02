"""Test de l'étape 8 (FR-19, FR-20). Usage : python tests/test_retrain.py"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import db  # noqa: E402
import retrain  # noqa: E402
from score import active_version_dir, load_config, load_version, score_matrix  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


print("== 1. Règle de décision ==")
old = {"f1": 0.90, "false_positive_rate": 0.05}
check("F1 meilleur et FPR plus bas -> promu", retrain.decide(old, {"f1": 0.91, "false_positive_rate": 0.04}))
check("F1 égal et FPR plus bas -> promu", retrain.decide(old, {"f1": 0.90, "false_positive_rate": 0.04}))
check("F1 égal et FPR égal -> refusé", not retrain.decide(old, {"f1": 0.90, "false_positive_rate": 0.05}))
check("F1 plus bas -> refusé", not retrain.decide(old, {"f1": 0.89, "false_positive_rate": 0.01}))
check("F1 meilleur mais FPR plus haut -> refusé", not retrain.decide(old, {"f1": 0.95, "false_positive_rate": 0.06}))

print("== 2. Pointeur de version active ==")
with tempfile.TemporaryDirectory() as tmp:
    m = Path(tmp)
    for v in ("v001", "v002", "v003"):
        (m / v).mkdir()
        (m / v / "model.joblib").write_bytes(b"x")
    check("sans pointeur -> dernière version", active_version_dir(m).name == "v003")
    (m / "active.txt").write_text("v001\n")
    check("pointeur v001 -> v001 (même si v003 existe)", active_version_dir(m).name == "v001")
    (m / "active.txt").write_text("v999\n")
    check("pointeur vers version absente -> repli sur v003", active_version_dir(m).name == "v003")

print("== 3. Cycle complet (base et modèles temporaires) ==")
cfg = load_config()
min_fb = cfg["retrain"]["min_feedback"]
n_fp = min_fb + 10
real_models = ROOT / cfg["paths"]["models"]
models_before = sorted(p.name for p in real_models.iterdir())
cfg_file = ROOT / "config.yaml"
cfg_before = cfg_file.read_bytes()

data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
X_val, y_val = data["X_val"], data["y_val"]
model, pre, meta, real_dir = load_version(cfg)
s = score_matrix(model, X_val)
normal_idx = np.where(y_val == 0)[0]
top = normal_idx[np.argsort(-s[normal_idx])][:n_fp]             # normaux les plus alarmants
attack_idx = int(np.where(y_val == 1)[0][0])

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    models = tmp / "models"
    models.mkdir()
    shutil.copytree(real_dir, models / real_dir.name)
    (models / "active.txt").write_text(real_dir.name + "\n")
    cfg_t = dict(cfg)
    cfg_t["paths"] = {**cfg["paths"], "models": str(models)}
    dbp = tmp / "test.db"

    alerts = [{"index": int(i), "score": float(s[i]), "severity": "faible",
               "top_features": [("count", 1.0)]} for i in top]
    ids = db.insert_alerts(alerts, X_val, meta["version"], path=dbp)
    for i in ids[:min_fb - 1]:
        db.add_feedback(i, "faux_positif", "test", path=dbp)
    r = retrain.run_cycle(cfg_t, dbp, apply_config=False)
    check(f"{min_fb - 1} faux positifs (< minimum) -> cycle ignoré", r["status"] == "skipped", r["status"])
    check("aucun modèle créé quand ignoré", len([p for p in models.iterdir() if p.is_dir()]) == 1)

    for i in ids[min_fb - 1:]:
        db.add_feedback(i, "faux_positif", "test", path=dbp)
    vp = db.insert_alerts([{"index": attack_idx, "score": float(s[attack_idx]), "severity": "élevée",
                            "top_features": []}], X_val, meta["version"], path=dbp)[0]
    db.add_feedback(vp, "vrai_positif", "test", path=dbp)

    r = retrain.run_cycle(cfg_t, dbp, apply_config=False)
    new_dir = models / r["new_version"]
    nmeta = json.loads((new_dir / "metadata.json").read_text()) if new_dir.exists() else {}
    print(f"  (info) F1 {r['old']['f1']:.4f} -> {r['new']['f1']:.4f} | "
          f"FPR {r['old']['false_positive_rate']:.4f} -> {r['new']['false_positive_rate']:.4f} | {r['status']}")

    check(f"{n_fp} faux positifs utilisés (le vrai positif est exclu)", r["n_feedback"] == n_fp, str(r["n_feedback"]))
    check("statut = promu ou rejeté", r["status"] in ("promoted", "rejected"), r["status"])
    check("nouvelle version sauvegardée", new_dir.exists() and r["new_version"] != real_dir.name
          and (new_dir / "model.joblib").exists() and (new_dir / "metadata.json").exists(), r["new_version"])
    check("metadata : version parente enregistrée", nmeta.get("parent_version") == real_dir.name)
    check("entraînement = données normales + faux positifs",
          nmeta.get("train_samples") == data["X_train"].shape[0] + n_fp, str(nmeta.get("train_samples")))
    check("décision conforme à la règle FR-20 et tracée",
          r["promoted"] == retrain.decide(r["old"], r["new"]) and nmeta["decision"]["promoted"] == r["promoted"])
    expected_active = r["new_version"] if r["promoted"] else real_dir.name
    check("pointeur active.txt cohérent avec la décision",
          active_version_dir(models).name == expected_active, expected_active)
    left = db.false_positives_for_retraining(path=dbp)
    check("faux positifs marqués utilisés seulement si promu",
          len(left) == (0 if r["promoted"] else n_fp), f"{len(left)} restants")

check("vrai dossier models/ inchangé", sorted(p.name for p in real_models.iterdir()) == models_before)
check("config.yaml inchangé", cfg_file.read_bytes() == cfg_before)

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
