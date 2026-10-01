"""Vérification globale des étapes 1 à 4. Usage : python tests/check_all.py"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import features as F          # noqa: E402
import ingestion as I         # noqa: E402
import train as T             # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


cfg = F.load_config()
raw = ROOT / cfg["paths"]["raw"]
proc = ROOT / cfg["paths"]["processed"]

print("== 1. Données brutes ==")
for name, n in [("KDDTrain+.txt", 125973), ("KDDTest+.txt", 22544)]:
    p = raw / name
    lines = p.read_text(errors="replace").splitlines() if p.exists() else []
    check(f"{name} : {n} lignes", len(lines) == n, f"{len(lines)} lignes")
    check(f"{name} : 43 champs partout", lines and all(l.count(",") == 42 for l in lines))

print("== 2. Ingestion ==")
train = I.load_nsl_kdd(raw / "KDDTrain+.txt")
test = I.load_nsl_kdd(raw / "KDDTest+.txt")
check("train (125973, 43)", train.shape == (125973, 43), str(train.shape))
check("test (22544, 43)", test.shape == (22544, 43), str(test.shape))
check("aucune valeur manquante", train.isna().sum().sum() == 0 and test.isna().sum().sum() == 0)
check("train normal = 67343", (train.label == "normal").sum() == 67343)
check("test attaques = 12833", (test.label != "normal").sum() == 12833)
bad = Path("/tmp/_bad_kdd.txt")
bad.write_text(open(raw / "KDDTrain+.txt").readline() + "ligne,cassee\n")
check("ligne mal formée rejetée sans planter", I.load_nsl_kdd(bad).shape[0] == 1)

print("== 3. Features ==")
d = F.build_datasets(cfg)
Xtr, Xv, Xte = d["X_train"], d["X_val"], d["X_test"]
check("même nombre de colonnes partout", Xtr.shape[1] == Xv.shape[1] == Xte.shape[1], str(Xtr.shape[1]))
check("X_train ≈ 80 % du normal", abs(Xtr.shape[0] - 0.8 * 67343) < 5, str(Xtr.shape[0]))
check("X_val = 20 % du train", Xv.shape[0] == 25195, str(Xv.shape[0]))
check("y_val : attaques 11726", int(d["y_val"].sum()) == 11726, str(int(d["y_val"].sum())))
check("y_test : attaques 12833", int(d["y_test"].sum()) == 12833)
check("aucun NaN / inf", all(np.isfinite(x).all() for x in (Xtr, Xv, Xte)))
check("moyenne train ≈ 0 (scaler)", abs(Xtr[:, :38].mean()) < 1e-3)
names = F.feature_names(d["pre"])
check("label / difficulty absents des variables",
      not any("label" in n or "difficulty" in n for n in names))
d2 = F.build_datasets(cfg)
check("reproductible (graine fixe)", np.array_equal(Xtr, d2["X_train"]) and np.array_equal(Xv, d2["X_val"]))
unk = test.head(5).copy()
unk["service"] = "service_jamais_vu"
try:
    F.transform(unk, d["pre"])
    check("catégorie inconnue sans plantage", True)
except Exception as e:
    check("catégorie inconnue sans plantage", False, str(e))
if (proc / "datasets.npz").exists():
    saved = np.load(proc / "datasets.npz")
    check("datasets.npz identique au recalcul", np.array_equal(saved["X_test"], Xte))
else:
    check("datasets.npz présent (lance python app-ml/features.py)", False)
pre_saved = proc / "preprocessor.joblib"
check("preprocessor.joblib présent", pre_saved.exists())
if pre_saved.exists():
    check("préprocesseur rechargé = même transformation",
          np.allclose(F.transform(test.head(100), joblib.load(pre_saved)), Xte[:100]))

print("== 4. Modèle ==")
mdir = ROOT / cfg["paths"]["models"]
versions = sorted(p for p in mdir.iterdir() if re.fullmatch(r"v\d+", p.name) and (p / "model.joblib").exists()) \
    if mdir.exists() else []
check("au moins un modèle versionné", len(versions) >= 1, ", ".join(p.name for p in versions))
empty = [p.name for p in mdir.iterdir() if re.fullmatch(r"v\d+", p.name) and not (p / "model.joblib").exists()]
check("aucun dossier de version vide", not empty, ", ".join(empty))
if versions:
    v = versions[-1]
    for f in ["model.joblib", "preprocessor.joblib", "metadata.json"]:
        check(f"{v.name}/{f}", (v / f).exists())
    meta = json.loads((v / "metadata.json").read_text())
    for k in ["version", "created_at", "hyperparameters", "train_samples", "n_features", "metrics"]:
        check(f"metadata : clé '{k}'", k in meta)
    check("metadata.version = nom du dossier", meta.get("version") == v.name,
          f"{meta.get('version')} vs {v.name}")
    check("metadata.n_features = 77", meta.get("n_features") == Xtr.shape[1])
    model = joblib.load(v / "model.joblib")
    s_tr, s_val, s_te = (T.anomaly_score(model, X) for X in (Xtr, Xv, Xte))
    check("score validation > score train", s_val.mean() > s_tr.mean(),
          f"{s_val.mean():.4f} > {s_tr.mean():.4f}")
    auc_v = roc_auc_score(d["y_val"], s_val)
    auc_t = roc_auc_score(d["y_test"], s_te)
    check("AUC validation > 0.80", auc_v > 0.80, f"{auc_v:.3f}")
    check("AUC test > 0.75", auc_t > 0.75, f"{auc_t:.3f}")
    t0 = time.time()
    T.anomaly_score(model, np.repeat(Xte, 1, axis=0)[:10000])
    dt = time.time() - t0
    check("NFR-01 : 10 000 événements en < 10 s", dt < 10, f"{dt:.2f} s")
    m2 = T.train_model(Xtr, cfg)
    check("entraînement reproductible (graine 42)",
          np.allclose(model.score_samples(Xv[:2000]), m2.score_samples(Xv[:2000])))

print("== 5. Git ==")
def git(*a):
    return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
check(".env non suivi par Git", git("ls-files", ".env") == "")
check(".env.example suivi", ".env.example" in git("ls-files"))
check("data brutes non suivies", not any(l.startswith("data/raw/KDD") for l in git("ls-files").splitlines()))
check("modèles non suivis", not any(l.endswith(".joblib") for l in git("ls-files").splitlines()))
check("au moins un commit", git("log", "--oneline") != "")

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
