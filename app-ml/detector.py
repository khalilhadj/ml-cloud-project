"""Détecteur SSH en continu (FR-23, ACC-2) : lit auth.log, agrège par IP et fenêtre de 10 s,
score avec le modèle SSH, écrit les alertes dans une base SQLite dédiée.
Usage : python app-ml/detector.py --once [--since "2026-11-10 01:45:00"]
        python app-ml/detector.py --follow            (boucle toutes les 5 s)"""
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import json

sys.path.append(str(Path(__file__).resolve().parent))
import db  # noqa: E402
from features_logs import FEATURE_NAMES, build_features  # noqa: E402
from ingestion import load_auth_log  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models" / "ssh" / "v002"
DB_SSH = ROOT / "data" / "alerts_ssh.db"      # base séparée : 6 variables, pas les 77 de NSL-KDD
NORMAL_LOG = ROOT / "data" / "raw" / "auth_normal.log"


def load_detector():
    model = joblib.load(MODEL_DIR / "model.joblib")
    meta = json.loads((MODEL_DIR / "metadata.json").read_text(encoding="utf-8"))
    _, Xn = build_features(load_auth_log(str(NORMAL_LOG)))
    return model, meta, Xn.mean(axis=0), Xn.std(axis=0) + 1e-6


def severity(score, thr):
    r = score / thr
    return "high" if r >= 1.5 else "medium" if r >= 1.2 else "low"


def scan(log_path, model, meta, mu, sd, seen, since=None):
    thr = meta["threshold"]
    keys, X = build_features(load_auth_log(log_path))
    if len(X) == 0:
        return 0
    scores = -model.score_samples(X)
    alerts, idx = [], []
    for i in range(len(X)):
        key = (keys.iloc[i]["src_ip"], str(keys.iloc[i]["window_start"]))
        if key in seen or (since is not None and keys.iloc[i]["window_start"] < since):
            continue
        if scores[i] >= thr:
            z = (X[i] - mu) / sd
            top = [{"feature": FEATURE_NAMES[j], "value": round(float(X[i][j]), 3), "z": round(float(z[j]), 1)}
                   for j in np.argsort(-np.abs(z))[:3]]
            alerts.append({"index": i, "score": float(scores[i]),
                           "severity": severity(scores[i], thr), "top_features": top})
            seen.add(key)
    if alerts:
        ips = keys["src_ip"].tolist()
        db.insert_alerts(alerts, X, meta["version"], src_ips=ips, path=DB_SSH)
        for a in alerts:
            k = keys.iloc[a["index"]]
            print(f"ALERTE {a['severity'].upper():6} ip={k['src_ip']} fenêtre={k['window_start']} "
                  f"score={a['score']:.3f} (seuil {thr:.3f}) top={a['top_features'][0]['feature']}")
    return len(alerts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/log/auth.log")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--since", default=None)
    a = ap.parse_args()
    model, meta, mu, sd = load_detector()
    since = pd.Timestamp(a.since) if a.since else (pd.Timestamp(datetime.now()) if a.follow else None)
    seen = set()
    print(f"Détecteur SSH {meta['version']} : seuil {meta['threshold']}, fenêtre {meta['window_seconds']} s, base {DB_SSH}")
    if a.once or not a.follow:
        n = scan(a.log, model, meta, mu, sd, seen, since)
        print(f"{n} alerte(s)")
    else:
        while True:
            scan(a.log, model, meta, mu, sd, seen, since)
            time.sleep(5)
