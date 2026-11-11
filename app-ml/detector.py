"""Détecteur de force brute SSH (FR-23, ACC-2) : règle de seuil par IP et par minute.
Usage : python app-ml/detector.py --once --log <auth.log> [--min-failed 5] [--since "2026-11-10 19:00:00"] [--notify]
        python app-ml/detector.py --follow [--notify]      (boucle toutes les 5 s)"""
import argparse
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent))
import db  # noqa: E402
from features_logs import build_auth_features, load_auth_attempts  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DB_SSH = ROOT / "data" / "alerts_ssh.db"   # base séparée : ne pas mélanger avec les 77 variables NSL-KDD
RULE_VERSION = "ssh-rule-v1"


def severity(r):
    if r["n_accepted"] > 0:
        return "élevée"            # accès obtenu après échecs : compromission probable
    if r["n_distinct_users"] >= 2:
        return "élevée" if r["n_failed"] >= 20 else "moyenne"
    return "faible"


def scan(log_path, min_failed, seen, since=None, notify_on=False, db_path=DB_SSH):
    df, _ = load_auth_attempts(log_path)
    feats = build_auth_features(df)
    if feats.empty:
        return 0
    feats = feats.reset_index(drop=True)
    X = feats[["n_failed", "n_accepted", "n_distinct_users"]].to_numpy(dtype=float)
    ips = feats["src_ip"].astype(str).tolist()
    alerts = []
    for i, r in feats.iterrows():
        key = (r["src_ip"], str(r["minute"]))
        if r["n_failed"] < min_failed or key in seen:
            continue
        if since is not None and pd.Timestamp(r["minute"]) < since:
            continue
        seen.add(key)
        alerts.append({"index": int(i), "src_ip": str(r["src_ip"]),
                       "score": float(r["n_failed"]), "severity": severity(r),
                       "top_features": [["n_failed", float(r["n_failed"])],
                                        ["n_distinct_users", float(r["n_distinct_users"])],
                                        ["n_accepted", float(r["n_accepted"])]]})
    if not alerts:
        return 0
    ids = db.insert_alerts(alerts, X, RULE_VERSION, src_ips=ips, path=db_path)
    with db.connect(db_path) as con:   # horodatage affiché = minute de l'attaque, pas l'heure d'insertion
        for a, alert_id in zip(alerts, ids):
            ts = pd.Timestamp(feats.loc[a["index"], "minute"]).isoformat(timespec="seconds")
            con.execute("UPDATE alerts SET created_at=? WHERE id=?", (ts, alert_id))
    for a in alerts:
        r = feats.loc[a["index"]]
        print(f"ALERTE {a['severity'].upper():8} ip={r['src_ip']} minute={r['minute']} "
              f"echecs={int(r['n_failed'])} comptes={int(r['n_distinct_users'])} acceptes={int(r['n_accepted'])}")
    if notify_on:
        import notify
        print("Notification :", notify.notify(alerts, RULE_VERSION))
    return len(alerts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/log/auth.log")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--since", default=None)
    ap.add_argument("--min-failed", type=int, default=5)
    ap.add_argument("--notify", action="store_true")
    a = ap.parse_args()
    since = pd.Timestamp(a.since) if a.since else (pd.Timestamp.now() if a.follow else None)
    seen = set()
    print(f"Détecteur {RULE_VERSION} : seuil {a.min_failed} échecs/IP/minute, base {DB_SSH}")
    if a.once or not a.follow:
        print(f"{scan(a.log, a.min_failed, seen, since, a.notify)} alerte(s)")
    else:
        while True:
            scan(a.log, a.min_failed, seen, since, a.notify)
            time.sleep(5)

