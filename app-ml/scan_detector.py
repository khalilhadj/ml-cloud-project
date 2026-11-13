"""Détecteur de scan de ports en continu (FR-23, ACC-1) : règle de seuil sur les logs UFW.
Usage : python app-ml/scan_detector.py --once --log <ufw.log> [--min-ports 20] [--since "..."] [--notify]
        python app-ml/scan_detector.py --follow [--notify]      (boucle toutes les 5 s)"""
import argparse
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent))
import db  # noqa: E402
from features_logs import build_ufw_features, load_ufw_blocks  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DB_SCAN = ROOT / "data" / "alerts_scan.db"   # base séparée : ne mélange pas avec SSH ni NSL-KDD
RULE_VERSION = "scan-rule-v1"


def severity(n_dports):
    if n_dports >= 200:
        return "élevée"
    if n_dports >= 50:
        return "moyenne"
    return "faible"


def scan(log_path, min_ports, seen, since=None, notify_on=False, db_path=DB_SCAN):
    df, _ = load_ufw_blocks(log_path)
    feats = build_ufw_features(df)
    if feats.empty:
        return 0
    feats = feats.reset_index(drop=True)
    X = feats[["n_dports", "n_blocked"]].to_numpy(dtype=float)
    ips = feats["src_ip"].astype(str).tolist()
    alerts = []
    for i, r in feats.iterrows():
        key = (r["src_ip"], str(r["minute"]))
        if r["n_dports"] < min_ports or key in seen:
            continue
        if since is not None and pd.Timestamp(r["minute"]) < since:
            continue
        seen.add(key)
        alerts.append({"index": int(i), "src_ip": str(r["src_ip"]),
                       "score": float(r["n_dports"]), "severity": severity(r["n_dports"]),
                       "top_features": [["ports_distincts", float(r["n_dports"])],
                                        ["paquets_bloques", float(r["n_blocked"])]]})
    if not alerts:
        return 0
    ids = db.insert_alerts(alerts, X, RULE_VERSION, src_ips=ips, path=db_path)
    with db.connect(db_path) as con:
        for a, alert_id in zip(alerts, ids):
            ts = pd.Timestamp(feats.loc[a["index"], "minute"]).isoformat(timespec="seconds")
            con.execute("UPDATE alerts SET created_at=? WHERE id=?", (ts, alert_id))
    for a in alerts:
        r = feats.loc[a["index"]]
        print(f"ALERTE SCAN {a['severity'].upper():8} ip={r['src_ip']} minute={r['minute']} "
              f"ports_distincts={int(r['n_dports'])} blocages={int(r['n_blocked'])}")
    if notify_on:
        import notify
        print("Notification :", notify.notify(alerts, RULE_VERSION))
    return len(alerts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/log/ufw.log")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--since", default=None)
    ap.add_argument("--min-ports", type=int, default=20)
    ap.add_argument("--notify", action="store_true")
    a = ap.parse_args()
    since = pd.Timestamp(a.since) if a.since else (pd.Timestamp.now() if a.follow else None)
    seen = set()
    print(f"Détecteur {RULE_VERSION} : seuil {a.min_ports} ports/IP/minute, base {DB_SCAN}")
    if a.once or not a.follow:
        print(f"{scan(a.log, a.min_ports, seen, since, a.notify)} alerte(s)")
    else:
        while True:
            scan(a.log, a.min_ports, seen, since, a.notify)
            time.sleep(5)
