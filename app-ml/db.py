"""Base SQLite : historique des alertes et feedback analyste (FR-14, FR-16 à FR-18)."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERDICTS = ("vrai_positif", "faux_positif")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT    NOT NULL,
    event_index   INTEGER,
    src_ip        TEXT,
    score         REAL    NOT NULL,
    severity      TEXT    NOT NULL,
    top_features  TEXT    NOT NULL,
    features      TEXT    NOT NULL,
    model_version TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'en_attente'
        CHECK (status IN ('en_attente', 'vrai_positif', 'faux_positif'))
);
CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL UNIQUE REFERENCES alerts(id),
    verdict       TEXT    NOT NULL CHECK (verdict IN ('vrai_positif', 'faux_positif')),
    comment       TEXT,
    analyst       TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    used_in_model TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path(path=None):
    if path:
        return Path(path)
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return ROOT / cfg["paths"]["database"]


@contextmanager
def connect(path=None):
    """Ouvre la base (créée si besoin), valide la transaction et ferme à la sortie."""
    p = db_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(SCHEMA)
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def insert_alerts(alerts, X, model_version, src_ips=None, path=None):
    """Enregistre les alertes produites par alerts.generate_alerts. Retourne les identifiants."""
    ids = []
    with connect(path) as con:
        for a in alerts:
            i = a["index"]
            cur = con.execute(
                "INSERT INTO alerts (created_at, event_index, src_ip, score, severity,"
                " top_features, features, model_version) VALUES (?,?,?,?,?,?,?,?)",
                (_now(), i, None if src_ips is None else str(src_ips[i]),
                 a["score"], a["severity"],
                 json.dumps(a["top_features"], ensure_ascii=False),
                 json.dumps([round(float(v), 6) for v in X[i]]),
                 model_version),
            )
            ids.append(cur.lastrowid)
    return ids


def _alert_dict(row):
    d = dict(row)
    d["top_features"] = json.loads(d["top_features"])
    d["features"] = json.loads(d["features"])
    return d


def list_pending(limit=50, severity=None, path=None):
    """FR-16 : alertes en attente, les plus anormales d'abord."""
    q = "SELECT * FROM alerts WHERE status = 'en_attente'"
    args = []
    if severity:
        q += " AND severity = ?"
        args.append(severity)
    q += " ORDER BY score DESC LIMIT ?"
    args.append(limit)
    with connect(path) as con:
        return [_alert_dict(r) for r in con.execute(q, args)]


def get_alert(alert_id, path=None):
    with connect(path) as con:
        r = con.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _alert_dict(r) if r else None


def add_feedback(alert_id, verdict, analyst, comment="", path=None):
    """FR-17, FR-18 : qualifie une alerte. Une nouvelle décision remplace l'ancienne."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict invalide : {verdict!r} (attendu : {VERDICTS})")
    if not analyst or not analyst.strip():
        raise ValueError("l'identité de l'analyste est obligatoire")
    with connect(path) as con:
        if con.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise ValueError(f"alerte {alert_id} introuvable")
        con.execute(
            "INSERT INTO feedback (alert_id, verdict, comment, analyst, created_at)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(alert_id) DO UPDATE SET verdict=excluded.verdict,"
            " comment=excluded.comment, analyst=excluded.analyst,"
            " created_at=excluded.created_at, used_in_model=NULL",
            (alert_id, verdict, comment, analyst.strip(), _now()),
        )
        con.execute("UPDATE alerts SET status = ? WHERE id = ?", (verdict, alert_id))


def false_positives_for_retraining(path=None):
    """FR-19 : faux positifs validés pas encore utilisés par un réentraînement."""
    with connect(path) as con:
        rows = con.execute(
            "SELECT f.id AS feedback_id, a.* FROM feedback f JOIN alerts a ON a.id = f.alert_id"
            " WHERE f.verdict = 'faux_positif' AND f.used_in_model IS NULL ORDER BY a.id"
        ).fetchall()
    return [_alert_dict(r) for r in rows]


def mark_feedback_used(feedback_ids, model_version, path=None):
    with connect(path) as con:
        con.executemany("UPDATE feedback SET used_in_model = ? WHERE id = ?",
                        [(model_version, i) for i in feedback_ids])


def stats(path=None):
    """FR-22 : décompte par statut et taux de faux positifs mesuré par le feedback."""
    with connect(path) as con:
        counts = {r["status"]: r["n"] for r in
                  con.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")}
    tp, fp = counts.get("vrai_positif", 0), counts.get("faux_positif", 0)
    qualified = tp + fp
    return {
        "total": sum(counts.values()),
        "en_attente": counts.get("en_attente", 0),
        "vrai_positif": tp,
        "faux_positif": fp,
        "taux_faux_positifs": round(fp / qualified, 4) if qualified else None,
        "precision_mesuree": round(tp / qualified, 4) if qualified else None,
    }


def _self_test():
    import sys
    import tempfile
    import numpy as np

    sys.path.append(str(Path(__file__).resolve().parent))
    from alerts import generate_alerts
    from score import load_config, load_version, score_matrix

    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))

    cfg = load_config()
    model, pre, meta, _ = load_version(cfg)
    names = list(pre.get_feature_names_out())
    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    X = data["X_test"][:300]
    alerts = generate_alerts(X, score_matrix(model, X), cfg, names)

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "test_alerts.db"
        print(f"Base de test temporaire (la vraie base n'est pas touchée) : {p}")

        ids = insert_alerts(alerts, X, meta["version"], path=p)
        check("insertion des alertes", len(ids) == len(alerts) > 0, f"{len(ids)} alertes")

        pend = list_pending(limit=1000, path=p)
        check("toutes en attente au départ", len(pend) == len(ids))
        check("tri par score décroissant",
              all(pend[i]["score"] >= pend[i + 1]["score"] for i in range(len(pend) - 1)))
        a = get_alert(ids[0], path=p)
        check("FR-14 : score, sévérité, variables, version",
              a["severity"] and a["top_features"] and len(a["features"]) == X.shape[1]
              and a["model_version"] == meta["version"], a["model_version"])

        add_feedback(ids[0], "faux_positif", "khalil", "trafic légitime", path=p)
        add_feedback(ids[1], "vrai_positif", "khalil", path=p)
        add_feedback(ids[2], "vrai_positif", "khalil", path=p)
        add_feedback(ids[2], "faux_positif", "khalil", "corrigé", path=p)
        check("FR-16 : la liste d'attente diminue",
              len(list_pending(limit=1000, path=p)) == len(ids) - 3)
        check("FR-17 : statut mis à jour", get_alert(ids[0], path=p)["status"] == "faux_positif")
        check("une décision remplace la précédente",
              get_alert(ids[2], path=p)["status"] == "faux_positif")

        for bad, label in [(lambda: add_feedback(ids[3], "peut-etre", "khalil", path=p), "verdict invalide"),
                           (lambda: add_feedback(ids[3], "faux_positif", "", path=p), "analyste vide"),
                           (lambda: add_feedback(10**9, "faux_positif", "khalil", path=p), "alerte inconnue")]:
            try:
                bad()
                check(f"rejet : {label}", False)
            except ValueError:
                check(f"rejet : {label}", True)

        fps = false_positives_for_retraining(path=p)
        check("FR-19 : 2 faux positifs à réutiliser", len(fps) == 2, str(len(fps)))
        mark_feedback_used([f["feedback_id"] for f in fps], "v003", path=p)
        check("faux positifs marqués comme utilisés", len(false_positives_for_retraining(path=p)) == 0)

        s = stats(path=p)
        check("FR-22 : statistiques", s["faux_positif"] == 2 and s["vrai_positif"] == 1
              and s["taux_faux_positifs"] == round(2 / 3, 4), str(s))

    print(f"\nRésultat : {sum(results)}/{len(results)} OK")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    _self_test()
