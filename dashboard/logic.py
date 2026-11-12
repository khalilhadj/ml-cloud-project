"""Logique du tableau de bord (testable, sans Streamlit)."""
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import db  # noqa: E402
from alerts import generate_alerts  # noqa: E402
from score import load_config, load_version, score_matrix  # noqa: E402


def demo_inject(n=30, attack_ratio=0.7, seed=None, db_path=None, cfg=None):
    """FR-23 : score n événements de la VALIDATION et enregistre les alertes. Retourne un résumé."""
    cfg = cfg or load_config()
    model, pre, meta, _ = load_version(cfg)
    names = list(pre.get_feature_names_out())
    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    X, y = data["X_val"], data["y_val"]
    rng = np.random.default_rng(seed)
    n_att = int(round(n * attack_ratio))
    idx = np.concatenate([
        rng.choice(np.where(y == 1)[0], n_att, replace=False),
        rng.choice(np.where(y == 0)[0], n - n_att, replace=False)])
    Xs = X[idx]
    alerts = generate_alerts(Xs, score_matrix(model, Xs), cfg, names)
    ids = db.insert_alerts(alerts, Xs, meta["version"], path=db_path)
    n_true = sum(int(y[idx[a["index"]]]) for a in alerts)
    return {"events": n, "alerts": len(alerts), "ids": ids, "model": meta["version"],
            "true_attacks_among_alerts": n_true}


def pending_rows(limit=100, severity=None, db_path=None):
    """Lignes affichables des alertes en attente."""
    rows = []
    for a in db.list_pending(limit=limit, severity=severity, path=db_path):
        rows.append({
            "id": a["id"], "créée": a["created_at"], "sévérité": a["severity"],
            "score": round(a["score"], 3), "ip": a["src_ip"] or "-",
            "variables déviantes": ", ".join(f"{n} ({d}σ)" for n, d in a["top_features"]),
            "modèle": a["model_version"]})
    return rows


def qualify(alert_id, verdict, analyst, comment="", db_path=None):
    db.add_feedback(alert_id, verdict, analyst, comment, path=db_path)


def metrics(db_path=None):
    """FR-22 : décomptes, taux de faux positifs mesuré, précision mesurée."""
    return db.stats(path=db_path)


def score_history(db_path=None):
    """FR-21 : scores des alertes dans l'ordre chronologique."""
    with db.connect(db_path) as con:
        rows = con.execute("SELECT id, created_at, score, severity, status FROM alerts ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def feedback_count_ready(db_path=None, cfg=None):
    """Nombre de faux positifs prêts pour le réentraînement et minimum requis."""
    cfg = cfg or load_config()
    return len(db.false_positives_for_retraining(path=db_path)), cfg["retrain"]["min_feedback"]


# ---------------------------------------------------------------- tableau de bord avancé
import csv  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402

from score import active_version_dir  # noqa: E402

SEVERITIES = ("élevée", "moyenne", "faible")
STATUSES = ("en_attente", "vrai_positif", "faux_positif")


def _row(r):
    d = dict(r)
    d["top_features"] = json.loads(d["top_features"])
    d["features"] = json.loads(d["features"])
    return d


def _display(a):
    return {
        "id": a["id"], "créée": a["created_at"], "sévérité": a["severity"],
        "score": round(a["score"], 3), "ip": a["src_ip"] or "-", "statut": a["status"],
        "variables déviantes": ", ".join(f"{n} ({d}σ)" for n, d in a["top_features"]),
        "modèle": a["model_version"]}


def all_alerts(status=None, severity=None, limit=500, db_path=None):
    """Alertes de tous statuts, les plus anormales d'abord, prêtes à afficher."""
    q, args = "SELECT * FROM alerts WHERE 1=1", []
    if status:
        q += " AND status = ?"
        args.append(status)
    if severity:
        q += " AND severity = ?"
        args.append(severity)
    q += " ORDER BY score DESC LIMIT ?"
    args.append(limit)
    with db.connect(db_path) as con:
        return [_display(_row(r)) for r in con.execute(q, args)]


def severity_counts(db_path=None):
    out = {s: 0 for s in SEVERITIES}
    with db.connect(db_path) as con:
        for r in con.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"):
            out[r["severity"]] = r["n"]
    return out


def status_counts(db_path=None):
    out = {s: 0 for s in STATUSES}
    with db.connect(db_path) as con:
        for r in con.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"):
            out[r["status"]] = r["n"]
    return out


def alert_detail(alert_id, db_path=None):
    """Fiche complète d'une alerte avec son feedback éventuel (ou None si inconnue)."""
    a = db.get_alert(int(alert_id), path=db_path)
    if a is None:
        return None
    with db.connect(db_path) as con:
        f = con.execute("SELECT verdict, comment, analyst, created_at FROM feedback WHERE alert_id = ?",
                        (int(alert_id),)).fetchone()
    a["feedback"] = dict(f) if f else None
    return a


def bulk_qualify(ids, verdict, analyst, comment="", db_path=None):
    """Qualifie plusieurs alertes d'un coup. Retourne le nombre traité."""
    n = 0
    for i in ids:
        db.add_feedback(int(i), verdict, analyst, comment, path=db_path)
        n += 1
    return n


def feedback_table(limit=200, db_path=None):
    """Journal des décisions de l'analyste (FR-18)."""
    with db.connect(db_path) as con:
        rows = con.execute(
            "SELECT f.alert_id, f.verdict, f.comment, f.analyst, f.created_at, f.used_in_model,"
            " a.score, a.severity FROM feedback f JOIN alerts a ON a.id = f.alert_id"
            " ORDER BY f.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def model_info(cfg=None):
    """Version active, seuils, métriques et versions disponibles."""
    cfg = cfg or load_config()
    models_dir = ROOT / cfg["paths"]["models"]
    vdir = active_version_dir(models_dir)
    meta = json.loads((vdir / "metadata.json").read_text(encoding="utf-8"))
    versions = sorted(p.name for p in models_dir.glob("v*") if (p / "model.joblib").exists())
    return {"active": vdir.name, "version": meta.get("version"), "created_at": meta.get("created_at"),
            "threshold": cfg["detection"]["threshold"], "severity": cfg["detection"]["severity"],
            "metrics": meta.get("metrics", {}), "versions": versions,
            "train_samples": meta.get("train_samples"), "n_features": meta.get("n_features")}


def cloud_status():
    import storage
    bucket = storage.bucket_name()
    return {"S3 (logs et modèles)": bucket or "non configuré",
            "Chiffrement": "KMS (alias/aws/s3)" if bucket else "-",
            "SNS (alertes)": "configuré" if os.environ.get("SNS_TOPIC_ARN", "").strip() else "non configuré"}


def retrain_history(limit=20, path=None):
    """Derniers cycles du planificateur, le plus récent d'abord."""
    p = path or (ROOT / load_config()["paths"]["processed"] / "retrain_history.jsonl")
    p = Path(p)
    if not p.exists():
        return []
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in reversed(lines)][:limit]


def run_retrain_now(db_path=None, apply_config=True):
    """Lance un cycle de réentraînement (même règle que le planificateur) et le trace dans l'historique."""
    import retrain
    import scheduler
    from datetime import datetime, timezone
    cfg = load_config()
    rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "status": "error",
           "old_version": None, "new_version": None, "n_feedback": None, "reason": None, "error": None}
    try:
        result = retrain.run_cycle(cfg, db_path=db_path, apply_config=apply_config)
        rec.update(status=result.get("status", "unknown"), old_version=result.get("old_version"),
                   new_version=result.get("new_version"), n_feedback=result.get("n_feedback"),
                   reason=result.get("reason"))
        return result
    except Exception as e:
        rec["error"] = str(e)
        raise
    finally:
        if db_path is None:   # pas de trace pour les tests, qui utilisent une base temporaire
            hist = scheduler.history_path(cfg)
            hist.parent.mkdir(parents=True, exist_ok=True)
            with open(hist, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def to_csv(rows):
    if not rows:
        return ""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def reset_db(db_path=None):
    """Supprime toutes les alertes et tous les feedbacks. Retourne le nombre d'alertes supprimées."""
    with db.connect(db_path) as con:
        n = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        con.execute("DELETE FROM feedback")
        con.execute("DELETE FROM alerts")
    return n
