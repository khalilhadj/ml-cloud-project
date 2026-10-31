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
