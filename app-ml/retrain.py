"""Réentraînement : faux positifs validés -> données normales, comparaison, promotion (FR-19, FR-20)."""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.append(str(Path(__file__).resolve().parent))
import db  # noqa: E402
from evaluate import best_threshold, metrics_at, write_threshold  # noqa: E402
from score import ROOT, load_config, load_version, score_matrix  # noqa: E402
from train import save_version, train_model  # noqa: E402

logger = logging.getLogger(__name__)


def decide(old, new):
    """FR-20 : F1 au moins égal ET taux de faux positifs strictement inférieur."""
    return new["f1"] >= old["f1"] and new["false_positive_rate"] < old["false_positive_rate"]


def validation_metrics(model, X_val, y_val):
    """Métriques sur la validation au seuil optimal du modèle."""
    s = score_matrix(model, X_val)
    thr, _ = best_threshold(y_val, s)
    m = metrics_at(y_val, s, thr)
    m["threshold"] = round(thr, 6)
    return m


def run_cycle(cfg=None, db_path=None, apply_config=True):
    cfg = cfg or load_config()
    min_fb = cfg["retrain"]["min_feedback"]
    fps = db.false_positives_for_retraining(path=db_path)
    if len(fps) < min_fb:
        return {"status": "skipped", "n_feedback": len(fps),
                "reason": f"{len(fps)} faux positifs disponibles, minimum {min_fb}"}

    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    X_train, X_val, y_val = data["X_train"], data["X_val"], data["y_val"]
    old_model, pre, old_meta, _ = load_version(cfg)

    X_fp = np.array([f["features"] for f in fps], dtype=np.float32)
    if X_fp.shape[1] != X_train.shape[1]:
        raise ValueError(f"{X_fp.shape[1]} variables dans la base, {X_train.shape[1]} attendues")
    X_new = np.vstack([X_train, X_fp])
    logger.info("Réentraînement sur %d événements (%d faux positifs ajoutés)", len(X_new), len(fps))

    new_model = train_model(X_new, cfg)
    new_dir = save_version(new_model, pre, cfg, X_new, extra={
        "retrained": True, "parent_version": old_meta["version"], "feedback_samples": len(fps)})

    old_m = validation_metrics(old_model, X_val, y_val)
    new_m = validation_metrics(new_model, X_val, y_val)
    promoted = decide(old_m, new_m)

    meta = json.loads((new_dir / "metadata.json").read_text(encoding="utf-8"))
    meta["metrics"] = {"threshold": new_m["threshold"], "validation": new_m}
    meta["decision"] = {
        "promoted": promoted, "compared_to": old_meta["version"],
        "old_validation": old_m, "new_validation": new_m,
        "decided_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (new_dir / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    if promoted:
        (new_dir.parent / "active.txt").write_text(new_dir.name + "\n", encoding="utf-8")
        db.mark_feedback_used([f["feedback_id"] for f in fps], new_dir.name, path=db_path)
        if apply_config:
            from alerts import calibrate_severity, write_severity
            write_threshold(new_m["threshold"])
            med, high = calibrate_severity(score_matrix(new_model, X_val), new_m["threshold"])
            write_severity(med, high, new_m["threshold"])

    return {
        "status": "promoted" if promoted else "rejected", "promoted": promoted,
        "old_version": old_meta["version"], "new_version": new_dir.name,
        "active": new_dir.name if promoted else old_meta["version"],
        "n_feedback": len(fps), "old": old_m, "new": new_m,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    r = run_cycle()
    print(r["status"].upper(), "-", r.get("reason", ""))
    if "old" in r:
        for k in ("f1", "false_positive_rate", "recall"):
            print(f"  {k:<20} ancien={r['old'][k]:.4f}  nouveau={r['new'][k]:.4f}")
        print(f"  version active : {r['active']}")
