"""Réglage du seuil sur la validation, évaluation finale sur le test (ACC-3)."""
import json
import re
from pathlib import Path

import numpy as np
from sklearn.metrics import (confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)

from score import load_config, load_version, score_matrix

ROOT = Path(__file__).resolve().parents[1]
KEYS = ["X_val", "y_val", "X_test", "y_test"]


def best_threshold(y_true, scores):
    """Seuil qui maximise le F1 (calculé sur la validation uniquement)."""
    prec, rec, thr = precision_recall_curve(y_true, scores)
    f1 = 2 * prec[:-1] * rec[:-1] / np.clip(prec[:-1] + rec[:-1], 1e-12, None)
    i = int(np.argmax(f1))
    return float(thr[i]), float(f1[i])


def metrics_at(y_true, scores, threshold):
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "f1": round(float(f1_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred)), 4),
        "recall": round(float(recall_score(y_true, y_pred)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4),
        "auc": round(float(roc_auc_score(y_true, scores)), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def write_threshold(thr):
    """Remplace seulement la valeur de detection.threshold, sans toucher au reste du fichier."""
    path = ROOT / "config.yaml"
    txt = path.read_text(encoding="utf-8")
    new, n = re.subn(r"(^\s*threshold:\s*)\S+", rf"\g<1>{thr:.6f}", txt, count=1, flags=re.M)
    if n == 0:
        raise SystemExit("Clé 'threshold' introuvable dans config.yaml")
    path.write_text(new, encoding="utf-8")


def main():
    cfg = load_config()
    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    missing = [k for k in KEYS if k not in data.files]
    if missing:
        raise SystemExit(f"Clés absentes de datasets.npz : {missing} (présentes : {data.files})")

    model, _, meta, vdir = load_version(cfg)
    s_val = score_matrix(model, data["X_val"])
    s_test = score_matrix(model, data["X_test"])

    thr, f1_val_best = best_threshold(data["y_val"], s_val)
    m_val = metrics_at(data["y_val"], s_val, thr)
    m_test = metrics_at(data["y_test"], s_test, thr)

    print(f"Modèle évalué : {meta['version']}")
    print(f"Seuil choisi sur la validation : {thr:.4f} (F1 val = {f1_val_best:.4f})")
    print("VALIDATION :", m_val)
    print("TEST       :", m_test)
    print(f"ACC-3 (F1 test >= 0,80) : {'OK' if m_test['f1'] >= 0.80 else 'NON ATTEINT'}")

    write_threshold(thr)                                            # FR-11, UC-4
    meta["metrics"] = {"threshold": round(thr, 6), "validation": m_val, "test": m_test}
    with open(vdir / "metadata.json", "w", encoding="utf-8") as f:   # FR-08
        json.dump(meta, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
