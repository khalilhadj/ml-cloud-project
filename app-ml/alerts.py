"""Alertes : seuil, sévérité calibrée, explication."""
import re
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.append(str(Path(__file__).resolve().parent))
from explain import top_deviations  # noqa: E402
from score import ROOT, load_config, load_version, score_matrix  # noqa: E402


def calibrate_severity(scores_val, threshold):
    """Bandes de largeur égale entre le seuil et le 99e percentile des scores d'alertes (validation)."""
    a = scores_val[scores_val >= threshold]
    top = float(np.quantile(a, 0.99))
    step = (top - threshold) / 3
    return threshold + step, threshold + 2 * step


def write_severity(medium, high, threshold):
    p = ROOT / "config.yaml"
    t = p.read_text(encoding="utf-8")
    for key, val in (("low", threshold), ("medium", medium), ("high", high)):
        t = re.sub(rf"(^\s*{key}:).*$", rf"\g<1> {val:.6f}", t, count=1, flags=re.M)
    p.write_text(t, encoding="utf-8")


def severity_of(score, sev):
    if score >= sev["high"]:
        return "élevée"
    if score >= sev["medium"]:
        return "moyenne"
    return "faible"


def generate_alerts(X, scores, cfg, names, k=3):
    """Retourne la liste des alertes (dicts) pour les lignes dont score >= seuil."""
    thr = cfg["detection"]["threshold"]
    sev = cfg["detection"]["severity"]
    out = []
    for i in np.where(scores >= thr)[0]:
        out.append({
            "index": int(i),
            "score": float(scores[i]),
            "severity": severity_of(scores[i], sev),
            "top_features": top_deviations(X[i], names, k),
        })
    return out


SEVERITY_RANK = {"faible": 0, "moyenne": 1, "élevée": 2}


def attach_context(alerts, src_ips=None, timestamps=None):
    """Ajoute src_ip et timestamp à chaque alerte (indexés par alert['index'])."""
    for a in alerts:
        if src_ips is not None:
            a["src_ip"] = str(src_ips[a["index"]])
        if timestamps is not None:
            a["timestamp"] = timestamps[a["index"]]
    return alerts


def _merge(group):
    rep = dict(max(group, key=lambda a: a["score"]))
    rep["count"] = len(group)
    rep["indexes"] = [a["index"] for a in group]
    rep["first_seen"] = min(a["timestamp"] for a in group)
    rep["last_seen"] = max(a["timestamp"] for a in group)
    rep["severity"] = max((a["severity"] for a in group), key=SEVERITY_RANK.get)
    return rep


def group_by_ip(alerts, window_minutes):
    """FR-15 : regroupe les alertes d'une même IP séparées de <= window_minutes."""
    from datetime import timedelta
    window = timedelta(minutes=window_minutes)
    out, by_ip = [], {}
    for a in alerts:
        if not a.get("src_ip") or a.get("timestamp") is None:
            single = dict(a)
            single.update(count=1, indexes=[a["index"]])
            out.append(single)
        else:
            by_ip.setdefault(a["src_ip"], []).append(a)
    for items in by_ip.values():
        items.sort(key=lambda a: a["timestamp"])
        cur = [items[0]]
        for a in items[1:]:
            if a["timestamp"] - cur[-1]["timestamp"] <= window:
                cur.append(a)
            else:
                out.append(_merge(cur))
                cur = [a]
        out.append(_merge(cur))
    return sorted(out, key=lambda a: a["score"], reverse=True)


if __name__ == "__main__":
    cfg = load_config()
    model, pre, meta, vdir = load_version(cfg)
    names = list(pre.get_feature_names_out())
    data = np.load(ROOT / cfg["paths"]["processed"] / "datasets.npz")
    thr = cfg["detection"]["threshold"]

    if cfg["detection"]["severity"].get("medium") is None:
        s_val = score_matrix(model, data["X_val"])
        med, high = calibrate_severity(s_val, thr)
        write_severity(med, high, thr)
        cfg = load_config()
        print(f"Sévérité calibrée : faible >= {thr:.4f}, moyenne >= {med:.4f}, élevée >= {high:.4f}")

    X, y = data["X_test"], data["y_test"]
    scores = score_matrix(model, X)
    alerts = generate_alerts(X, scores, cfg, names)
    print(f"\n{len(alerts)} alertes sur {len(X)} événements du test (modèle {meta['version']})")
    for sev in ("élevée", "moyenne", "faible"):
        n = sum(a["severity"] == sev for a in alerts)
        print(f"  sévérité {sev:<8}: {n}")

    print("\nExemples (vrai label : 1 = attaque) :")
    for a in alerts[:8]:
        print(f"  #{a['index']:<6} score={a['score']:.3f} {a['severity']:<8} "
              f"vrai={y[a['index']]}  ->  "
              + ", ".join(f"{n} ({d}σ)" for n, d in a["top_features"]))
