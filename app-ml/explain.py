"""Explication déterministe : variables les plus déviantes d'un événement (NFR-06)."""
import numpy as np


def _base_name(feature_name):
    """'num__count' -> 'count' ; 'cat__service_http' -> 'service'."""
    n = feature_name.split("__", 1)[-1]
    for cat in ("protocol_type", "service", "flag"):
        if n.startswith(cat + "_"):
            return cat
    return n


def top_deviations(x_row, names, k=3):
    """Retourne les k variables les plus déviantes [(nom, écart_en_sigma)].

    Numériques : |valeur normalisée| (nombre d'écarts-types par rapport au normal).
    Catégorielles : une catégorie jamais vue en normal (toutes les colonnes à 0)
    est signalée avec un écart fixe de 5.
    """
    devs = {}
    cat_sum = {}
    for name, v in zip(names, x_row):
        base = _base_name(name)
        if name.startswith("num__"):
            devs[base] = abs(float(v))
        else:
            cat_sum[base] = cat_sum.get(base, 0.0) + float(v)
    for base, s in cat_sum.items():
        devs[base] = 0.0 if s > 0 else 5.0
    ranked = sorted(devs.items(), key=lambda kv: kv[1], reverse=True)[:k]
    return [(n, round(d, 2)) for n, d in ranked]


def explain_text(x_row, names, k=3):
    return ", ".join(f"{n} ({d} σ)" for n, d in top_deviations(x_row, names, k))
