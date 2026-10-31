"""Test de la logique du tableau de bord. Usage : python tests/test_dashboard.py"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))

import logic  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


with tempfile.TemporaryDirectory() as tmp:
    dbp = Path(tmp) / "t.db"
    check("base vide : aucune ligne", logic.pending_rows(db_path=dbp) == [])
    check("base vide : statistiques à zéro", logic.metrics(dbp)["total"] == 0 and logic.metrics(dbp)["taux_faux_positifs"] is None)

    r = logic.demo_inject(n=40, attack_ratio=0.75, seed=1, db_path=dbp)
    check("démo : alertes créées", r["alerts"] > 0 and len(r["ids"]) == r["alerts"], f"{r['alerts']} alertes / 40")
    check("démo : majorité de vraies attaques", r["true_attacks_among_alerts"] > r["alerts"] / 2,
          f"{r['true_attacks_among_alerts']}/{r['alerts']}")
    r2 = logic.demo_inject(n=40, attack_ratio=0.75, seed=1, db_path=Path(tmp) / "t2.db")
    check("démo reproductible (même graine)", r2["alerts"] == r["alerts"] and r2["true_attacks_among_alerts"] == r["true_attacks_among_alerts"])

    rows = logic.pending_rows(limit=1000, db_path=dbp)
    check("toutes les alertes sont en attente", len(rows) == r["alerts"])
    check("triées par score décroissant", all(rows[i]["score"] >= rows[i + 1]["score"] for i in range(len(rows) - 1)))
    check("variables déviantes affichées", all("σ" in x["variables déviantes"] for x in rows))
    sev = rows[0]["sévérité"]
    check("filtre par sévérité", all(x["sévérité"] == sev for x in logic.pending_rows(severity=sev, db_path=dbp)))

    logic.qualify(rows[0]["id"], "vrai_positif", "khalil", "scan", dbp)
    logic.qualify(rows[1]["id"], "faux_positif", "khalil", "", dbp)
    m = logic.metrics(dbp)
    check("métriques après feedback", m["vrai_positif"] == 1 and m["faux_positif"] == 1 and m["taux_faux_positifs"] == 0.5, str(m))
    check("alertes qualifiées retirées de la liste", len(logic.pending_rows(limit=1000, db_path=dbp)) == r["alerts"] - 2)
    check("historique des scores complet", len(logic.score_history(dbp)) == r["alerts"])
    ready, needed = logic.feedback_count_ready(dbp)
    check("faux positifs prêts : 1 sur le minimum de la config", ready == 1 and needed == 20, f"{ready}/{needed}")

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
