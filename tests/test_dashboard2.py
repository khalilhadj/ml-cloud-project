"""Test du tableau de bord avancé. Usage : python tests/test_dashboard2.py"""
import json
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
    tmp = Path(tmp)
    dbp = tmp / "t.db"

    check("sévérités à zéro sur base vide", logic.severity_counts(dbp) == {"élevée": 0, "moyenne": 0, "faible": 0})

    r = logic.demo_inject(n=60, attack_ratio=0.7, seed=3, db_path=dbp)
    n = r["alerts"]
    check("démo : au moins 3 alertes", n >= 3, str(n))
    check("somme des sévérités = nombre d'alertes", sum(logic.severity_counts(dbp).values()) == n)
    check("toutes en attente au départ", logic.status_counts(dbp)["en_attente"] == n)
    rows = logic.all_alerts(db_path=dbp)
    check("all_alerts retourne toutes les alertes", len(rows) == n)
    check("filtre par statut", len(logic.all_alerts(status="faux_positif", db_path=dbp)) == 0)

    ids = [x["id"] for x in rows]
    check("qualification en masse : 3 traitées", logic.bulk_qualify(ids[:3], "faux_positif", "khalil", "test", dbp) == 3)
    check("statuts mis à jour", logic.status_counts(dbp)["faux_positif"] == 3)
    check("filtre faux_positif : 3 lignes", len(logic.all_alerts(status="faux_positif", db_path=dbp)) == 3)

    d = logic.alert_detail(ids[0], dbp)
    check("fiche : variables, vecteur et décision",
          d["top_features"] and len(d["features"]) == 77 and d["feedback"]["verdict"] == "faux_positif"
          and d["feedback"]["analyst"] == "khalil")
    check("fiche d'une alerte non qualifiée : pas de feedback", logic.alert_detail(ids[5], dbp)["feedback"] is None)
    check("fiche d'une alerte inconnue : None", logic.alert_detail(10**9, dbp) is None)
    try:
        logic.bulk_qualify([ids[5]], "faux_positif", "", db_path=dbp)
        check("analyste vide rejeté", False)
    except ValueError:
        check("analyste vide rejeté", True)
    check("liste vide : 0 traitée", logic.bulk_qualify([], "faux_positif", "khalil", db_path=dbp) == 0)
    check("journal des décisions : 3 lignes", len(logic.feedback_table(db_path=dbp)) == 3)

    info = logic.model_info()
    check("modèle actif : version, seuil, versions", info["version"] in info["versions"]
          and info["threshold"] is not None and info["active"] in info["versions"], info["active"])

    hist = tmp / "h.jsonl"
    check("historique absent : liste vide", logic.retrain_history(path=tmp / "nope.jsonl") == [])
    hist.write_text(json.dumps({"n": 1}) + "\n" + json.dumps({"n": 2}) + "\n")
    got = logic.retrain_history(path=hist)
    check("historique : le plus récent d'abord", len(got) == 2 and got[0]["n"] == 2)

    res = logic.run_retrain_now(db_path=tmp / "empty.db", apply_config=False)
    check("cycle sur base vide : skipped", res["status"] == "skipped", res["status"])

    csv_text = logic.to_csv(rows)
    check("export CSV : en-tête + une ligne par alerte", len(csv_text.strip().splitlines()) == n + 1)
    check("remise à zéro", logic.reset_db(dbp) == n and sum(logic.status_counts(dbp).values()) == 0)

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
