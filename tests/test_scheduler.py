"""Test de l'étape 8b. Usage : python tests/test_scheduler.py"""
import json
import logging
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import retrain  # noqa: E402
import scheduler  # noqa: E402
from score import load_config  # noqa: E402

logging.disable(logging.CRITICAL)   # le test provoque des erreurs voulues : pas de traceback à l'écran
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


cfg = load_config()

print("== 1. Intervalles ==")
check("weekly = 604800 s", scheduler.interval_seconds("weekly") == 604800)
check("daily = 86400 s", scheduler.interval_seconds("daily") == 86400)
check("hourly = 3600 s", scheduler.interval_seconds("hourly") == 3600)
try:
    scheduler.interval_seconds("monthly")
    check("planification inconnue rejetée", False)
except ValueError:
    check("planification inconnue rejetée", True)

print("== 2. Un cycle ==")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    hist = tmp / "sub" / "history.jsonl"

    rec = scheduler.run_job(cfg, job=lambda c: {"status": "skipped", "n_feedback": 3,
                                                 "reason": "3 faux positifs"}, history=hist)
    check("cycle ignoré : statut et compteur conservés", rec["status"] == "skipped" and rec["n_feedback"] == 3)
    lines = hist.read_text(encoding="utf-8").splitlines()
    check("1 ligne JSON dans l'historique (dossier créé)", len(lines) == 1 and json.loads(lines[0])["status"] == "skipped")

    def boom(c):
        raise RuntimeError("boom")

    rec = scheduler.run_job(cfg, job=boom, history=hist)
    check("erreur : pas d'exception, status = error", rec["status"] == "error")
    check("message d'erreur conservé", "boom" in (rec["error"] or ""))
    check("l'erreur est aussi dans l'historique", len(hist.read_text(encoding="utf-8").splitlines()) == 3 - 1)

    rec = scheduler.run_job(cfg, job=lambda c: {"status": "promoted", "old_version": "v002",
                                                 "new_version": "v003", "n_feedback": 25}, history=None)
    check("cycle promu : versions enregistrées",
          rec["status"] == "promoted" and rec["old_version"] == "v002" and rec["new_version"] == "v003")

    print("== 3. Boucle ==")
    sleeps, calls = [], []
    n = scheduler.loop(100, cfg=cfg, job=lambda c: calls.append(1) or {"status": "skipped"},
                       history=None, sleep=sleeps.append, max_runs=3)
    check("3 cycles exécutés", n == 3)
    check("attente de 100 s avant chaque cycle", sleeps == [100, 100, 100], str(sleeps))
    check("le job est appelé 3 fois", len(calls) == 3)

    state = {"n": 0}

    def flaky(c):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("panne")
        return {"status": "skipped"}

    n = scheduler.loop(1, cfg=cfg, job=flaky, history=None, sleep=lambda s: None, max_runs=2)
    check("la boucle continue après une erreur", n == 2 and state["n"] == 2)

    print("== 4. Configuration et vrai cycle ==")
    check("config.yaml : retrain.schedule = weekly", cfg["retrain"]["schedule"] == "weekly",
          str(cfg["retrain"]["schedule"]))
    check("intervalle réel = 7 jours", scheduler.interval_seconds(cfg["retrain"]["schedule"]) == 604800)

    from db import false_positives_for_retraining  # noqa: E402,F401
    dbp = tmp / "empty.db"
    rec = scheduler.run_job(cfg, job=lambda c: retrain.run_cycle(c, db_path=dbp, apply_config=False), history=None)
    check("vrai run_cycle sur base vide -> skipped, 0 feedback",
          rec["status"] == "skipped" and rec["n_feedback"] == 0, f"{rec['status']}, {rec['n_feedback']}")

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
