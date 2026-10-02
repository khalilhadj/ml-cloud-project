"""Planificateur : réentraînement périodique (UC-3). Usage : python app-ml/scheduler.py [--once]"""
import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
import retrain  # noqa: E402
from score import ROOT, load_config  # noqa: E402

logger = logging.getLogger(__name__)
INTERVALS = {"hourly": 3600, "daily": 86400, "weekly": 7 * 86400}


def interval_seconds(schedule):
    if schedule not in INTERVALS:
        raise ValueError(f"planification inconnue : {schedule!r} (attendu : {list(INTERVALS)})")
    return INTERVALS[schedule]


def history_path(cfg):
    return ROOT / cfg["paths"]["processed"] / "retrain_history.jsonl"


def run_job(cfg=None, job=None, history=None):
    """Exécute un cycle. Ne lève jamais d'exception : une erreur devient status='error'."""
    cfg = cfg or load_config()
    job = job or retrain.run_cycle
    rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "status": "error",
           "old_version": None, "new_version": None, "n_feedback": None, "reason": None, "error": None}
    try:
        r = job(cfg)
        rec.update(status=r.get("status", "unknown"), old_version=r.get("old_version"),
                   new_version=r.get("new_version"), n_feedback=r.get("n_feedback"),
                   reason=r.get("reason"))
    except Exception as e:
        logger.exception("Échec du cycle de réentraînement (le planificateur continue)")
        rec["error"] = str(e)
    logger.info("Cycle de réentraînement : %s", rec["status"])
    if history:
        history = Path(history)
        history.parent.mkdir(parents=True, exist_ok=True)
        with open(history, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def loop(interval, cfg=None, job=None, history=None, sleep=time.sleep, max_runs=None):
    """Attend `interval` secondes puis lance un cycle, en boucle. Retourne le nombre de cycles."""
    runs = 0
    while max_runs is None or runs < max_runs:
        sleep(interval)
        run_job(cfg, job, history)
        runs += 1
    return runs


def main(argv=None):
    ap = argparse.ArgumentParser(description="Planificateur de réentraînement")
    ap.add_argument("--once", action="store_true", help="un seul cycle puis arrêt (pour cron)")
    ap.add_argument("--interval-seconds", type=int, help="remplace retrain.schedule (tests)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = load_config()
    hist = history_path(cfg)
    if args.once:
        rec = run_job(cfg, history=hist)
        print(json.dumps(rec, ensure_ascii=False))
        return 1 if rec["status"] == "error" else 0

    interval = args.interval_seconds or interval_seconds(cfg["retrain"]["schedule"])
    logger.info("Planificateur démarré : un cycle toutes les %d s", interval)
    try:
        loop(interval, history=hist)
    except KeyboardInterrupt:
        logger.info("Arrêt demandé")
    return 0


if __name__ == "__main__":
    sys.exit(main())
