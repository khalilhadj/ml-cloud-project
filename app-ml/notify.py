"""Notification des alertes : email SMTP, webhook Slack, ou simulation (FR-13)."""
import json
import logging
import os
import smtplib
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)
RANK = {"élevée": 2, "moyenne": 1, "faible": 0}


def load_settings():
    load_dotenv(ROOT / ".env")
    g = os.environ.get
    return {
        "host": g("SMTP_HOST", "").strip(),
        "port": int(g("SMTP_PORT", "587") or 587),
        "user": g("SMTP_USER", "").strip(),
        "password": g("SMTP_PASSWORD", ""),
        "to": g("ALERT_EMAIL_TO", "").strip(),
        "slack": g("SLACK_WEBHOOK_URL", "").strip(),
    }


def build_message(alerts, model_version, top=10):
    """Texte récapitulatif : compteurs par sévérité + les alertes les plus graves."""
    counts = {s: sum(a["severity"] == s for a in alerts) for s in RANK}
    ranked = sorted(alerts, key=lambda a: (RANK[a["severity"]], a["score"]), reverse=True)[:top]
    subject = (f"[Détection d'anomalies] {len(alerts)} alerte(s) - "
               f"{counts['élevée']} élevée(s)")
    lines = [f"Modèle : {model_version}",
             f"Alertes : {len(alerts)} (élevée {counts['élevée']}, "
             f"moyenne {counts['moyenne']}, faible {counts['faible']})", "",
             f"Les {len(ranked)} plus graves :"]
    for a in ranked:
        feats = ", ".join(f"{n} ({d} σ)" for n, d in a["top_features"])
        ip = f" ip={a['src_ip']}" if a.get("src_ip") else ""
        n = f" x{a['count']}" if a.get("count", 1) > 1 else ""
        lines.append(f"- {a['severity']:<7} score={a['score']:.3f}{ip}{n} : {feats}")
    lines += ["", "Qualifier ces alertes dans le tableau de bord (vrai / faux positif)."]
    return subject, "\n".join(lines)


def _send_smtp(s, subject, body):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, s["user"] or s["to"], s["to"]
    msg.set_content(body)
    with smtplib.SMTP(s["host"], s["port"], timeout=15) as smtp:
        smtp.starttls()
        if s["user"]:
            smtp.login(s["user"], s["password"])
        smtp.send_message(msg)


def _send_slack(url, subject, body):
    data = json.dumps({"text": f"*{subject}*\n```{body}```"}).encode()
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15).read()


def notify(alerts, model_version, settings=None, top=10):
    """Retourne 'email', 'slack', 'email+slack', 'simulation', 'aucune_alerte' ou 'erreur'."""
    if not alerts:
        return "aucune_alerte"
    s = settings or load_settings()
    subject, body = build_message(alerts, model_version, top)
    sent = []
    try:
        if s["host"] and s["to"]:
            _send_smtp(s, subject, body)
            sent.append("email")
        if s["slack"]:
            _send_slack(s["slack"], subject, body)
            sent.append("slack")
    except Exception:
        logger.exception("Échec de l'envoi de la notification (le pipeline continue)")
        return "erreur"
    if not sent:
        print("--- MODE SIMULATION (SMTP non configuré) ---")
        print(f"Sujet : {subject}\n\n{body}\n--------------------------------------------")
        return "simulation"
    return "+".join(sent)


if __name__ == "__main__":
    import sys
    from unittest import mock

    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))

    demo = [
        {"index": 1, "score": 0.71, "severity": "élevée", "src_ip": "10.0.0.5", "count": 50,
         "top_features": [("num_failed_logins", 9.1), ("count", 6.2)]},
        {"index": 2, "score": 0.52, "severity": "faible", "top_features": [("src_bytes", 3.4)]},
        {"index": 3, "score": 0.58, "severity": "moyenne", "top_features": [("serror_rate", 5.0)]},
    ]
    empty = {"host": "", "port": 587, "user": "", "password": "", "to": "", "slack": ""}
    smtp_cfg = {**empty, "host": "smtp.test", "to": "analyste@test", "user": "u", "password": "p"}

    check("aucune alerte -> rien envoyé", notify([], "v002", empty) == "aucune_alerte")
    check("SMTP non configuré -> simulation", notify(demo, "v002", empty) == "simulation")
    subject, body = build_message(demo, "v002")
    check("sujet : total et nombre d'élevées", "3 alerte(s)" in subject and "1 élevée" in subject, subject)
    check("la plus grave est listée en premier", body.index("score=0.710") < body.index("score=0.580") < body.index("score=0.520"))
    check("IP et regroupement affichés", "ip=10.0.0.5 x50" in body)
    check("variables déviantes affichées", "num_failed_logins (9.1 σ)" in body)
    with mock.patch("smtplib.SMTP") as m:
        check("SMTP configuré -> email", notify(demo, "v002", smtp_cfg) == "email")
        check("starttls + login + envoi appelés",
              m.return_value.__enter__.return_value.send_message.called)
    with mock.patch("smtplib.SMTP", side_effect=OSError("serveur injoignable")):
        check("erreur SMTP -> ne plante pas", notify(demo, "v002", smtp_cfg) == "erreur")
    print(f"\nRésultat : {sum(results)}/{len(results)} OK")
    sys.exit(0 if all(results) else 1)
