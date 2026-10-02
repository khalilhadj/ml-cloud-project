"""Test de FR-15 : regroupement des alertes par IP source. Usage : python tests/test_grouping.py"""
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

from alerts import attach_context, group_by_ip, severity_of  # noqa: E402
from ingestion import load_auth_log  # noqa: E402
from score import load_config  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


def line(dt, ip, user="root"):
    return (f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} srv sshd[101]: "
            f"Failed password for {user} from {ip} port 4242 ssh2")


year = datetime.now().year
t0 = datetime(year, 10, 1, 11, 0, 0)
lines = []
lines += [line(t0 + timedelta(seconds=2 * i), "10.0.0.5") for i in range(50)]   # force brute : 50 échecs en 100 s
lines += [line(t0 + timedelta(minutes=25), "10.0.0.5")]                          # même IP, 25 min plus tard
lines += [line(t0, "10.0.0.9"), line(t0 + timedelta(minutes=30), "10.0.0.9")]    # 2 échecs espacés de 30 min
lines += [line(t0 + timedelta(minutes=5), "10.0.0.7")]                           # IP isolée

cfg = load_config()
window = cfg["detection"]["dedup_window_minutes"]
sev = {"low": 0.0, "medium": 0.55, "high": 0.60}

with tempfile.TemporaryDirectory() as tmp:
    log = Path(tmp) / "auth.log"
    log.write_text("\n".join(lines) + "\n")
    df = load_auth_log(log, year=year)

check("54 événements SSH lus", len(df) == 54, str(len(df)))

alerts = [{"index": i, "score": 0.5 + 0.001 * i, "severity": severity_of(0.5 + 0.001 * i, sev),
           "top_features": [("failed", 1.0)]} for i in range(len(df))]
alerts[30]["score"] = 0.70
alerts[30]["severity"] = severity_of(0.70, sev)
attach_context(alerts, src_ips=df["src_ip"].to_numpy(), timestamps=list(df["timestamp"]))
alerts.append({"index": 54, "score": 0.9, "severity": "élevée", "top_features": []})  # sans IP (type NSL-KDD)

groups = group_by_ip(alerts, window)
check(f"fenêtre de {window} min lue depuis config.yaml", window == 10)
check("55 alertes -> 6 groupes", len(groups) == 6, str(len(groups)))

burst = [g for g in groups if g.get("src_ip") == "10.0.0.5" and g["count"] > 1]
check("force brute : 50 alertes regroupées en 1", len(burst) == 1 and burst[0]["count"] == 50)
if burst:
    b = burst[0]
    check("représentante = score maximal du groupe", abs(b["score"] - 0.70) < 1e-9)
    check("durée du groupe = 98 s", (b["last_seen"] - b["first_seen"]).total_seconds() == 98)
    check("sévérité = la plus haute du groupe", b["severity"] == "élevée", b["severity"])
    check("indexes conservés", len(b["indexes"]) == 50)

later = [g for g in groups if g.get("src_ip") == "10.0.0.5" and g["count"] == 1]
check("même IP 25 min plus tard : groupe séparé", len(later) == 1)
check("10.0.0.9 espacée de 30 min : 2 groupes", sum(g.get("src_ip") == "10.0.0.9" for g in groups) == 2)
check("IP isolée conservée", sum(g.get("src_ip") == "10.0.0.7" for g in groups) == 1)
check("alerte sans IP non regroupée", any(g["index"] == 54 and g["count"] == 1 for g in groups))
check("tri par score décroissant", all(groups[i]["score"] >= groups[i + 1]["score"] for i in range(len(groups) - 1)))
check("aucune alerte perdue", sum(g["count"] for g in groups) == len(alerts), str(sum(g["count"] for g in groups)))

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
