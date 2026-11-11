"""Tests du détecteur par règle (logs synthétiques, base temporaire)."""
import sys
import tempfile
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "app-ml"))
import db  # noqa: E402
import detector  # noqa: E402

IP = "10.0.0.5"


def line(t, ok=False, ip=IP, user="alice"):
    st = "Accepted" if ok else "Failed"
    return f"Nov 10 {t} host sshd[1]: {st} password for {user} from {ip} port 40000 ssh2\n"


def run(lines):
    with tempfile.TemporaryDirectory() as tmp:
        log, dbp = Path(tmp) / "auth.log", Path(tmp) / "a.db"
        log.write_text("".join(lines))
        n = detector.scan(str(log), 5, set(), db_path=dbp)
        rows = []
        if n:
            with db.connect(dbp) as con:
                rows = [dict(r) for r in con.execute("SELECT severity, created_at, src_ip FROM alerts")]
        return n, rows


fails = 0
def check(name, cond):
    global fails
    print(("OK  " if cond else "KO  ") + name)
    fails += not cond

n, _ = run([line("10:00:01"), line("10:00:05"), line("10:00:09"), line("10:00:12", ok=True)])
check("3 échecs puis succès (utilisateur légitime) : 0 alerte", n == 0)
n, _ = run([line(f"10:00:{s:02d}") for s in (1, 2, 3, 4)])
check("4 échecs dans la minute (sous le seuil) : 0 alerte", n == 0)
n, _ = run([line(f"10:{m:02d}:10") for m in range(10)])
check("1 échec par minute pendant 10 min : 0 alerte", n == 0)
n, rows = run([line(f"10:00:{s:02d}") for s in (1, 2, 3, 4, 5)])
check("5 échecs dans la minute : 1 alerte", n == 1)
check("horodatage = minute de l'attaque", rows and rows[0]["created_at"].endswith("10:00:00"))
check("IP enregistrée", rows and rows[0]["src_ip"] == IP)
n, rows = run([line(f"10:00:{s:02d}") for s in range(1, 7)] + [line("10:00:30", ok=True)])
check("6 échecs + accès obtenu : sévérité élevée", n == 1 and rows[0]["severity"] == "élevée")
sys.exit(1 if fails else 0)
