"""Ingestion des logs : NSL-KDD (CSV), Nginx (access.log), SSH (auth.log)."""
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag", "label"]
NUMERIC = [c for c in NSL_KDD_COLUMNS if c not in CATEGORICAL]


def load_nsl_kdd(path):
    """Charge un fichier NSL-KDD. Les lignes mal formées sont rejetées et journalisées."""
    good, rejected = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != len(NSL_KDD_COLUMNS):
                logger.warning("%s ligne %d rejetée : %d champs au lieu de %d",
                               path, n, len(parts), len(NSL_KDD_COLUMNS))
                rejected += 1
                continue
            good.append(parts)

    df = pd.DataFrame(good, columns=NSL_KDD_COLUMNS)
    for col in NUMERIC:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    bad = df[NUMERIC].isna().any(axis=1)
    if bad.any():
        logger.warning("%s : %d lignes rejetées (valeurs non numériques)", path, int(bad.sum()))
        rejected += int(bad.sum())
        df = df[~bad]
    df = df.reset_index(drop=True)
    logger.info("%s : %d lignes chargées, %d rejetées", path, len(df), rejected)
    return df


# 1.2.3.4 - - [01/Oct/2026:11:44:20 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/7.81"
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)'
)


def load_nginx(path):
    """Parse un access.log Nginx (format combined)."""
    rows, rejected = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            m = NGINX_RE.match(line)
            if not m:
                logger.warning("%s ligne %d rejetée (format Nginx invalide)", path, n)
                rejected += 1
                continue
            try:
                ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                logger.warning("%s ligne %d rejetée (date invalide)", path, n)
                rejected += 1
                continue
            rows.append({
                "timestamp": ts, "src_ip": m["ip"], "method": m["method"],
                "url": m["url"], "status": int(m["status"]),
                "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
            })
    logger.info("%s : %d lignes chargées, %d rejetées", path, len(rows), rejected)
    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "method", "url", "status", "bytes"])


# Oct  1 11:44:20 host sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
AUTH_RE = re.compile(
    r"^(?P<time>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) \w+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


def load_auth_log(path, year=None):
    """Parse un auth.log SSH (échecs et succès d'authentification)."""
    year = year or datetime.now().year
    rows, ignored, rejected = [], 0, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            if "sshd[" not in line:
                ignored += 1          # ligne d'un autre service, pas une erreur
                continue
            m = AUTH_RE.match(line)
            if not m:
                ignored += 1          # autre message sshd (connexion fermée, etc.)
                continue
            try:
                ts = datetime.strptime(f"{year} {m['time']}", "%Y %b %d %H:%M:%S")
            except ValueError:
                logger.warning("%s ligne %d rejetée (date invalide)", path, n)
                rejected += 1
                continue
            rows.append({
                "timestamp": ts, "src_ip": m["ip"], "user": m["user"],
                "port": int(m["port"]), "failed": int(m["result"] == "Failed"),
            })
    logger.info("%s : %d événements SSH, %d rejetés, %d ignorés",
                path, len(rows), rejected, ignored)
    return pd.DataFrame(rows, columns=["timestamp", "src_ip", "user", "port", "failed"])


def load_file(path):
    """Choisit le bon parseur selon le nom du fichier."""
    name = Path(path).name.lower()
    if "auth" in name:
        return load_auth_log(path)
    if "access" in name or "nginx" in name:
        return load_nginx(path)
    return load_nsl_kdd(path)


def load_folder(folder):
    """FR-01 : charge tous les fichiers d'un dossier. Un fichier en erreur n'arrête pas les autres."""
    results = {}
    for p in sorted(Path(folder).glob("*")):
        if p.name.startswith(".") or not p.is_file():
            continue
        try:
            results[p.name] = load_file(p)
        except Exception:
            logger.exception("Échec du chargement de %s", p)
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "data/raw/KDDTrain+.txt"
    df = load_file(target)
    print(df.shape)
    print(df.head(3).T.head(12))
