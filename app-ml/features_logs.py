"""features_logs.py : variables par IP et par minute à partir des logs
UFW (scan de ports) et auth.log (force brute SSH).

Usage :
  python app-ml/features_logs.py ufw   data/raw/ssh/ufw_scan_nmap_1510.log
  python app-ml/features_logs.py auth  data/raw/ssh/auth_hydra_1520.log
"""
import math
import re
import sys
from collections import Counter
from datetime import datetime

import pandas as pd

KV = re.compile(r"(\w+)=(\S*)")

# --- UFW (scan de ports) -----------------------------------------------

def parse_ufw_line(line, year):
    if "[UFW BLOCK]" not in line:
        return None
    parts = line.split()
    try:
        ts = datetime.strptime(
            f"{year} {parts[0]} {parts[1]} {parts[2]}", "%Y %b %d %H:%M:%S"
        )
        kv = dict(KV.findall(line))
        return {
            "timestamp": ts,
            "src_ip": kv["SRC"],
            "spt": int(kv.get("SPT") or 0),
            "dpt": int(kv["DPT"]),
        }
    except (ValueError, KeyError, IndexError):
        return None


def load_ufw_blocks(path, year=None):
    year = year or datetime.now().year
    rows, rejected = [], 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            if "[UFW BLOCK]" not in line:
                continue
            rec = parse_ufw_line(line, year)
            if rec is None:
                rejected += 1
            else:
                rows.append(rec)
    return pd.DataFrame(rows), rejected


def entropy(values):
    counts = Counter(values)
    n = sum(counts.values())
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def build_ufw_features(df):
    if df.empty:
        return df
    df = df.copy()
    df["minute"] = df["timestamp"].dt.floor("min")
    out = (
        df.groupby(["src_ip", "minute"])
        .agg(
            n_blocked=("dpt", "size"),
            n_dports=("dpt", "nunique"),
            n_sports=("spt", "nunique"),
            dport_entropy=("dpt", entropy),
        )
        .reset_index()
    )
    out["ports_per_packet"] = out["n_dports"] / out["n_blocked"]
    return out


# --- auth.log (force brute SSH) -----------------------------------------

AUTH_LINE_RE = re.compile(
    r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<status>Failed password|Accepted password|Invalid user)"
    r"(?:\s+for)?(?:\s+invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_auth_line(line, year):
    """Retourne un dict ou None. Ignore toute ligne qui n'est pas un essai SSH."""
    if "sshd[" not in line:
        return None
    if not any(k in line for k in ("Failed password", "Accepted password", "Invalid user")):
        return None
    m = AUTH_LINE_RE.search(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        )
        return {
            "timestamp": ts,
            "src_ip": m["ip"],
            "user": m["user"],
            "status": m["status"],
        }
    except ValueError:
        return None


def load_auth_attempts(path, year=None):
    year = year or datetime.now().year
    rows, rejected = [], 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            if "sshd[" not in line:
                continue
            if not any(k in line for k in ("Failed password", "Accepted password", "Invalid user")):
                continue
            rec = parse_auth_line(line, year)
            if rec is None:
                rejected += 1
            else:
                rows.append(rec)
    return pd.DataFrame(rows), rejected


def build_auth_features(df):
    if df.empty:
        return df
    df = df.copy()
    df["minute"] = df["timestamp"].dt.floor("min")
    failed = df[df["status"] == "Failed password"]
    accepted = df[df["status"] == "Accepted password"]
    invalid = df[df["status"] == "Invalid user"]

    out = (
        df.groupby(["src_ip", "minute"])
        .size()
        .reset_index(name="n_attempts")
    )
    for name, sub in [("n_failed", failed), ("n_accepted", accepted), ("n_invalid_user", invalid)]:
        counts = sub.groupby(["src_ip", "minute"]).size().reset_index(name=name)
        out = out.merge(counts, on=["src_ip", "minute"], how="left")
    out = out.fillna(0)

    n_users = df.groupby(["src_ip", "minute"])["user"].nunique().reset_index(name="n_distinct_users")
    out = out.merge(n_users, on=["src_ip", "minute"], how="left")

    for col in ("n_failed", "n_accepted", "n_invalid_user", "n_distinct_users"):
        out[col] = out[col].astype(int)
    out["fail_ratio"] = out["n_failed"] / out["n_attempts"]
    return out


# --- CLI -----------------------------------------------------------------

if __name__ == "__main__":
    kind, path = sys.argv[1], sys.argv[2]
    if kind == "ufw":
        df, rejected = load_ufw_blocks(path)
        feats = build_ufw_features(df)
        print(f"Lignes UFW BLOCK lues : {len(df)} | rejetées : {rejected}")
    elif kind == "auth":
        df, rejected = load_auth_attempts(path)
        feats = build_auth_features(df)
        print(f"Tentatives SSH lues : {len(df)} | rejetées : {rejected}")
    else:
        sys.exit("Usage: features_logs.py [ufw|auth] <fichier>")

    sort_col = "n_dports" if kind == "ufw" else "n_attempts"
    print(feats.sort_values(sort_col, ascending=False).to_string(index=False))


# --- Détecteur SSH (modèle ML, fenêtre de 10 s) --------------------------
# Agrège les événements auth.log par IP et par fenêtre fixe de 10 secondes.
# Une version antérieure de cette fonction existait mais n'a jamais été
# committée ; elle produisait un nombre de fenêtres différent, non
# reproductible. Cette version est la seule considérée comme valide, et
# le nombre de fenêtres qu'elle produit dépend uniquement du fichier
# source utilisé.

SSH_WINDOW = 10  # secondes
FEATURE_NAMES = ["n_events", "n_failed", "fail_ratio", "n_distinct_users",
                  "n_distinct_ports", "events_per_second"]


def build_features(events):
    """events : DataFrame avec colonnes timestamp, src_ip, user, port, failed
    (sortie de ingestion.load_auth_log). Retourne (keys, X) : keys a les
    colonnes src_ip et window_start ; X est un tableau numpy (n_fenetres, 6)."""
    import numpy as np
    if events.empty:
        return pd.DataFrame(columns=["src_ip", "window_start"]), np.empty((0, 6))
    df = events.copy()
    epoch = df["timestamp"].astype("int64") // 10**9
    df["window_start"] = pd.to_datetime((epoch // SSH_WINDOW) * SSH_WINDOW, unit="s")

    rows = []
    for (ip, w), g in df.groupby(["src_ip", "window_start"]):
        n_events = len(g)
        n_failed = int(g["failed"].sum())
        rows.append({
            "src_ip": ip,
            "window_start": w,
            "n_events": n_events,
            "n_failed": n_failed,
            "fail_ratio": n_failed / n_events,
            "n_distinct_users": g["user"].nunique(),
            "n_distinct_ports": g["port"].nunique(),
            "events_per_second": n_events / SSH_WINDOW,
        })
    out = pd.DataFrame(rows).sort_values(["src_ip", "window_start"]).reset_index(drop=True)
    keys = out[["src_ip", "window_start"]]
    X = out[FEATURE_NAMES].to_numpy(dtype=float)
    return keys, X
