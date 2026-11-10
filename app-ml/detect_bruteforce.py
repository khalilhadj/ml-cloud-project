"""Détection de force brute SSH (ACC-2) : règle de seuil sur auth.log.
Alerte si une IP accumule >= MIN_FAILED échecs en une minute.
Usage : python app-ml/detect_bruteforce.py <auth.log> [seuil]"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from features_logs import build_auth_features, load_auth_attempts  # noqa: E402

path = sys.argv[1]
min_failed = int(sys.argv[2]) if len(sys.argv) > 2 else 5
df, rejected = load_auth_attempts(path)
feats = build_auth_features(df)
if feats.empty:
    sys.exit("Aucune tentative SSH : aucune alerte.")

hits = feats[feats["n_failed"] >= min_failed]
for _, r in hits.iterrows():
    if r["n_accepted"] > 0:
        sev = "high"  # accès obtenu après échecs : compromission probable
    elif r["n_distinct_users"] >= 2:
        sev = "high" if r["n_failed"] >= 20 else "medium"
    else:
        sev = "low"
    print(f"ALERTE BRUTEFORCE {sev.upper():6} ip={r['src_ip']} minute={r['minute']} "
          f"echecs={r['n_failed']} utilisateurs_distincts={r['n_distinct_users']} "
          f"acceptes={r['n_accepted']}")
print(f"{len(hits)} alerte(s) sur {len(feats)} fenêtre(s) IP/minute (seuil {min_failed} échecs)")
