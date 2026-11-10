"""Détection de scan de ports (ACC-1) : règle de seuil sur les logs UFW.
Alerte si une IP touche >= MIN_PORTS ports distincts en une minute.
Usage : python app-ml/detect_scan.py <ufw.log> [seuil]"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from features_logs import build_ufw_features, load_ufw_blocks  # noqa: E402

path = sys.argv[1]
min_ports = int(sys.argv[2]) if len(sys.argv) > 2 else 20
df, rejected = load_ufw_blocks(path)
feats = build_ufw_features(df)
if feats.empty:
    sys.exit("Aucune ligne UFW BLOCK : aucune alerte.")
hits = feats[feats["n_dports"] >= min_ports]
for _, r in hits.iterrows():
    sev = "high" if r["n_dports"] >= 200 else "medium" if r["n_dports"] >= 50 else "low"
    print(f"ALERTE SCAN {sev.upper():6} ip={r['src_ip']} minute={r['minute']} "
          f"ports_distincts={r['n_dports']} blocages={r['n_blocked']}")
print(f"{len(hits)} alerte(s) sur {len(feats)} fenêtre(s) IP/minute (seuil {min_ports} ports)")
