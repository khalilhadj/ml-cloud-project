#!/usr/bin/env bash
# Trafic SSH légitime vers la VM locale (cible de laboratoire). Usage : normal_traffic.sh [minutes]
MIN="${1:-15}"
END=$(( $(date +%s) + MIN*60 ))
KEY="$HOME/.ssh/lab_local"
while [ "$(date +%s)" -lt "$END" ]; do
  ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
  sleep $(( (RANDOM % 3) + 1 ))
done
echo "trafic normal terminé"
