#!/usr/bin/env bash
MIN="${1:-20}"
END=$(( $(date +%s) + MIN*60 ))
KEY="$HOME/.ssh/lab_local"

echo "Génération de trafic normal varié (v2, burst limité) pendant $MIN minutes..."

profile_isolated() {
  while [ "$(date +%s)" -lt "$END" ]; do
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep $(( (RANDOM % 20) + 10 ))
  done
}

profile_burst() {
  while [ "$(date +%s)" -lt "$END" ]; do
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep 2
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep $(( (RANDOM % 50) + 30 ))
  done
}

profile_heartbeat() {
  while [ "$(date +%s)" -lt "$END" ]; do
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep $(( (RANDOM % 5) + 5 ))
  done
}

profile_isolated &
PID_A=$!
profile_burst &
PID_B=$!
profile_heartbeat &
PID_C=$!

wait $PID_A $PID_B $PID_C
echo "trafic normal varié (v2) terminé"
