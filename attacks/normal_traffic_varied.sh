#!/usr/bin/env bash
MIN="${1:-20}"
END=$(( $(date +%s) + MIN*60 ))
KEY="$HOME/.ssh/lab_local"

echo "Génération de trafic normal varié pendant $MIN minutes (clé $KEY)..."

profile_isolated() {
  while [ "$(date +%s)" -lt "$END" ]; do
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep $(( (RANDOM % 20) + 10 ))
  done
}

profile_burst() {
  while [ "$(date +%s)" -lt "$END" ]; do
    n=$(( (RANDOM % 3) + 2 ))
    for i in $(seq 1 "$n"); do
      ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
      sleep 1
    done
    sleep $(( (RANDOM % 40) + 20 ))
  done
}

profile_heartbeat() {
  while [ "$(date +%s)" -lt "$END" ]; do
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes localhost true 2>/dev/null
    sleep $(( (RANDOM % 4) + 3 ))
  done
}

profile_isolated &
PID_A=$!
profile_burst &
PID_B=$!
profile_heartbeat &
PID_C=$!

wait $PID_A $PID_B $PID_C
echo "trafic normal varié terminé"
