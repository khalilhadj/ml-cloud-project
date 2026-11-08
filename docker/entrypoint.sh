#!/usr/bin/env bash
set -e
mkdir -p /app/models /app/data/processed
python - << 'PY'
import os, sys
sys.path.insert(0, "/app/app-ml")
import models_sync, storage
print("modèles récupérés :", models_sync.pull_missing("/app/models"))
dst = "/app/data/processed/datasets.npz"
if not os.path.exists(dst) and storage.enabled():
    storage.download("data/datasets.npz", dst)
    print("datasets.npz récupéré")
PY
exec "$@"
