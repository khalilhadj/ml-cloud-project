"""Synchronisation des modèles versionnés avec S3 (jamais bloquant)."""
import logging
import re
from pathlib import Path

import storage

logger = logging.getLogger(__name__)
PREFIX = "models/"
FILES = ("model.joblib", "preprocessor.joblib", "metadata.json")


def push_version(vdir, bucket=None, client=None):
    """Envoie les fichiers d'un dossier models/vNNN. Retourne les clés envoyées."""
    vdir, keys = Path(vdir), []
    for name in FILES:
        f = vdir / name
        if f.exists():
            key = f"{PREFIX}{vdir.name}/{name}"
            storage.upload(f, key, bucket=bucket, client=client)
            keys.append(key)
    return keys


def push_active(models_dir, bucket=None, client=None):
    f = Path(models_dir) / "active.txt"
    if not f.exists():
        return None
    storage.upload(f, PREFIX + "active.txt", bucket=bucket, client=client)
    return PREFIX + "active.txt"


def pull_missing(models_dir, bucket=None, client=None):
    """Télécharge ce qui manque en local (sans écraser). Retourne les chemins relatifs récupérés."""
    if client is None and not storage.enabled():
        return []
    client = client or storage.get_client()
    bucket = bucket or storage.bucket_name()
    models_dir, got = Path(models_dir), []
    for key in storage.list_keys(PREFIX, bucket=bucket, client=client):
        rel = key[len(PREFIX):]
        parts = rel.split("/")
        if rel == "active.txt":
            local = models_dir / "active.txt"
        elif len(parts) == 2 and re.fullmatch(r"v\d+", parts[0]) and parts[1] in FILES:
            local = models_dir / parts[0] / parts[1]
        else:
            continue
        if local.exists():
            continue
        storage.download(key, local, bucket=bucket, client=client)
        got.append(rel)
    return got


def safe_push(vdir, with_active=False, bucket=None, client=None):
    """Retourne 'ok', 'disabled' (S3 non configuré) ou 'error'. Ne lève jamais d'exception."""
    if client is None and not storage.enabled():
        return "disabled"
    try:
        client = client or storage.get_client()
        bucket = bucket or storage.bucket_name()
        push_version(vdir, bucket, client)
        if with_active:
            push_active(Path(vdir).parent, bucket, client)
        return "ok"
    except Exception:
        logger.exception("Envoi du modèle sur S3 impossible (le pipeline continue)")
        return "error"


if __name__ == "__main__":
    import sys
    from score import ROOT, load_config

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    models_dir = ROOT / load_config()["paths"]["models"]
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "push":
        for v in sorted(models_dir.glob("v*")):
            if v.is_dir():
                print(v.name, safe_push(v))
        if storage.enabled():
            print("active.txt :", push_active(models_dir, client=storage.get_client()))
    elif cmd == "pull":
        print("récupéré :", pull_missing(models_dir))
    else:
        print("Usage : python app-ml/models_sync.py push|pull")
