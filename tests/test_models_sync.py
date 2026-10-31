"""Test de 9c avec faux S3 en mémoire. Usage : python tests/test_models_sync.py"""
import logging
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import models_sync as ms  # noqa: E402
import score  # noqa: E402
import storage  # noqa: E402

logging.disable(logging.CRITICAL)
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


class FakeS3:
    def __init__(self):
        self.objects, self.lists = {}, 0

    def upload_file(self, path, bucket, key):
        self.objects[key] = Path(path).read_bytes()

    def download_file(self, bucket, key, path):
        Path(path).write_bytes(self.objects[key])

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        self.lists += 1
        return {"Contents": [{"Key": k} for k in sorted(self.objects) if k.startswith(Prefix)]}


class BrokenS3:
    def upload_file(self, *a, **k):
        raise OSError("réseau coupé")

    download_file = list_objects_v2 = upload_file


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    models = tmp / "models"
    v1 = models / "v001"
    v1.mkdir(parents=True)
    (v1 / "model.joblib").write_bytes(b"MODEL")
    (v1 / "preprocessor.joblib").write_bytes(b"PRE")
    (v1 / "metadata.json").write_bytes(b'{"version": "v001"}')
    (v1 / "junk.txt").write_bytes(b"inutile")
    (models / "active.txt").write_text("v001\n")

    print("== 1. Envoi ==")
    s3 = FakeS3()
    keys = ms.push_version(v1, bucket="b", client=s3)
    check("3 fichiers envoyés, junk.txt exclu",
          sorted(keys) == ["models/v001/metadata.json", "models/v001/model.joblib", "models/v001/preprocessor.joblib"]
          and "models/v001/junk.txt" not in s3.objects)
    check("contenu identique", s3.objects["models/v001/model.joblib"] == b"MODEL")
    check("active.txt envoyé", ms.push_active(models, "b", s3) == "models/active.txt"
          and s3.objects["models/active.txt"] == b"v001\n")
    check("pas de active.txt -> None", ms.push_active(tmp / "vide", "b", s3) is None)

    print("== 2. Récupération ==")
    s3.objects["models/v002/evil.sh"] = b"x"
    s3.objects["models/notversion/model.joblib"] = b"x"
    s3.objects["models/v003/sub/model.joblib"] = b"x"
    pulled = tmp / "pulled"
    got = ms.pull_missing(pulled, bucket="b", client=s3)
    check("4 fichiers récupérés (3 du modèle + active.txt)",
          sorted(got) == ["active.txt", "v001/metadata.json", "v001/model.joblib", "v001/preprocessor.joblib"], str(sorted(got)))
    check("contenu identique en local",
          (pulled / "v001" / "model.joblib").read_bytes() == b"MODEL" and (pulled / "active.txt").read_text() == "v001\n")
    check("clés piégées ignorées",
          not (pulled / "v002").exists() and not (pulled / "notversion").exists() and not (pulled / "v003").exists())
    check("seconde récupération : rien à faire", ms.pull_missing(pulled, bucket="b", client=s3) == [])
    (pulled / "v001" / "model.joblib").write_bytes(b"LOCAL")
    check("un fichier local n'est jamais écrasé",
          ms.pull_missing(pulled, bucket="b", client=s3) == [] and (pulled / "v001" / "model.joblib").read_bytes() == b"LOCAL")
    with mock.patch.object(storage, "enabled", lambda: False):
        check("S3 non configuré -> récupération vide", ms.pull_missing(tmp / "x") == [])

    print("== 3. Envoi sécurisé ==")
    with mock.patch.object(storage, "enabled", lambda: False):
        check("S3 non configuré -> 'disabled'", ms.safe_push(v1) == "disabled")
    f2 = FakeS3()
    check("envoi avec active.txt -> 'ok'", ms.safe_push(v1, with_active=True, bucket="b", client=f2) == "ok"
          and "models/active.txt" in f2.objects and "models/v001/model.joblib" in f2.objects)
    f3 = FakeS3()
    ms.safe_push(v1, with_active=False, bucket="b", client=f3)
    check("sans active.txt quand non promu", "models/active.txt" not in f3.objects)
    check("panne S3 -> 'error' sans exception", ms.safe_push(v1, bucket="b", client=BrokenS3()) == "error")

    print("== 4. Récupération automatique dans score.py ==")
    m2 = tmp / "m2"
    check("dossier vide -> modèle récupéré depuis S3",
          score._ensure_local(m2, None, client=s3, bucket="b") is True and (m2 / "v001" / "model.joblib").exists())
    before = s3.lists
    check("modèle présent -> aucun appel S3",
          score._ensure_local(m2, None, client=s3, bucket="b") is False and s3.lists == before)
    check("version demandée absente -> récupérée",
          score._ensure_local(tmp / "m3", "v001", client=s3, bucket="b") is True and (tmp / "m3" / "v001" / "model.joblib").exists())
    check("panne S3 -> False sans exception", score._ensure_local(tmp / "m4", None, client=BrokenS3(), bucket="b") is False)

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
