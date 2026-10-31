"""Test S3 + SNS avec faux clients en mémoire. Usage : python tests/test_storage.py"""
import logging
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app-ml"))

import ingestion  # noqa: E402
import notify  # noqa: E402
import storage  # noqa: E402

logging.disable(logging.CRITICAL)
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'OK' if cond else 'KO'}] {name}" + (f"  ->  {detail}" if detail else ""))


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.pages = 0

    def upload_file(self, path, bucket, key):
        self.objects[key] = Path(path).read_bytes()

    def download_file(self, bucket, key, path):
        Path(path).write_bytes(self.objects[key])

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        start = int(ContinuationToken or 0)
        page = keys[start:start + 2]            # 2 objets par page : teste la pagination
        self.pages += 1
        r = {"Contents": [{"Key": k} for k in page]}
        if start + 2 < len(keys):
            r["IsTruncated"], r["NextContinuationToken"] = True, str(start + 2)
        return r


class FakeSNS:
    def __init__(self):
        self.sent = []

    def publish(self, **kw):
        self.sent.append(kw)


kdd_line = open(ROOT / "data/raw/KDDTrain+.txt", encoding="utf-8").readline()
objects = {
    "logs/KDD_sample.txt": (kdd_line * 2).encode(),
    "logs/auth.log": (b"Oct  1 11:44:20 srv sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2\n"
                      b"Oct  1 11:44:22 srv sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2\n"),
    "logs/.gitkeep": b"",
    "autre/ignore.txt": b"x",
}

print("== 1. Adresses S3 ==")
check("s3://bucket/a/b -> (bucket, a/b)", storage.parse_s3_url("s3://bucket/a/b") == ("bucket", "a/b"))
check("s3://bucket -> prefixe vide", storage.parse_s3_url("s3://bucket") == ("bucket", ""))
for bad in ("/tmp/x", "s3://"):
    try:
        storage.parse_s3_url(bad)
        check(f"rejet de {bad!r}", False)
    except ValueError:
        check(f"rejet de {bad!r}", True)

print("== 2. Stockage ==")
s3 = FakeS3(objects)
keys = storage.list_keys("logs/", bucket="b", client=s3)
check("liste paginée : 3 objets sous logs/", len(keys) == 3 and s3.pages == 2, f"{len(keys)} objets, {s3.pages} pages")
check("hors préfixe exclu", "autre/ignore.txt" not in keys)
with tempfile.TemporaryDirectory() as tmp:
    f = Path(tmp) / "a" / "up.txt"
    f.parent.mkdir()
    f.write_text("salut")
    storage.upload(f, "models/up.txt", bucket="b", client=s3)
    check("upload", s3.objects["models/up.txt"] == b"salut")
    storage.download("models/up.txt", Path(tmp) / "new" / "dl.txt", bucket="b", client=s3)
    check("download (dossier créé)", (Path(tmp) / "new" / "dl.txt").read_text() == "salut")

print("== 3. Ingestion depuis S3 ==")
r = ingestion.load_folder("s3://b/logs/", client=FakeS3(objects))
check("2 fichiers chargés (.gitkeep ignoré)", sorted(r) == ["KDD_sample.txt", "auth.log"], str(sorted(r)))
check("NSL-KDD : 2 lignes x 43 colonnes", r["KDD_sample.txt"].shape == (2, 43), str(r["KDD_sample.txt"].shape))
check("auth.log : 2 échecs SSH", len(r["auth.log"]) == 2 and r["auth.log"]["failed"].sum() == 2)
bad = dict(objects)
bad["logs/auth_cassé.log"] = b"\xff\xfe"
r2 = ingestion.load_folder("s3://b/logs/", client=FakeS3(bad))
check("un fichier illisible n'arrête pas les autres", "KDD_sample.txt" in r2 and "auth.log" in r2)
check("mode local inchangé", isinstance(ingestion.load_folder(str(ROOT / "tests")), dict))

print("== 4. SNS ==")
demo = [{"index": 1, "score": 0.7, "severity": "élevée", "top_features": [("count", 5.0)]}]
base = {"host": "", "port": 587, "user": "", "password": "", "to": "", "slack": ""}
sns = FakeSNS()
res = notify.notify(demo, "v001", {**base, "sns": "arn:aws:sns:us-east-1:1:topic"}, sns_client=sns)
check("SNS seul -> 'sns'", res == "sns", res)
check("message publié sur le bon topic", len(sns.sent) == 1 and sns.sent[0]["TopicArn"].endswith(":topic"))
check("sujet <= 100 caractères", len(sns.sent[0]["Subject"]) <= 100)


class BrokenSNS:
    def publish(self, **kw):
        raise OSError("réseau coupé")


check("erreur SNS -> ne plante pas",
      notify.notify(demo, "v001", {**base, "sns": "arn:x"}, sns_client=BrokenSNS()) == "erreur")
check("sans SNS ni SMTP -> simulation", notify.notify(demo, "v001", {**base, "sns": ""}) == "simulation")

print(f"\nRésultat : {sum(results)}/{len(results)} OK")
sys.exit(0 if all(results) else 1)
