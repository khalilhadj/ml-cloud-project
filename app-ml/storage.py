"""Stockage S3 (logs bruts, modèles). Sans S3_BUCKET, le projet reste 100 % local."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]


def bucket_name():
    load_dotenv(ROOT / ".env")
    return os.environ.get("S3_BUCKET", "").strip()


def enabled():
    return bool(bucket_name())


def get_client():
    import boto3
    return boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))


def parse_s3_url(url):
    """'s3://bucket/a/b' -> ('bucket', 'a/b')."""
    if not url.startswith("s3://"):
        raise ValueError(f"URL S3 invalide : {url!r}")
    bucket, _, prefix = url[5:].partition("/")
    if not bucket:
        raise ValueError(f"bucket manquant dans {url!r}")
    return bucket, prefix


def upload(local_path, key, bucket=None, client=None):
    client = client or get_client()
    client.upload_file(str(local_path), bucket or bucket_name(), key)


def download(key, local_path, bucket=None, client=None):
    client = client or get_client()
    Path(local_path).parent.mkdir(parents=True, exist_ok=True)
    client.download_file(bucket or bucket_name(), key, str(local_path))


def list_keys(prefix="", bucket=None, client=None):
    client = client or get_client()
    keys, token = [], None
    while True:
        kw = {"Bucket": bucket or bucket_name(), "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        r = client.list_objects_v2(**kw)
        keys += [o["Key"] for o in r.get("Contents", []) if not o["Key"].endswith("/")]
        if not r.get("IsTruncated"):
            return keys
        token = r["NextContinuationToken"]
