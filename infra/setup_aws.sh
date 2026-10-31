#!/usr/bin/env bash
# Crée (ou vérifie) l'infrastructure AWS du projet. Relançable sans risque.
set -u
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)" || { echo "Credentials invalides : lance lab-creds"; exit 1; }
BUCKET="${S3_BUCKET:-ml-anomaly-${ACCOUNT}}"
TOPIC="ml-anomaly-alerts"

echo "== S3 : $BUCKET =="
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "bucket déjà présent"
else
  aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" && echo "bucket créé"
fi
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/aws/s3"},"BucketKeyEnabled":true}]}' \
  && echo "chiffrement KMS (alias/aws/s3) activé"
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  && echo "accès public bloqué"
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled \
  && echo "versionnement activé"

echo "== SNS : $TOPIC =="
ARN="$(aws sns create-topic --name "$TOPIC" --region "$REGION" --query TopicArn --output text)" && echo "topic : $ARN"

echo
echo "== Vérification =="
aws s3api get-bucket-encryption --bucket "$BUCKET" --query "ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault" --output text
echo
echo "Ajoute ces lignes à ton .env :"
echo "S3_BUCKET=$BUCKET"
echo "SNS_TOPIC_ARN=${ARN:-}"
