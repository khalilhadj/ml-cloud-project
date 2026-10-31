#!/usr/bin/env bash
# IAM (vérification), DynamoDB, EC2, EventBridge, CloudTrail. Relançable sans risque.
REGION="${AWS_REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"
ok() { echo "  [OK] $1"; }
ko() { echo "  [KO] $1"; }

ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
[ -z "$ACCOUNT" ] && { echo "Credentials invalides : lance lab-creds"; exit 1; }

echo "== IAM (rôles du Lab, réutilisés) =="
ROLE_ARN="$(aws iam get-role --role-name LabRole --query Role.Arn --output text 2>/dev/null)"
[ -n "$ROLE_ARN" ] && ok "LabRole : $ROLE_ARN" || ko "LabRole introuvable"
PROFILE=""
aws iam get-instance-profile --instance-profile-name LabInstanceProfile >/dev/null 2>&1 \
  && { PROFILE="LabInstanceProfile"; ok "LabInstanceProfile présent"; } || ko "LabInstanceProfile absent (EC2 sans accès S3 automatique)"

echo "== DynamoDB =="
TABLE="ml-anomaly-alerts"
if aws dynamodb describe-table --table-name "$TABLE" >/dev/null 2>&1; then ok "table $TABLE déjà présente"
else
  aws dynamodb create-table --table-name "$TABLE" \
    --attribute-definitions AttributeName=alert_id,AttributeType=S \
    --key-schema AttributeName=alert_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null 2>&1 && ok "table $TABLE créée" || ko "création de la table refusée"
fi

echo "== EC2 =="
VPC="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text 2>/dev/null)"
if [ -z "$VPC" ] || [ "$VPC" = "None" ]; then ko "aucun VPC par défaut"; else
  ok "VPC par défaut : $VPC"
  MYIP="$(curl -s https://checkip.amazonaws.com | tr -d '[:space:]')"
  SG="$(aws ec2 describe-security-groups --filters Name=group-name,Values=ml-anomaly-sg Name=vpc-id,Values="$VPC" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
  if [ -z "$SG" ] || [ "$SG" = "None" ]; then
    SG="$(aws ec2 create-security-group --group-name ml-anomaly-sg --description "ML anomaly detection" --vpc-id "$VPC" --query GroupId --output text 2>/dev/null)"
  fi
  if [ -n "$SG" ] && [ "$SG" != "None" ]; then
    for PORT in 22 8501; do
      aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port "$PORT" --cidr "${MYIP}/32" >/dev/null 2>&1
    done
    ok "groupe de sécurité $SG (ports 22 et 8501 ouverts à $MYIP/32 seulement)"
  else ko "groupe de sécurité non créé"; fi

  KEY="ml-anomaly-key"; PEM="$HOME/.ssh/${KEY}.pem"; mkdir -p ~/.ssh
  if aws ec2 describe-key-pairs --key-names "$KEY" >/dev/null 2>&1; then
    [ -f "$PEM" ] && ok "clé SSH $KEY présente" || ko "clé $KEY existe dans AWS mais pas $PEM : supprime-la (aws ec2 delete-key-pair --key-name $KEY) et relance"
  else
    umask 077
    aws ec2 create-key-pair --key-name "$KEY" --query KeyMaterial --output text > "$PEM" 2>/dev/null && chmod 400 "$PEM" && ok "clé SSH créée : $PEM" || ko "création de la clé refusée"
  fi

  IID="$(aws ec2 describe-instances --filters Name=tag:Name,Values=ml-anomaly Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)"
  if [ -n "$IID" ] && [ "$IID" != "None" ]; then ok "instance déjà présente : $IID"
  else
    AMI="$(aws ssm get-parameters --names /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id --query 'Parameters[0].Value' --output text 2>/dev/null)"
    if [ -z "$AMI" ] || [ "$AMI" = "None" ]; then
      AMI="$(aws ec2 describe-images --owners 099720109477 --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*' --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text 2>/dev/null)"
    fi
    ARGS=(--image-id "$AMI" --instance-type t3.small --key-name "$KEY" --security-group-ids "$SG"
          --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}'
          --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ml-anomaly}]'
          --query 'Instances[0].InstanceId' --output text)
    [ -n "$PROFILE" ] && ARGS+=(--iam-instance-profile "Name=$PROFILE")
    IID="$(aws ec2 run-instances "${ARGS[@]}" 2>/dev/null)"
    if [ -n "$IID" ]; then ok "instance créée : $IID (AMI $AMI)"; aws ec2 wait instance-running --instance-ids "$IID" 2>/dev/null
    else ko "création de l'instance refusée"; fi
  fi
  [ -n "$IID" ] && [ "$IID" != "None" ] && echo "  IP publique : $(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null)"
fi

echo "== EventBridge =="
if aws events put-rule --name ml-anomaly-weekly-retrain --schedule-expression 'cron(0 3 ? * SUN *)' \
     --state DISABLED --description "Reentrainement hebdomadaire (cible a ajouter en 10b)" >/dev/null 2>&1
then ok "règle ml-anomaly-weekly-retrain (dimanche 3h UTC, désactivée)"; else ko "règle refusée"; fi

echo "== CloudTrail =="
TB="ml-anomaly-trail-${ACCOUNT}"
aws s3api head-bucket --bucket "$TB" 2>/dev/null || aws s3api create-bucket --bucket "$TB" --region "$REGION" >/dev/null 2>&1
cat > /tmp/trail-policy.json << POLICY
{"Version":"2012-10-17","Statement":[
{"Sid":"AclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::${TB}"},
{"Sid":"Write","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::${TB}/AWSLogs/${ACCOUNT}/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]}
POLICY
aws s3api put-public-access-block --bucket "$TB" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null 2>&1
if aws s3api put-bucket-policy --bucket "$TB" --policy file:///tmp/trail-policy.json >/dev/null 2>&1; then
  aws cloudtrail create-trail --name ml-anomaly-trail --s3-bucket-name "$TB" >/dev/null 2>&1
  if aws cloudtrail start-logging --name ml-anomaly-trail >/dev/null 2>&1; then ok "trail ml-anomaly-trail actif (logs dans $TB)"; else ko "CloudTrail refusé"; fi
else ko "politique du bucket CloudTrail refusée"; fi

echo
echo "Résumé : relance 'bash infra/status_aws.sh' pour tout revérifier."
