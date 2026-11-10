#!/usr/bin/env bash
# Autorise l'IP actuelle de cette machine sur les ports 22 et 8501,
# retire les anciennes IP, démarre l'EC2 si besoin, affiche l'URL.
set -euo pipefail
INSTANCE_ID="i-08e14795b347a7bd7"
KEY="$HOME/.ssh/ml-anomaly-key.pem"
PORTS="22 8501"

MYIP=$(curl -s https://checkip.amazonaws.com | tr -d '\n')
echo "Mon IP actuelle : $MYIP"

STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].State.Name' --output text)
if [ "$STATE" = "stopped" ]; then
  echo "Instance arrêtée, démarrage..."
  aws ec2 start-instances --instance-ids "$INSTANCE_ID" >/dev/null
  aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
fi

SG=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)

for PORT in $PORTS; do
  OLD=$(aws ec2 describe-security-groups --group-ids "$SG" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`$PORT\`].IpRanges[].CidrIp" --output text)
  for CIDR in $OLD; do
    if [ "$CIDR" != "$MYIP/32" ]; then
      aws ec2 revoke-security-group-ingress --group-id "$SG" \
        --protocol tcp --port "$PORT" --cidr "$CIDR" >/dev/null
      echo "  retiré  $CIDR (port $PORT)"
    fi
  done
  aws ec2 authorize-security-group-ingress --group-id "$SG" \
    --protocol tcp --port "$PORT" --cidr "$MYIP/32" >/dev/null 2>&1 \
    && echo "  ajouté  $MYIP/32 (port $PORT)" || echo "  déjà présent (port $PORT)"
done

EC2IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo
echo "Dashboard : http://$EC2IP:8501"
echo "SSH       : ssh -i $KEY ubuntu@$EC2IP"

if [ "${1:-}" = "ssh" ]; then
  sleep 5
  exec ssh -o ConnectTimeout=15 -i "$KEY" ubuntu@"$EC2IP"
fi
