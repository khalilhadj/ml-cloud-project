#!/bin/bash
# Même principe que open_access.sh, mais pour la machine attaquante.
set -e
MY_IP=$(curl -s ifconfig.me)
ATTACKER_SG="sg-02e5160f95b2a27e0"
ATTACKER_ID="i-06215b3c149dcf65a"

echo "Mon IP actuelle : $MY_IP"

# Retire les anciennes règles port 22 (CIDR différents de la nouvelle IP), ajoute la nouvelle
OLD_RULES=$(aws ec2 describe-security-groups --group-ids "$ATTACKER_SG" \
  --query "SecurityGroups[].IpPermissions[?FromPort==\`22\`].IpRanges[].CidrIp" --output text)
for cidr in $OLD_RULES; do
  if [ "$cidr" != "$MY_IP/32" ]; then
    aws ec2 revoke-security-group-ingress --group-id "$ATTACKER_SG" --protocol tcp --port 22 --cidr "$cidr" 2>/dev/null \
      && echo "  retiré  $cidr"
  fi
done
aws ec2 authorize-security-group-ingress --group-id "$ATTACKER_SG" --protocol tcp --port 22 --cidr "$MY_IP/32" 2>/dev/null \
  && echo "  ajouté  $MY_IP/32" || echo "  déjà présent  $MY_IP/32"

ATTACKER_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$ATTACKER_ID" \
  --query "Reservations[].Instances[].PublicIpAddress" --output text)
echo "IP publique actuelle de l'attaquante : $ATTACKER_PUBLIC_IP"

if [ "$1" = "ssh" ]; then
  ssh -i ~/.ssh/ml-anomaly-key.pem "ec2-user@$ATTACKER_PUBLIC_IP"
fi
