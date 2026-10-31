#!/usr/bin/env bash
# Etat de l'infrastructure. Option : stop | start pour l'instance EC2.
export AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
IID="$(aws ec2 describe-instances --filters Name=tag:Name,Values=ml-anomaly Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)"
case "${1:-}" in
  stop)  aws ec2 stop-instances  --instance-ids "$IID" --query 'StoppingInstances[0].CurrentState.Name' --output text; exit;;
  start) aws ec2 start-instances --instance-ids "$IID" --query 'StartingInstances[0].CurrentState.Name' --output text; exit;;
esac
echo "S3        : $(aws s3 ls 2>/dev/null | awk '{print $3}' | tr '\n' ' ')"
echo "SNS       : $(aws sns list-topics --query 'Topics[].TopicArn' --output text 2>/dev/null | tr '\t' '\n' | grep ml-anomaly)"
echo "DynamoDB  : $(aws dynamodb list-tables --query 'TableNames' --output text 2>/dev/null)"
echo "EC2       : $IID $(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].[State.Name,PublicIpAddress]' --output text 2>/dev/null)"
echo "EventBridge: $(aws events describe-rule --name ml-anomaly-weekly-retrain --query '[Name,State,ScheduleExpression]' --output text 2>/dev/null)"
echo "CloudTrail: $(aws cloudtrail get-trail-status --name ml-anomaly-trail --query IsLogging --output text 2>/dev/null)"
