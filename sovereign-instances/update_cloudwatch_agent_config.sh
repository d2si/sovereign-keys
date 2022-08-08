#!/bin/bash

# Prereqs

# Script
# Verify the version of the SSM Parameter
LAST_MODIF=$(aws ssm get-parameter --name $SSM_CLOUDWATCH_CONFIG --query Parameter.LastModifiedDate)
if [ ! -f /root/cloudwatch-agent-config-last-change ] ||  [ $LAST_MODIF != $(cat /root/cloudwatch-agent-config-last-change) ] ; then
  echo "Cloudwatch Config changed in SSM"
  amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c ssm:$SSM_CLOUDWATCH_CONFIG -s
  echo $LAST_MODIF > /root/cloudwatch-agent-config-last-change
fi
