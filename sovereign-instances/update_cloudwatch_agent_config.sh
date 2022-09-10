#!/bin/bash

# Copyright 2022 Devoteam Revolve (D2SI SAS)
# This file is part of `Sovereign Keys`.
#
# `Sovereign Keys` is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# `Sovereign Keys` is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with `Sovereign Keys`. If not, see <http://www.gnu.org/licenses/>.

# Prereqs

# Script
# Verify the version of the SSM Parameter
LAST_MODIF=$(aws ssm get-parameter --name $SSM_CLOUDWATCH_CONFIG --query Parameter.LastModifiedDate)
if [ ! -f /root/cloudwatch-agent-config-last-change ] ||  [ $LAST_MODIF != $(cat /root/cloudwatch-agent-config-last-change) ] ; then
  echo "Cloudwatch Config changed in SSM"
  amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c ssm:$SSM_CLOUDWATCH_CONFIG -s
  echo $LAST_MODIF > /root/cloudwatch-agent-config-last-change
fi
