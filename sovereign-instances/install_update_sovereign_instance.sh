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

# First thing first, refresh envvars
aws ssm get-parameter --name $SSM_ENV_VARS --query Parameter.Value --output text > /etc/profile.d/fixed-env.sh.new
if [ $? -eq 0 ] && ! diff /etc/profile.d/fixed-env.sh.new /etc/profile.d/fixed-env.sh ; then
  mv /etc/profile.d/fixed-env.sh.new /etc/profile.d/fixed-env.sh
  echo "Sourcing new parameters found in $SSM_ENV_VARS"
  . /etc/profile.d/fixed-env.sh
else
  rm /etc/profile.d/fixed-env.sh.new
fi

export RAMFS_DIR=/mnt/ram-store
export KEY_FILE=$RAMFS_DIR/client.key

# Function checking modifs and downloading scripts
# Returns true ( 0 ) only if the script was modified
check_and_download () {
  SCRIPT=$1
  ETAG=$(aws s3api head-object --bucket $ARTIFACT_BUCKET --key sovereign-instances/$SCRIPT --query ETag --output text)
  if [ ! -f /root/$SCRIPT.etag ] || [ $ETAG != $(cat /root/$SCRIPT.etag) ] ; then
    echo $ETAG > /root/$SCRIPT.etag
    aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/$SCRIPT /root/$SCRIPT.tmp
    if [ ! -f /root/$SCRIPT ] || ! diff /root/$SCRIPT.tmp /root/$SCRIPT ; then
      echo "Updating $SCRIPT"
      mv /root/$SCRIPT.tmp /root/$SCRIPT
      chmod +x /root/$SCRIPT
      return 0
    else
      rm /root/$SCRIPT.tmp
    fi
  fi
  return 1
}

# Try to retrieve a new version of the current script
# If a new version is indeed available, run it and then exit this old version
if check_and_download install_update_sovereign_instance.sh ; then
  echo "Running new version of install_update_sovereign_instance.sh"
  /root/install_update_sovereign_instance.sh
  exit
fi

# Retrieve installation/update script for Cloudwatch Agent Configuration
check_and_download update_cloudwatch_agent_config.sh
echo "Running update_cloudwatch_agent_config.sh"
/root/update_cloudwatch_agent_config.sh

# Retrieve creation script for RAM store
if check_and_download create_ram_store.sh ; then
  echo "Running create_ram_store.sh"
  /root/create_ram_store.sh
fi

###############################################################
#                      BEGIN HSM LAYER                        #
###############################################################
# Retrieve installation/update script for the HSM layer
# This is the installation of the PKSC#11 libs and binaries
# Chosen according to the HSM_TYPE envvar
if [ "$HSM_TYPE" == "proteccio" ] || [ "$HSM_TYPE" == "cloudhsm" ] ; then
  if check_and_download "install_update_hsm_layer.$HSM_TYPE.sh" ; then
    echo "Running install_update_hsm_layer.$HSM_TYPE.sh"
    eval "/root/install_update_hsm_layer.$HSM_TYPE.sh"
  fi
fi
###############################################################
#                       END HSM LAYER                         #
###############################################################

# Retrieve installation/update script for Sovereign API
check_and_download install_update_sovereign_keys_api.sh
echo "Running install_update_sovereign_keys_api.sh"
/root/install_update_sovereign_keys_api.sh

# Retrieve installation/update script for etcd
if check_and_download install_update_etcd.sh ; then
  echo "Running install_update_etcd.sh"
  /root/install_update_etcd.sh
fi

# Retrieve installation/update script for ssss
if check_and_download install_update_ssss.sh ; then
  echo "Running install_update_ssss.sh"
  /root/install_update_ssss.sh
fi

# Retrieve installation/update script for self-locker
if check_and_download install_update_self_locker.sh ; then
  echo "Running install_update_self_locker.sh"
  /root/install_update_self_locker.sh
fi
