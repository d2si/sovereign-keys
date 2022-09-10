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

# Getting the binaries
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-pkcs11-latest.el7.x86_64.rpm
yum install -y ./cloudhsm-pkcs11-latest.el7.x86_64.rpm

# Installing config files
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/cloudhsm-conf/customerCA.crt /opt/cloudhsm/etc/customerCA.crt
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/cloudhsm-conf/ssl-client.crt /opt/cloudhsm/etc/ssl-client.crt

# Creating place holder for the private key in the RAMstore
# And creates a sym-link where CloudHSM software expects it
touch $KEY_FILE
ln -s $KEY_FILE /opt/cloudhsm/etc/ssl-client.key

# Configuring
/opt/cloudhsm/bin/configure-pkcs11 --hsm-ca-cert /opt/cloudhsm/etc/customerCA.crt
/opt/cloudhsm/bin/configure-pkcs11 --server-client-cert-file /opt/cloudhsm/etc/ssl-client.crt --server-client-key-file /opt/cloudhsm/etc/ssl-client.key
/opt/cloudhsm/bin/configure-pkcs11 --log-file /home/sk-api/cloudhsm-pkcs11.log
/opt/cloudhsm/bin/configure-pkcs11 --disable-key-availability-check

HSM_IP=$(aws cloudhsmv2 describe-clusters --query Clusters[0].Hsms[].EniIp --output text | xargs)
echo /opt/cloudhsm/bin/configure-pkcs11 -a $HSM_IP
/opt/cloudhsm/bin/configure-pkcs11 -a $HSM_IP
