#!/bin/bash

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
