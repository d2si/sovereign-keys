#!/bin/bash

INST_DIR=/opt/tw_proteccio
[ -d "${INST_DIR}" ] || mkdir -p "${INST_DIR}"
INST_LIB_CLNT="${INST_DIR}/lib"

# Getting the binaries
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/proteccio/nethsmstatus ${INST_LIB_CLNT}/nethsmstatus
chmod +x ${INST_LIB_CLNT}/nethsmstatus
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/proteccio/libnethsm.so ${INST_LIB_CLNT}/libnethsm.so
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/proteccio/libnethsmanalyze.so ${INST_LIB_CLNT}/libnethsmanalyze.so

cp -f ${INST_LIB_CLNT}/libnethsm.so /usr/lib64/libnethsm.so
cp -f ${INST_LIB_CLNT}/libnethsmanalyze.so /usr/lib64/libnethsmanalyze.so
ln -s /usr/lib64/libnethsm.so /usr/lib64/libnethsm64.so
ln -s /usr/lib64/libnethsmanalyze.so /usr/lib64/libnethsmanalyze64.so

# Installing config files
aws s3 sync s3://$ARTIFACT_BUCKET/sovereign-instances/proteccio-conf/ /etc/proteccio/

# Creating place holder for the private key in the RAMstore
# And creates a sym-link where proteccio software expects it
touch $KEY_FILE
ln -s $KEY_FILE /etc/proteccio/client.key

# Ensuring logfile rotation
cat << EOF > /etc/logrotate.d/proteccio-pkcs11
/etc/proteccio/pkcs11.log {
  size 100M
  copytruncate
  nocopy
  rotate 0
  count 1
  postrotate
    rm /etc/proteccio/pkcs11.log-*
  endscript
}
EOF
