#!/bin/bash

# Ensure pre-req
# We don't want swap
swapoff -a

SK_USER=sk-api

# Create user
if [ ! -d /home/$SK_USER ] ; then
  useradd -U -s /bin/bash -m $SK_USER
fi
cd /home/$SK_USER

# Give the API user rights on the key
chown $SK_USER:$SK_USER $KEY_FILE
chmod 600 $KEY_FILE

# Retrieve sovereign_keys_api.tgz
NEED_RESTART="false"
ETAG=$(aws s3api head-object --bucket $ARTIFACT_BUCKET --key sovereign-instances/sovereign_keys_api.tgz --query ETag --output text)
if [ ! -f ./sovereign_keys_api.tgz.etag ] || [ $ETAG != $(cat ./sovereign_keys_api.tgz.etag) ] ; then
  echo $ETAG > ./sovereign_keys_api.tgz.etag
  aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/sovereign_keys_api.tgz ./sovereign_keys_api.tgz
  tar xvzf sovereign_keys_api.tgz
  NEED_RESTART="true"
fi

# Prepare logfile
LOGFILE=/home/$SK_USER/sovereign_keys_api.log
# Create logrotate file
cat << EOF > /etc/logrotate.d/sovereign_keys_api
$LOGFILE {
  size 100M
  copytruncate
  nocopy
  rotate 0
  count 1
  postrotate
    rm ${LOGFILE}-*
  endscript
}
EOF

# Create systemd services
cat << EOF > /tmp/sk-api.service
[Unit]
Description=Sovereign Keys API service
After=network.target
Wants=network.target
[Service]
User=$SK_USER
Group=$SK_USER
Type=simple
Restart=always
RestartSec=5
ExecStart=/bin/sh -c 'exec /usr/bin/python3 /home/$SK_USER/sovereign_keys_api/sovereign_keys_api.py &>> $LOGFILE'
Environment=AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION
Environment=EKT_BUCKET=$EKT_BUCKET
Environment=VPC_INFOS_TABLE=$VPC_INFOS_TABLE
Environment=AUDIT_BUCKET=$AUDIT_BUCKET
Environment=KEY_FILE=$KEY_FILE
Environment=HSM_TYPE=$HSM_TYPE
[Install]
WantedBy=default.target
EOF

if [ ! -f /etc/systemd/system/sk-api.service ] || ! diff /etc/systemd/system/sk-api.service /tmp/sk-api.service || [ "$NEED_RESTART" == "true" ] ; then
  echo "Need to start or restart the service..."
  mv /tmp/sk-api.service /etc/systemd/system/sk-api.service
  systemctl daemon-reload
  systemctl enable sk-api
  systemctl restart sk-api
else
  rm -f /tmp/sk-api.service
fi
