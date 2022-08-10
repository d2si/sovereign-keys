#!/bin/bash

# Self locker will simply run as root
# It will test the health of the service
# And if at some point it is healthy while the locker is on, it will shutdown sshd
# If the locker is off by env var, it will start sshd
# Cycle every 5min
cat > /root/self-locker.sh << EOF
#!/bin/bash
while true ; do
  source /etc/profile.d/fixed-env.sh
  if [ "\$SELF_LOCKER_ON" = "true" ] && systemctl status sshd &>/dev/null && curl -f http://localhost:8080/healthcheck ; then
    systemctl stop sshd
    systemctl disable sshd
  fi
  if [ "\$SELF_LOCKER_ON" = "false" ] && ! systemctl status sshd &>/dev/null ; then
    systemctl enable sshd
    systemctl start sshd
  fi
  # When SSH is on, will run through the loop quicker
  if systemctl status sshd &>/dev/null ; then
    sleep 10
  else
    sleep 300
  fi
done
EOF


# Create systemd services
cat << EOF > /tmp/self-locker.service
[Unit]
Description=Self Locker Service
After=network.target
Wants=network.target
[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=/bin/sh /root/self-locker.sh &>/dev/null'
[Install]
WantedBy=default.target
EOF

if [ ! -f /etc/systemd/system/self-lockerservice ] || ! diff /etc/systemd/system/self-locker.service /tmp/self-locker.service || [ "$NEED_RESTART" == "true" ] ; then
  echo "Need to start or restart the service..."
  mv /tmp/self-locker.service /etc/systemd/system/self-locker.service
  systemctl daemon-reload
  systemctl enable self-locker
  systemctl restart self-locker
else
  rm -f /tmp/self-locker.service
fi
