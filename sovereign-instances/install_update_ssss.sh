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

INST_BIN=/usr/local/bin

# Getting the binaries
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/ssss/ssss ${INST_BIN}/ssss-split
ln ${INST_BIN}/ssss-split ${INST_BIN}/ssss-combine
chmod +x ${INST_BIN}/ssss-combine
chmod +x ${INST_BIN}/ssss-split

# Installing the man page
aws s3 cp s3://$ARTIFACT_BUCKET/sovereign-instances/ssss/ssss.1.gz /usr/local/share/man/man1/ssss.1.gz

# Creating the sk-set-hsm-password script
cat > ${INST_BIN}/sk-set-hsm-password << EOF
#!/bin/bash

SHARE_COUNT=4
SHARE_THRESHOLD=2
SHARE_PREFIX=sk-hsm-pwd-
SHARE_PREFIX_LEN=\${#SHARE_PREFIX}

echo This script will collect the Shamir\'s Secret Shares of the Sovereign Keys HSM PIN.
echo Once the PIN has been successfully reconstructed, the script will set it in the API
echo Please input \$SHARE_THRESHOLD different shares out of the \$SHARE_COUNT existing shares
SSSS_INPUT=""
for x in \$(seq \$SHARE_THRESHOLD); do
  read -s -p "Input one of the share with prefix '\$SHARE_PREFIX' [\$x/\$SHARE_THRESHOLD]: " tmp
  echo
  if [[ \$tmp =~ ^\$SHARE_PREFIX.*$ ]] ; then
    SSSS_INPUT="\${SSSS_INPUT}\${tmp:\$SHARE_PREFIX_LEN}\\n"
  else
    echo "Invalid share was input (prefix is not '\$SHARE_PREFIX')"
    exit 1
  fi
  unset tmp
done
HSM_PIN=""
# This morron is outputing the secret on stderr
SSSS_ERROR=\$(echo -e \$SSSS_INPUT | ssss-combine -t\$SHARE_THRESHOLD -q 2>&1)
if [ "\$?" == "0" ] ; then
  HSM_PIN=\$SSSS_ERROR
else
  echo \$SSSS_ERROR
fi
unset SSSS_ERROR
unset SSSS_INPUT

if [ -z "\$HSM_PIN" ] ; then
  echo Could not reconstruct the HSM PIN
  exit 2
fi
echo HSM PIN was successfully reconstructed
echo Calling the API to set the PIN
curl -H "Content-Type: application/json" -X PUT -d "{\\"pin\\":\\"\$HSM_PIN\\"}" http://localhost:8080/hsm-pin
unset HSM_PIN
EOF

chmod +x ${INST_BIN}/sk-set-hsm-password
