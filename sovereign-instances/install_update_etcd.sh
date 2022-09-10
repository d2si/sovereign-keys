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

ETCD_USER=etcd-user

# Ensure pre-req
yum install -y jq &>/dev/null
# We don't want swap
swapoff -a

# Create etcd user
useradd -U -s /bin/bash -m $ETCD_USER

# Retrieve and install etcd
cd /home/$ETCD_USER

# Retrieve etcd archive if RELEASE_VERSION changed
RELEASE_VERSION=v3.4.0

if [ ! -f /root/etcd-release ] || [ "$RELEASE_VERSION" != "$(cat /root/etcd-release)" ] ; then
  echo "etcd release changed. Was: $(cat /root/etcd-release 2>/dev/null) ; Is: $RELEASE_VERSION"
  FOLDER_NAME=etcd-$RELEASE_VERSION-linux-amd64
  # FOLDER_NAME=etcd-$RELEASE_VERSION-linux-arm64
  ARCHIVE_NAME=$FOLDER_NAME.tar.gz
  ARCHIVE_URL=https://github.com/etcd-io/etcd/releases/download/$RELEASE_VERSION/$ARCHIVE_NAME
  echo "Downloading $ARCHIVE_URL..."
  sudo -u $ETCD_USER wget $ARCHIVE_URL
  sudo -u $ETCD_USER tar xvzf $ARCHIVE_NAME
  echo "Updating binary..."
  mv $FOLDER_NAME/etcd /usr/bin
  chown $ETCD_USER:$ETCD_USER /usr/bin/etcd
  mv $FOLDER_NAME/etcdctl /usr/bin
  chown $ETCD_USER:$ETCD_USER /usr/bin/etcdctl
  # Freeup space
  rm -f $ARCHIVE_NAME
  rm -rf $FOLDER_NAME
fi

ARGS=""

# Prepare logfile
LOGFILE=/home/$ETCD_USER/etcd.log
# Create logrotate file
cat << EOF > /etc/logrotate.d/etcd
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


# ETCD Data directory
ETCD_DATA_DIR=$RAMFS_DIR/etcd
# ETCD config file path
CONFIGFILE=/home/$ETCD_USER/etcd.conf

# If config file does not exist,
if [ ! -f $CONFIGFILE ] ; then
  # Create a RAM FS because in this case we don't want etcd to commit anything on-disk
  mkdir -p $ETCD_DATA_DIR

  ETCD_CURLOPTS="-ksf --connect-timeout 5"
  ETCD_OPTS="--insecure-transport=false --insecure-skip-tls-verify"
  ###############################################################################
  # Following is largely inspired from the Monsanto solution:                   #
  # https://github.com/MonsantoCo/etcd-aws-cluster/blob/master/etcd-aws-cluster #
  #                                                                             #
  # It has been adaptated and enhenced to remain stable in adverse Autoscaling  #
  # conditions where instances keep being killed and replaced.                  #
  ###############################################################################

  # ETCD API https://coreos.com/etcd/docs/2.0.11/other_apis.html
  add_ok=201
  already_added=409
  delete_ok=204
  delete_gone=410
  # Retrieve instance ID
  ec2_instance_id=$(curl -sf http://169.254.169.254/latest/meta-data/instance-id)
  # Retrieve private IP
  ec2_instance_ip=$(curl -sf http://169.254.169.254/latest/meta-data/local-ipv4)

  autoscaling_group_instances=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name "$ASG_NAME")
  echo "[etcd_prep] autoscaling_group_instances=$autoscaling_group_instances"
  # Get target peer count
  etcd_desired_peer_count=$(echo $autoscaling_group_instances | jq -r .AutoScalingGroups[0].DesiredCapacity)
  tmp=$(aws ec2 describe-instances --instance-ids $(echo $autoscaling_group_instances | jq '.AutoScalingGroups[0].Instances[].InstanceId' | xargs) | jq -r ".Reservations[].Instances | map(.InstanceId + \":\" + .NetworkInterfaces[].PrivateIpAddress + \"\n\")[]")
  declare -A instance_ips
  for l in $tmp ; do
    iid=$(echo $l | cut -d":" -f1)
    iip=$(echo $l | cut -d":" -f2)
    instance_ips[$iid]=$iip
  done

  candidate_peer_urls=$(for instance in $(echo $autoscaling_group_instances | jq '.AutoScalingGroups[0].Instances | sort_by(.LifecycleState, .InstanceId)[] | select(.LifecycleState  == "InService" or .LifecycleState  == "Terminating") | .InstanceId' | xargs) ; do if [[ ${instance_ips["$instance"]} ]] ; then echo https://${instance_ips["$instance"]}:2379 ; fi ; done)
  echo "[etcd_prep] candidate_peer_urls=$(echo $candidate_peer_urls | xargs)"

  etcd_existing_peer_urls=
  etcd_existing_peer_names=
  etcd_good_member_url=

  for url in $candidate_peer_urls; do
    echo "[etcd_prep] curl $ETCD_CURLOPTS $url/v2/members"
    etcd_members=$(curl $ETCD_CURLOPTS $url/v2/members)

    if [[ $? == 0 && $etcd_members ]]; then
      etcd_good_member_url="$url"
      echo "[etcd_prep] etcd_members=$etcd_members"
      etcd_existing_peer_urls=$(echo "$etcd_members" | jq --raw-output .[][].clientURLs[0])
      etcd_existing_peer_names=$(echo "$etcd_members" | jq --raw-output .[][].name)
      break
    fi
  done

  echo "[etcd_prep] etcd_good_member_url=$etcd_good_member_url"
  echo "[etcd_prep] etcd_existing_peer_urls=$(echo $etcd_existing_peer_urls | xargs)"
  echo "[etcd_prep] etcd_existing_peer_names=$(echo $etcd_existing_peer_names | xargs)"

  # if I am not listed as a member of the cluster assume that this is a existing cluster
  # this will also be the case for a proxy situation
  if [[ $etcd_existing_peer_urls && $etcd_existing_peer_names != *"$ec2_instance_id"* ]]; then

    MEMBER_TABLE=$(etcdctl $ETCD_OPTS endpoint status --endpoints=$(etcdctl $ETCD_OPTS --endpoints=$etcd_good_member_url member list -wsimple | cut -d"," -f5 | xargs | sed "s/ /,/g") -wtable)
    echo "$MEMBER_TABLE" | while read line ; do echo "[etcd_prep] $line" ; done

    # At this point, we create a simplistic lock that will ensure that only one instance performs modifications of the cluster
    echo "[etcd_prep] Trying to acquire lock..."
    while ! curl $ETCD_CURLOPTS $etcd_good_member_url/v2/keys/clustermanipulationlock?prevExist=false -XPUT -d value=$ec2_instance_id -d ttl=60 ; do sleep 1 ; echo "[etcd_prep] Waiting on lock..." ; done
    echo "[etcd_prep] Lock acquired"

   # Finding the leader URL and using it from this point forward
    etcd_leader_id=$(curl $ETCD_CURLOPTS $etcd_good_member_url/v2/stats/self | jq -r .leaderInfo.leader)
    etcd_leader_url=$(echo $etcd_members | jq -r ".members[] | select(.id==\"$etcd_leader_id\") | .clientURLs[0]")
    echo "[etcd_prep] etcd_leader_url=$etcd_leader_url"

    MEMBER_TABLE=$(etcdctl $ETCD_OPTS endpoint status --endpoints=$(etcdctl $ETCD_OPTS --endpoints=$etcd_leader_url member list -wsimple | cut -d"," -f5 | xargs | sed "s/ /,/g") -wtable)
    echo "$MEMBER_TABLE" | while read line ; do echo "[etcd_prep] $line" ; done

    # Verifying if the cluster still contains the secret
    SECRET_KEY=$(curl -ksf --connect-timeout 5 $etcd_leader_url/v2/keys/secrets/hsm_pin_b64 | jq -r .node.key)
    if [[ $SECRET_KEY ]] ; then
      echo "[etcd_prep] Secret present at $SECRET_KEY"
    else
      echo "[etcd_prep] Secret not present"
    fi

    # Refresh cluster status
    etcd_members=$(curl $ETCD_CURLOPTS $etcd_leader_url/v2/members)
    etcd_existing_peer_urls=$(echo "$etcd_members" | jq --raw-output .[][].clientURLs[0])
    # Current peer count
    etcd_existing_peer_count=$(echo "$etcd_members" | jq '.members | length')
    max_peer_to_remove=$(($etcd_existing_peer_count - $etcd_desired_peer_count + 1))

    echo "[etcd_prep] etcd_existing_peer_urls=$(echo $etcd_existing_peer_urls | xargs)"
    echo "[etcd_prep] etcd_existing_peer_count=$etcd_existing_peer_count"
    echo "[etcd_prep] etcd_desired_peer_count=$etcd_desired_peer_count"
    echo "[etcd_prep] max_peer_to_remove=$max_peer_to_remove"

    echo "[etcd_prep] trying to eject $max_peer_to_remove bad peers..."
    # eject bad members from cluster
    # Bad peers will contains first members that are not responding
    not_responding_urls=$(for url in $etcd_existing_peer_urls ; do if ! curl $ETCD_CURLOPTS "$url/v2/members" &>/dev/null ; then echo $url ; fi ; done)
    not_responding_regexp=$(echo "$not_responding_urls" | sed 's/^.*https:\/\/\([0-9.]*\):[0-9]*.*$/contains(\\"\/\/\1:\\")/' | xargs | sed 's/  */ or /g')
    not_responding_peers=$(echo "$etcd_members" | jq --raw-output ".[] | map(select(.peerURLs[] | $not_responding_regexp)) | .[].id")
    echo "[etcd_prep] not_responding_peers=$(echo $not_responding_peers | xargs)"
    # Then those not part of the asg anymore
    all_in_asg=$(for instance in $(echo $autoscaling_group_instances | jq '.AutoScalingGroups[0].Instances[] | .InstanceId' | xargs) ; do if [[ ${instance_ips["$instance"]} ]] ; then echo https://${instance_ips["$instance"]}:2379 ; fi ; done)
    all_in_asg_regexp=$(echo "$all_in_asg" | sed 's/^.*https:\/\/\([0-9.]*\):[0-9]*.*$/contains(\\"\/\/\1:\\")/' | xargs | sed 's/  */ or /g')
    not_in_asg_peers=$(echo "$etcd_members" | jq --raw-output ".[] | map(select(.peerURLs[] | $all_in_asg_regexp | not )) | .[].id")
    not_in_asg_peers=$(echo $not_in_asg_peers | xargs)
    echo "[etcd_prep] not_in_asg_peers=$(echo $not_in_asg_peers | xargs)"
    # Then those that are terminating
    terminating_etcd_peer_urls=$(for instance in $(echo $autoscaling_group_instances | jq '.AutoScalingGroups[0].Instances | sort_by(.InstanceId)[] | select(.LifecycleState  == "Terminating") | .InstanceId' | xargs) ; do if [[ ${instance_ips["$instance"]} ]] ; then echo https://${instance_ips["$instance"]}:2379 ; fi ; done)
    terminating_regexp=$(echo "$terminating_etcd_peer_urls" | sed 's/^.*https:\/\/\([0-9.]*\):[0-9]*.*$/contains(\\"\/\/\1:\\")/' | xargs | sed 's/  */ or /g')
    terminating_peers=$(echo "$etcd_members" | jq --raw-output ".[] | map(select(.peerURLs[] | $terminating_regexp)) | .[].id")
    echo "[etcd_prep] terminating_peers=$(echo $terminating_peers | xargs)"
    # That our bad peers list with deduplication
    bad_peers=$(echo "$not_responding_peers $not_in_asg_peers $terminating_peers" | xargs -n1 | awk '!x[$0]++' | xargs)
    echo "[etcd_prep] bad_peers=$bad_peers"
    count=0
    if [[ $bad_peers ]]; then
      for bp in $bad_peers; do
        if [[ $count -ge $max_peer_to_remove ]]; then
          break
        fi
        if [[ $bp == $etcd_leader_id ]]; then
          echo "[etcd_prep] Trying to remove the leader!"
        fi
        status=0
        echo "[etcd_prep] curl $ETCD_CURLOPTS -w %{http_code} "$etcd_leader_url/v2/members/$bp" -XDELETE"
        status=$(curl $ETCD_CURLOPTS -w %{http_code} "$etcd_leader_url/v2/members/$bp" -XDELETE)
        echo "[etcd_prep] removing bad peer $bp, return code $status."
        if [[ $status != $delete_ok && $status != $delete_gone ]]; then
          echo "[etcd_prep] ERROR: failed to remove bad peer"
        elif [[ $status == $delete_gone ]]; then
          echo "[etcd_prep] WARN: bad peer seemed already gone"
        else
          echo "[etcd_prep] removed bad peer"
          count=$(($count + 1))
          # If the leader has been removed, now is a good time to wait and find
          if [[ $bp == $etcd_leader_id ]]; then
            echo "[etcd_prep] Leader removed. Waiting 5 seconds for re-election..."
            sleep 5
            for url in $candidate_peer_urls; do
              echo "[etcd_prep] curl $ETCD_CURLOPTS $url/v2/members"
              etcd_members=$(curl $ETCD_CURLOPTS $url/v2/members)
              if [[ $? == 0 && $etcd_members ]]; then
                etcd_good_member_url="$url"
                echo "[etcd_prep] etcd_members=$etcd_members"
                break
              fi
            done
            etcd_leader_id=$(curl $ETCD_CURLOPTS $etcd_good_member_url/v2/stats/self | jq -r .leaderInfo.leader)
            etcd_leader_url=$(echo $etcd_members | jq -r ".members[] | select(.id==\"$etcd_leader_id\") | .clientURLs[0]")
            echo "[etcd_prep] etcd_leader_url=$etcd_leader_url"
          fi
        fi
      done
    fi

    if [[ $count -ge $max_peer_to_remove ]]; then
      echo "[etcd_prep] joining existing cluster"
    else
      echo "[etcd_prep] failed to remove any bad peer. Abording cluster join"
      exit
    fi

    # Add ourselves as a member to the cluster

    peer_url="https://$ec2_instance_ip:2380"
    etcd_initial_cluster=$(curl $ETCD_CURLOPTS "$etcd_leader_url/v2/members" | jq --raw-output '.[] | map(.name + "=" + .peerURLs[0]) | .[]' | xargs | sed 's/  */,/g')$(echo ",$ec2_instance_id=$peer_url")
    echo "[etcd_prep] etcd_initial_cluster=$etcd_initial_cluster"

    # join an existing cluster
    status=0
    retry=1
    until [[ $status = $add_ok || $status = $already_added || $retry = 3 ]]; do
      echo "[etcd_prep] curl $ETCD_CURLOPTS -w %{http_code} -o /dev/null -XPOST \"$etcd_leader_url/v2/members\" -H \"Content-Type: application/json\" -d {\"peerURLs\": [\"$peer_url\"], \"name\": \"$ec2_instance_id\"}"
      status=$(curl $ETCD_CURLOPTS -w %{http_code} -o /dev/null -XPOST "$etcd_leader_url/v2/members" -H "Content-Type: application/json" -d "{\"peerURLs\": [\"$peer_url\"], \"name\": \"$ec2_instance_id\"}")
      echo "[etcd_prep] adding instance ID $ec2_instance_id with peer URL $peer_url, retry $((retry++)), return code $status."
      sleep 2
    done
    if [[ $status != $add_ok && $status != $already_added ]]; then
      echo "[etcd_prep] unable to add $peer_url to the cluster: return code $status."
      exit 9
    else
      echo "[etcd_prep] added $peer_url to existing cluster, return code $status"
    fi

    ETCD_INITIAL_CLUSTER_STATE=existing
    ETCD_INITIAL_CLUSTER="$etcd_initial_cluster"

    # Remove the lock
    curl $ETCD_CURLOPTS $etcd_leader_url/v2/keys/clustermanipulationlock?prevValue=$ec2_instance_id -XDELETE
    echo "[etcd_prep] Lock has been released"

  # otherwise I was already listed as a member so assume that this is a new cluster
  else
    # create a new cluster
    echo "[etcd_prep] creating new cluster"

    etcd_initial_cluster=$(echo $(for instance in $(echo $autoscaling_group_instances | jq '.AutoScalingGroups[0].Instances[] | select(.LifecycleState  == "InService" or (.LifecycleState | startswith("Pending"))) | .InstanceId' | xargs) ; do echo ${instance}=https://${instance_ips["$instance"]}:2380 ; done) | sed "s/ /,/g")
    echo "[etcd_prep] etcd_initial_cluster=$etcd_initial_cluster"
    if [[ ! $etcd_initial_cluster ]]; then
      echo "[etcd_prep] unable to get peers from auto scaling group"
      exit 10
    fi

    ETCD_INITIAL_CLUSTER_STATE=new
    ETCD_INITIAL_CLUSTER="$etcd_initial_cluster"
  fi

  ###############################################################################
  # Previous is largely inspired from the Monsanto solution:                    #
  # https://github.com/MonsantoCo/etcd-aws-cluster/blob/master/etcd-aws-cluster #
  ###############################################################################

  # Create config file
  cat << EOF > $CONFIGFILE
# Human-readable name for this member.
name: '$ec2_instance_id'
# Path to the data directory.
data-dir: $ETCD_DATA_DIR
# Path to the dedicated wal directory.
wal-dir:
# Number of committed transactions to trigger a snapshot to disk.
snapshot-count: 10000
# Time (in milliseconds) of a heartbeat interval.
heartbeat-interval: 100
# Time (in milliseconds) for an election to timeout.
election-timeout: 1000
# Raise alarms when backend size exceeds the given quota. 0 means use the
# default quota.
quota-backend-bytes: 100000000
# List of comma separated URLs to listen on for peer traffic.
listen-peer-urls: https://${ec2_instance_ip}:2380
# List of comma separated URLs to listen on for client traffic.
listen-client-urls: https://${ec2_instance_ip}:2379,http://localhost:2379
# Maximum number of snapshot files to retain (0 is unlimited).
max-snapshots: 1
# Maximum number of wal files to retain (0 is unlimited).
max-wals: 1
# Comma-separated white list of origins for CORS (cross-origin resource sharing).
cors:
# List of this member's peer URLs to advertise to the rest of the cluster.
# The URLs needed to be a comma-separated list.
initial-advertise-peer-urls: https://${ec2_instance_ip}:2380
# List of this member's client URLs to advertise to the public.
# The URLs needed to be a comma-separated list.
advertise-client-urls: https://${ec2_instance_ip}:2379
# Discovery URL used to bootstrap the cluster.
discovery:
# Valid values include 'exit', 'proxy'
discovery-fallback: 'proxy'
# HTTP proxy to use for traffic to discovery service.
discovery-proxy:
# DNS domain used to bootstrap initial cluster.
discovery-srv:
# Initial cluster configuration for bootstrapping.
initial-cluster: $ETCD_INITIAL_CLUSTER
# Initial cluster token for the etcd cluster during bootstrap.
initial-cluster-token: 'etcd-cluster'
# Initial cluster state ('new' or 'existing').
initial-cluster-state: '$ETCD_INITIAL_CLUSTER_STATE'
# Reject reconfiguration requests that would cause quorum loss.
strict-reconfig-check: false
# Auto compaction retention for mvcc key value store in hour. 0 means disable auto compaction
auto-compaction-retention: 5
# Interpret 'auto-compaction-retention' one of: 'periodic', 'revision'. 'periodic' for duration based retention, defaulting to hours if no time unit is provided (e.g. '5m'). 'revision' for revision number based retention.
auto-compaction-mode: revision
# Accept etcd V2 client requests
enable-v2: true
# Enable runtime profiling data via HTTP server
enable-pprof: true
# Valid values include 'on', 'readonly', 'off'
proxy: 'off'
# Time (in milliseconds) an endpoint will be held in a failed state.
proxy-failure-wait: 5000
# Time (in milliseconds) of the endpoints refresh interval.
proxy-refresh-interval: 30000
# Time (in milliseconds) for a dial to timeout.
proxy-dial-timeout: 1000
# Time (in milliseconds) for a write to timeout.
proxy-write-timeout: 5000
# Time (in milliseconds) for a read to timeout.
proxy-read-timeout: 0
client-transport-security:
  # Path to the client server TLS cert file.
  cert-file:
  # Path to the client server TLS key file.
  key-file:
  # Enable client cert authentication.
  client-cert-auth: false
  # Path to the client server TLS trusted CA cert file.
  trusted-ca-file:
  # Client TLS using generated certificates
  auto-tls: true
peer-transport-security:
  # Path to the peer server TLS cert file.
  cert-file:
  # Path to the peer server TLS key file.
  key-file:
  # Enable peer client cert authentication.
  client-cert-auth: false
  # Path to the peer server TLS trusted CA cert file.
  trusted-ca-file:
  # Peer TLS using generated certificates.
  auto-tls: true
# Enable debug-level logging for etcd.
log-level: info
# Specify 'stdout' or 'stderr' to skip journald logging even when running under systemd.
log-outputs: [stderr]
# Force to create a new one member cluster.
force-new-cluster: false
auto-compaction-mode: periodic
auto-compaction-retention: "1"
EOF
fi

chown -R $ETCD_USER:$ETCD_USER $ETCD_DATA_DIR
chown -R $ETCD_USER:$ETCD_USER /home/$ETCD_USER
chmod 700 $ETCD_DATA_DIR
chmod 600 $CONFIGFILE
SERVICE_FILE=/etc/systemd/system/etcd.service

# Create systemd services
cat << EOF > /tmp/etcd.service
[Unit]
Description=etcd distributed key-value store service
After=network.target
Wants=network.target
[Service]
User=$ETCD_USER
Group=$ETCD_USER
Type=simple
Restart=always
RestartSec=5
WorkingDirectory=/home/$ETCD_USER
ExecStart=/usr/bin/etcd --config-file $CONFIGFILE
[Install]
WantedBy=default.target
EOF
# Environment=ETCD_UNSUPPORTED_ARCH=arm64

# Enable and start Etcd
if [ ! -f $SERVICE_FILE ] || ! diff $SERVICE_FILE /tmp/etcd.service || [ ! -f /root/etcd-release ] || [ "$RELEASE_VERSION" != "$(cat /root/etcd-release)" ] ; then
  echo "Need to start or restart the service..."
  mv /tmp/etcd.service $SERVICE_FILE
  systemctl daemon-reload
  systemctl enable etcd
  systemctl restart etcd
else
  rm -f /tmp/etcd.service
fi

echo $RELEASE_VERSION > /root/etcd-release
