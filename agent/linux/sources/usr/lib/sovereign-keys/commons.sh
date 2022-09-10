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

# Constants
export BASE_URL=$(cat /etc/sovereign-keys/api_url.txt)
export INSTANCE_ID=$(curl -sf http://169.254.169.254/latest/meta-data/instance-id)

BASE_PATH=/tmp/sovereign_keys
EC_PUB_KEY_PATH=/etc/sovereign-keys/api_public_key.pem
AUTOMOUNT_FILE_PATH=/etc/sovereign-keys/automount.conf
SECRET_STORE_MOUNT_POINT=$BASE_PATH/secret_store
RSA_PEM_PATH=$BASE_PATH/tmp.pem
RSA_PEM_PASSWORD_PATH=$BASE_PATH/tmp_pwd.txt
ENCRYPTED_SECRET_PATH=$SECRET_STORE_MOUNT_POINT/encrypted_secret.bin
CLEAR_TEXT_SECRET_PATH=$BASE_PATH/pizza.bin

log () {
    printf '%-75s' "$1"
}

verify_signature () {
    # Extract params
    B64_BIN_VALUE=$1
    B64_BIN_SIG=$2
    # Tmp store sig
    echo $B64_BIN_SIG | base64 -d > $BASE_PATH/tmp.sig
    echo $B64_BIN_VALUE | base64 -d > $BASE_PATH/tmp.bin
    openssl dgst -sha256 -verify $EC_PUB_KEY_PATH -signature $BASE_PATH/tmp.sig $BASE_PATH/tmp.bin >/dev/null
    RET_VAL=$?
    rm $BASE_PATH/tmp.sig
    rm $BASE_PATH/tmp.bin
    return $RET_VAL
}

get_local_pubkey () {
    # Delete the first (BEGIN PUBLIC KEY) and last (END PUBLIC KEY) lines
    # Return the remaining base64 string
    cat $EC_PUB_KEY_PATH | sed '1d' | sed '$d'
}

# Return a X chars random alpha-numeric string
generate_random_string () {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $1 | head -n 1
}

generate_password_file () {
  generate_random_string 32 > $RSA_PEM_PASSWORD_PATH
}

# Create the working space RAM disk
mount_ram_fs() {
    mkdir -p $BASE_PATH
    mount -t tmpfs -o size=1m tmpfs $BASE_PATH
}
umount_ram_fs() {
    umount $BASE_PATH
    rmdir $BASE_PATH
}

mount_secret_store() {
    SECRET_PARTITION_DEVICE=$1
    mkdir -p $SECRET_STORE_MOUNT_POINT
    mount $SECRET_PARTITION_DEVICE $SECRET_STORE_MOUNT_POINT
}

umount_secret_store() {
    umount $SECRET_STORE_MOUNT_POINT
    rmdir $SECRET_STORE_MOUNT_POINT
}

get_rsa_pub_key() {
    generate_password_file
    openssl genrsa -passout file:$RSA_PEM_PASSWORD_PATH -aes256 -out $RSA_PEM_PATH 4096 &>/dev/null
    openssl rsa -in $RSA_PEM_PATH -outform DER -pubout -passin file:$RSA_PEM_PASSWORD_PATH 2>/dev/null | base64 -w0
}

unwrap_secret() {
    echo $1 | base64 -d | openssl pkeyutl -decrypt -inkey $RSA_PEM_PATH -passin file:$RSA_PEM_PASSWORD_PATH -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out $CLEAR_TEXT_SECRET_PATH
}

archive_current_encrypted_secret() {
    cp $ENCRYPTED_SECRET_PATH ${ENCRYPTED_SECRET_PATH}.$(date -u +%s)
}

store_encrypted_secret() {
    echo $1 | base64 -d > $ENCRYPTED_SECRET_PATH
}

get_encrypted_secret() {
    base64 -w0 $ENCRYPTED_SECRET_PATH
}

prepare_crypto_volume() {
    # File system to create (default values anyway)
    FS_TYPE=$1
    PARTITION_DEVICE=$2
    MAPPER_NAME=$(generate_random_string 16)
    cryptsetup -q -d $CLEAR_TEXT_SECRET_PATH luksFormat $PARTITION_DEVICE
    cryptsetup -d $CLEAR_TEXT_SECRET_PATH open $PARTITION_DEVICE $MAPPER_NAME
    mkfs -t $FS_TYPE /dev/mapper/$MAPPER_NAME &>/dev/null
    sync
    cryptsetup close $MAPPER_NAME
}

mount_crypto_volume() {
    PARTITION_DEVICE=$1
    MOUNT_POINT=$2
    MAPPER_NAME=$(generate_random_string 16)
    cryptsetup -d $CLEAR_TEXT_SECRET_PATH open $PARTITION_DEVICE $MAPPER_NAME
    mkdir -p $MOUNT_POINT
    mount /dev/mapper/$MAPPER_NAME $MOUNT_POINT
}

add_automount () {
    DEVICE=$1
    MOUNT_POINT=$2
    # If the device is already registered, need to remove it
    if [ -f $AUTOMOUNT_FILE_PATH ] ; then
        grep -v "$DEVICE" $AUTOMOUNT_FILE_PATH >>$BASE_PATH/automount.tmp
        mv $BASE_PATH/automount.tmp $AUTOMOUNT_FILE_PATH
    fi
    # Then add the new entry
    echo "${DEVICE}:${MOUNT_POINT}" >>$AUTOMOUNT_FILE_PATH
}

get_automount_devices () {
    cat $AUTOMOUNT_FILE_PATH 2>/dev/null
}

is_nitro () {
    if [ $INSTANCE_ID == $(cat /sys/devices/virtual/dmi/id/board_asset_tag 2>/dev/null) ] ; then
        return 0
    else
        return 1
    fi
}

is_user_root () {
    [ $(whoami) = "root" ]
}

get_device_guid () {
    DEVICE=$1
    blkid -s PTUUID -o value $DEVICE
}

get_mapper_name_for_mountpoint () {
    MOUNT_POINT="$1"
    if [[ $MOUNT_POINT =~ /$ ]] ; then
        MOUNT_POINT=${MOUNT_POINT::-1}
    fi
    match=$(cat /proc/mounts | grep " $MOUNT_POINT " | cut -f1 -d" " | sed 's@/dev/mapper/@@')
    if [ -n "$match" ] ; then
        echo $match
    else
        return 1
    fi
}
