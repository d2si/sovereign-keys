#!/bin/bash

# We don't want swap
swapoff -a

if ! mount | grep -q $RAMFS_DIR ; then
  mkdir -p $RAMFS_DIR
  mount -t tmpfs -o size=100m tmpfs $RAMFS_DIR
fi
