#!/bin/sh
set -eu
# Railway mounts persistent storage as root. Give only the data directory to the app.
mkdir -p /data
chown 10001:10001 /data
exec setpriv --reuid=10001 --regid=10001 --init-groups /usr/local/bin/zntil "$@"
