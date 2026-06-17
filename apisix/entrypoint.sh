#!/bin/sh
set -e
cp /tmp/apisix-init/config.yaml /usr/local/apisix/conf/config.yaml
chown 636:636 /usr/local/apisix/conf/config.yaml
exec /docker-entrypoint.sh docker-start
